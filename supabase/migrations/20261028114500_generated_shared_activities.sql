-- Atividades inéditas compartilhadas, geradas pelo professor a partir de LAN e Wi-Fi.

alter table public.exams add column if not exists custom_prompt text;
alter table public.exams add column if not exists custom_rules jsonb;
alter table public.exams add column if not exists knowledge_level text;
alter table public.exams add column if not exists generation_key text;

create unique index if not exists exams_teacher_generation_key_unique
on public.exams(teacher_id,generation_key) where generation_key is not null;

do $$
begin
  if not exists(select 1 from pg_constraint where conname='exams_knowledge_level_check' and conrelid='public.exams'::regclass)then
    alter table public.exams add constraint exams_knowledge_level_check
    check(knowledge_level is null or knowledge_level in('basico','intermediario','avancado'));
  end if;
  if exists(select 1 from pg_constraint where conname='exams_school_class_check' and conrelid='public.exams'::regclass)then
    alter table public.exams drop constraint exams_school_class_check;
  end if;
  alter table public.exams add constraint exams_school_class_check check(
    (school_code='narceu' and target_class in('UNICA','TODAS'))or
    (school_code='joao_neiva' and target_class in('01','02','TODAS'))
  );
end $$;

create or replace function public.create_generated_activity(
  p_title text,p_prompt text,p_rules jsonb,p_knowledge_level text,p_generation_key text,
  p_password text,p_school text,p_target_grade text,p_target_class text,
  p_duration_minutes integer,p_max_score numeric,p_starts_at timestamptz,p_ends_at timestamptz
) returns uuid
language plpgsql security definer set search_path=public,extensions as $$
declare
  v_id uuid;v_school text:=lower(trim(coalesce(p_school,'')));
  v_level text:=lower(trim(coalesce(p_knowledge_level,'')));v_class text:=upper(trim(coalesce(p_target_class,'')));
  allowed_keys text[]:=array['pc','phone','switch','wirelessRouter','server','firewall','notebook','desktopComputer','pcWire','wifi','sameSubnet','switchesLinked','routerSwitch','minSubnets','gigabit','reach'];
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())then raise exception 'Conta não autorizada como professor.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione uma escola válida.';end if;
  if(v_school='narceu'and v_class not in('UNICA','TODAS'))or(v_school='joao_neiva'and v_class not in('01','02','TODAS'))then raise exception 'Selecione uma turma válida para a escola.';end if;
  if v_level not in('basico','intermediario','avancado')then raise exception 'Selecione o nível básico, intermediário ou avançado.';end if;
  if length(trim(coalesce(p_title,'')))<3 or length(trim(coalesce(p_prompt,'')))<40 then raise exception 'A atividade gerada está incompleta.';end if;
  if jsonb_typeof(p_rules)<>'object' or pg_column_size(p_rules)>4096 then raise exception 'Critérios automáticos inválidos.';end if;
  if exists(select 1 from jsonb_object_keys(p_rules)k where not(k=any(allowed_keys)))then raise exception 'A atividade contém um critério não autorizado.';end if;
  if length(trim(coalesce(p_generation_key,'')))<8 or length(p_generation_key)>80 then raise exception 'Identificador da atividade inválido.';end if;
  if length(trim(coalesce(p_password,'')))<8 then raise exception 'A senha deve possuir pelo menos 8 caracteres.';end if;
  if p_ends_at<=p_starts_at then raise exception 'O encerramento deve ser posterior ao início.';end if;
  if coalesce((p_rules->>'pc')::integer,0) not between 2 and 12
     or coalesce((p_rules->>'phone')::integer,0) not between 1 and 12
     or coalesce((p_rules->>'switch')::integer,0) not between 1 and 6
     or coalesce((p_rules->>'wirelessRouter')::integer,0) not between 1 and 4
     or coalesce((p_rules->>'server')::integer,0) not between 0 and 4
     or coalesce((p_rules->>'firewall')::integer,0) not between 0 and 2 then
    raise exception 'Quantidade de equipamentos fora dos limites didáticos.';
  end if;
  insert into public.exams(
    teacher_id,title,activity_key,assessment_type,school_code,target_grade,target_class,
    duration_minutes,max_score,starts_at,ends_at,password_hash,custom_prompt,custom_rules,knowledge_level,generation_key
  )values(
    auth.uid(),left(trim(p_title),160),'gerada','atividade',v_school,left(trim(coalesce(p_target_grade,'')),40),v_class,
    greatest(5,least(240,p_duration_minutes)),greatest(0.1,least(1000,p_max_score)),p_starts_at,p_ends_at,
    crypt(p_password,gen_salt('bf')),left(trim(p_prompt),4000),p_rules,v_level,left(trim(p_generation_key),80)
  )returning id into v_id;
  return v_id;
exception when unique_violation then
  raise exception 'Esta proposta já foi utilizada. Gere uma nova atividade.';
end $$;

revoke all on function public.create_generated_activity(text,text,jsonb,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) from public,anon;
grant execute on function public.create_generated_activity(text,text,jsonb,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) to authenticated;

create or replace function public.start_exam(
  p_password text,p_student_name text,p_student_school text,p_student_grade text,p_student_class text
) returns jsonb
language plpgsql security definer set search_path=public,extensions as $$
declare v_exam public.exams%rowtype;v_attempt public.exam_attempts%rowtype;v_school text:=lower(trim(coalesce(p_student_school,'')));
begin
  if length(trim(coalesce(p_student_name,'')))<3 then raise exception 'Informe o nome completo.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione a escola correta.';end if;
  if trim(coalesce(p_student_grade,''))=''or trim(coalesce(p_student_class,''))=''then raise exception 'Informe a série e a turma.';end if;
  select * into v_exam from public.exams e
  where e.active and e.school_code=v_school and now()between e.starts_at and e.ends_at
    and e.password_hash=crypt(p_password,e.password_hash)
  order by e.created_at desc limit 1;
  if v_exam.id is null then raise exception 'Senha inválida, escola incorreta ou prova/atividade fora do período de liberação.';end if;
  if v_exam.target_grade<>''and lower(trim(v_exam.target_grade))<>lower(trim(p_student_grade))then raise exception 'Este registro não está liberado para a série informada.';end if;
  if v_exam.target_class not in('','TODAS')and lower(trim(v_exam.target_class))<>lower(trim(p_student_class))then raise exception 'Este registro não está liberado para a turma informada.';end if;
  if exists(select 1 from public.exam_attempts a where a.exam_id=v_exam.id and lower(trim(a.student_name))=lower(trim(p_student_name)) and lower(trim(a.student_grade))=lower(trim(p_student_grade)) and lower(trim(a.student_class))=lower(trim(p_student_class)))then raise exception 'Já existe uma tentativa registrada para este aluno.';end if;
  insert into public.exam_attempts(exam_id,student_name,student_school,student_grade,student_class)
  values(v_exam.id,trim(p_student_name),v_school,trim(p_student_grade),trim(p_student_class))returning * into v_attempt;
  return jsonb_build_object(
    'attempt_token',v_attempt.attempt_token,'exam_id',v_exam.id,'title',v_exam.title,
    'assessment_type',v_exam.assessment_type,'school_code',v_exam.school_code,'activity_key',v_exam.activity_key,
    'custom_prompt',v_exam.custom_prompt,'knowledge_level',v_exam.knowledge_level,
    'duration_minutes',v_exam.duration_minutes,'max_score',v_exam.max_score,
    'deadline',least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes))
  );
end $$;

revoke all on function public.start_exam(text,text,text,text,text) from public;
grant execute on function public.start_exam(text,text,text,text,text) to anon,authenticated;

do $$
begin
  if to_regprocedure('public._submit_exam_secure_catalog(uuid,jsonb)') is null
     and to_regprocedure('public.submit_exam_secure(uuid,jsonb)') is not null then
    alter function public.submit_exam_secure(uuid,jsonb) rename to _submit_exam_secure_catalog;
  end if;
end $$;

revoke all on function public._submit_exam_secure_catalog(uuid,jsonb) from public,anon,authenticated;

create or replace function public._submit_generated_activity(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare
  a public.exam_attempts%rowtype;e public.exams%rowtype;r jsonb;ch jsonb:='[]'::jsonb;
  ds jsonb:=coalesce(p_topology->'devices','[]'::jsonb);cs jsonb:=coalesce(p_topology->'connections','[]'::jsonb);
  rs jsonb:=coalesce(p_topology->'racks','[]'::jsonb);k text;typ text;lbl text;req integer;n integer;ok boolean;
  ids text[];first_id text;x text;total integer;passed integer;grade integer;deadline timestamptz;final_status text;
begin
  select * into a from public.exam_attempts where attempt_token=p_attempt_token for update;
  if a.id is null then raise exception 'Tentativa não encontrada.';end if;
  if a.status<>'in_progress'then raise exception 'Esta atividade já foi entregue.';end if;
  select * into e from public.exams where id=a.exam_id;
  if e.activity_key<>'gerada'or jsonb_typeof(e.custom_rules)<>'object'then raise exception 'Atividade inédita inválida.';end if;
  r:=e.custom_rules;
  if p_topology is null or jsonb_typeof(p_topology)<>'object'or jsonb_typeof(ds)<>'array'or jsonb_typeof(cs)<>'array'or jsonb_typeof(rs)<>'array'then raise exception 'Topologia inválida.';end if;
  if pg_column_size(p_topology)>1048576 or jsonb_array_length(ds)>100 or jsonb_array_length(cs)>300 or jsonb_array_length(rs)>30 then raise exception 'Topologia excede os limites permitidos.';end if;
  if exists(select 1 from jsonb_array_elements(ds)d where coalesce(d->>'id','')=''or coalesce(d->>'type','')not in('pc','phone','router','switch','patchPanel','server','firewall','cloud','satDish','satellite'))
     or(select count(*)from jsonb_array_elements(ds))<>(select count(distinct d->>'id')from jsonb_array_elements(ds)d)then raise exception 'A topologia contém equipamentos inválidos ou repetidos.';end if;

  for k,req in select key,(value#>>'{}')::integer from jsonb_each(r)
    where key in('pc','phone','switch','wirelessRouter','server','firewall')loop
    typ:=case k when'wirelessRouter'then'router'else k end;
    lbl:=case k when'pc'then'Computadores'when'phone'then'Celulares'when'switch'then'Switches'when'wirelessRouter'then'Roteadores sem fio'when'server'then'Servidores'else'Firewalls'end;
    if k='wirelessRouter'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'='router'and(coalesce(d->>'ssid','')<>''or d->>'routerType'in('soho','mesh_node'));
    else select count(*)into n from jsonb_array_elements(ds)d where d->>'type'=typ;end if;
    ch:=public._exam_check(ch,lbl||': pelo menos '||req,n>=req);
  end loop;

  if r?'notebook'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'='pc'and coalesce(d->>'pcStyle','notebook')='notebook';ch:=public._exam_check(ch,'Notebook presente',n>=(r->>'notebook')::integer);end if;
  if r?'desktopComputer'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'='pc'and d->>'pcStyle'='complete';ch:=public._exam_check(ch,'Computador presente',n>=(r->>'desktopComputer')::integer);end if;
  if r?'pcWire'then ok:=not exists(select 1 from jsonb_array_elements(ds)p where p->>'type'='pc'and not exists(select 1 from jsonb_array_elements(ds)s cross join jsonb_array_elements(cs)c where s->>'type'='switch'and coalesce(c->>'active','true')<>'false'and coalesce(c->>'kind','cable')<>'wifi'and((c->>'from'=p->>'id'and c->>'to'=s->>'id')or(c->>'to'=p->>'id'and c->>'from'=s->>'id'))));ch:=public._exam_check(ch,'Todos os computadores ligados aos switches por cabo',ok);end if;
  if r?'wifi'then ok:=not exists(select 1 from jsonb_array_elements(ds)p where p->>'type'='phone'and not exists(select 1 from jsonb_array_elements(cs)c where coalesce(c->>'active','true')<>'false'and c->>'kind'='wifi'and(c->>'from'=p->>'id'or c->>'to'=p->>'id')));ch:=public._exam_check(ch,'Todos os celulares associados por Wi-Fi',ok);end if;
  if r?'sameSubnet'then select count(distinct split_part(d->>'ip','.',1)||'.'||split_part(d->>'ip','.',2)||'.'||split_part(d->>'ip','.',3))into n from jsonb_array_elements(ds)d where d->>'type'='pc';ch:=public._exam_check(ch,'Computadores na mesma rede /24',n=1);end if;
  if r?'switchesLinked'then ok:=exists(select 1 from jsonb_array_elements(ds)a1 cross join jsonb_array_elements(ds)a2 cross join jsonb_array_elements(cs)c where a1->>'type'='switch'and a2->>'type'='switch'and a1->>'id'<>a2->>'id'and((c->>'from'=a1->>'id'and c->>'to'=a2->>'id')or(c->>'to'=a1->>'id'and c->>'from'=a2->>'id')));ch:=public._exam_check(ch,'Switches interligados',ok);end if;
  if r?'routerSwitch'then ok:=exists(select 1 from jsonb_array_elements(ds)ro cross join jsonb_array_elements(ds)sw cross join jsonb_array_elements(cs)c where ro->>'type'='router'and sw->>'type'='switch'and((c->>'from'=ro->>'id'and c->>'to'=sw->>'id')or(c->>'to'=ro->>'id'and c->>'from'=sw->>'id')));ch:=public._exam_check(ch,'Roteador sem fio ligado à LAN',ok);end if;
  if r?'minSubnets'then select count(distinct split_part(d->>'ip','.',1)||'.'||split_part(d->>'ip','.',2)||'.'||split_part(d->>'ip','.',3))into n from jsonb_array_elements(ds)d where d->>'type'='pc';ch:=public._exam_check(ch,'Redes /24: pelo menos '||(r->>'minSubnets'),n>=(r->>'minSubnets')::integer);end if;
  if r?'gigabit'then ok:=exists(select 1 from jsonb_array_elements(cs)c where coalesce(c->>'kind','')not in('wifi','satellite')and coalesce((c->>'bw')::numeric,0)>=1000);ch:=public._exam_check(ch,'Enlace central de pelo menos 1 Gb/s',ok);end if;
  if r?'reach'then
    select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'type'in('pc','phone','server');
    ok:=coalesce(array_length(ids,1),0)>1;if ok then first_id:=ids[1];foreach x in array ids loop if not public._exam_path(p_topology,first_id,x)then ok:=false;exit;end if;end loop;end if;
    ch:=public._exam_check(ch,'Comunicação entre todos os clientes e servidores',ok);
  end if;

  total:=jsonb_array_length(ch);select count(*)into passed from jsonb_array_elements(ch)c where(c->>'ok')::boolean;
  grade:=round(passed::numeric/greatest(1,total)*100);deadline:=least(e.ends_at,a.started_at+make_interval(mins=>e.duration_minutes));
  final_status:=case when now()>deadline then'expired'else'submitted'end;
  update public.exam_attempts set submitted_at=now(),status=final_status,score=grade,passed_checks=passed,total_checks=total,checks=ch,topology=p_topology where id=a.id;
  return jsonb_build_object('ok',true,'status',final_status,'message','Atividade corrigida e entregue ao professor.');
end $$;

revoke all on function public._submit_generated_activity(uuid,jsonb) from public,anon,authenticated;

create or replace function public.submit_exam_secure(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare v_key text;
begin
  select e.activity_key into v_key from public.exam_attempts a join public.exams e on e.id=a.exam_id where a.attempt_token=p_attempt_token;
  if v_key is null then raise exception 'Tentativa não encontrada.';end if;
  if v_key='gerada'then return public._submit_generated_activity(p_attempt_token,p_topology);end if;
  return public._submit_exam_secure_catalog(p_attempt_token,p_topology);
end $$;

revoke all on function public.submit_exam_secure(uuid,jsonb) from public;
grant execute on function public.submit_exam_secure(uuid,jsonb) to anon,authenticated;

notify pgrst,'reload schema';

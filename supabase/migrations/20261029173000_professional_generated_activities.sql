-- Nível Profissional para atividades inéditas: Backbone e Segmentação.

alter table public.exams drop constraint if exists exams_knowledge_level_check;
alter table public.exams add constraint exams_knowledge_level_check
check(knowledge_level is null or knowledge_level in('basico','intermediario','avancado','profissional'));

create or replace function public.create_generated_activity(
  p_title text,p_prompt text,p_rules jsonb,p_knowledge_level text,p_generation_key text,
  p_password text,p_school text,p_target_grade text,p_target_class text,
  p_duration_minutes integer,p_max_score numeric,p_starts_at timestamptz,p_ends_at timestamptz
) returns uuid
language plpgsql security definer set search_path=public,extensions as $$
declare
  v_id uuid;v_school text:=lower(trim(coalesce(p_school,'')));
  v_level text:=lower(trim(coalesce(p_knowledge_level,'')));v_class text:=upper(trim(coalesce(p_target_class,'')));
  allowed_keys text[]:=array['pc','phone','switch','wirelessRouter','server','firewall','notebook','desktopComputer','pcWire','wifi','sameSubnet','switchesLinked','routerSwitch','minSubnets','gigabit','reach','minAssigned','minVlans','minBackbones','backboneSpeed'];
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())then raise exception 'Conta não autorizada como professor.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione uma escola válida.';end if;
  if(v_school='narceu'and v_class not in('UNICA','TODAS'))or(v_school='joao_neiva'and v_class not in('01','02','TODAS'))then raise exception 'Selecione uma turma válida para a escola.';end if;
  if v_level not in('basico','intermediario','avancado','profissional')then raise exception 'Selecione o nível básico, intermediário, avançado ou profissional.';end if;
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
  if (p_rules?'minSubnets' and (p_rules->>'minSubnets')::integer not between 1 and 8)
     or (p_rules?'minAssigned' and (p_rules->>'minAssigned')::integer not between 2 and 30)
     or (p_rules?'minVlans' and (p_rules->>'minVlans')::integer not between 2 and 8)
     or (p_rules?'minBackbones' and (p_rules->>'minBackbones')::integer not between 1 and 10)
     or (p_rules?'backboneSpeed' and (p_rules->>'backboneSpeed')::integer not between 1000 and 100000) then
    raise exception 'Critérios profissionais fora dos limites didáticos.';
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
  if r?'minAssigned'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'in('pc','phone','server')and d->>'vlanAssigned'='true';ch:=public._exam_check(ch,'Clientes e servidores atribuídos a VLANs: pelo menos '||(r->>'minAssigned'),n>=(r->>'minAssigned')::integer);end if;
  if r?'minVlans'then select count(distinct d->>'vlan')into n from jsonb_array_elements(ds)d where d->>'type'in('pc','phone','server')and d->>'vlanAssigned'='true'and coalesce(d->>'vlan','')<>'';ch:=public._exam_check(ch,'VLANs diferentes: pelo menos '||(r->>'minVlans'),n>=(r->>'minVlans')::integer);end if;
  if r?'minBackbones'then select count(*)into n from jsonb_array_elements(cs)c where c->>'kind'='backbone'and coalesce(c->>'active','true')<>'false';ch:=public._exam_check(ch,'Enlaces de backbone: pelo menos '||(r->>'minBackbones'),n>=(r->>'minBackbones')::integer);end if;
  if r?'backboneSpeed'then ok:=exists(select 1 from jsonb_array_elements(cs)c where c->>'kind'='backbone'and coalesce(c->>'active','true')<>'false'and coalesce((c->>'bw')::numeric,0)>=(r->>'backboneSpeed')::numeric);ch:=public._exam_check(ch,'Backbone principal de pelo menos 10 Gb/s',ok);end if;
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

notify pgrst,'reload schema';

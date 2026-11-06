-- Libera as atividades da Sala Cidade e adiciona correção automática segura no servidor.

create or replace function public.create_exam(
  p_title text,p_activity_key text,p_password text,p_assessment_type text,p_school text,
  p_target_grade text,p_target_class text,p_duration_minutes integer,p_max_score numeric,
  p_starts_at timestamptz,p_ends_at timestamptz
) returns uuid
language plpgsql security definer set search_path=public,extensions as $$
declare v_id uuid;v_school text:=lower(trim(coalesce(p_school,'')));v_type text:=lower(trim(coalesce(p_assessment_type,'')));
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())then raise exception 'Conta não autorizada como professor.';end if;
  if v_type not in('prova','atividade')then raise exception 'Selecione Prova ou Atividade.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione uma escola válida.';end if;
  if(v_school='narceu'and p_target_class<>'UNICA')or(v_school='joao_neiva'and p_target_class not in('01','02'))then raise exception 'Selecione uma turma válida para a escola.';end if;
  if length(trim(coalesce(p_title,'')))<3 then raise exception 'Informe um título válido.';end if;
  if p_activity_key!~'^(lan|wifi|backbone|vlan|city|prova)[0-9]+$'then raise exception 'Atividade inválida.';end if;
  if length(trim(coalesce(p_password,'')))<8 then raise exception 'A senha deve possuir pelo menos 8 caracteres.';end if;
  if p_ends_at<=p_starts_at then raise exception 'O encerramento deve ser posterior ao início.';end if;
  insert into public.exams(teacher_id,title,activity_key,assessment_type,school_code,target_grade,target_class,duration_minutes,max_score,starts_at,ends_at,password_hash)
  values(auth.uid(),left(trim(p_title),160),p_activity_key,v_type,v_school,left(trim(coalesce(p_target_grade,'')),40),left(trim(coalesce(p_target_class,'')),40),greatest(5,least(240,p_duration_minutes)),greatest(0.1,least(1000,p_max_score)),p_starts_at,p_ends_at,crypt(p_password,gen_salt('bf')))
  returning id into v_id;return v_id;
end $$;

revoke all on function public.create_exam(text,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) from public,anon;
grant execute on function public.create_exam(text,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) to authenticated;

do $$
begin
  if to_regprocedure('public._submit_exam_secure_before_city(uuid,jsonb)') is null
     and to_regprocedure('public.submit_exam_secure(uuid,jsonb)') is not null then
    alter function public.submit_exam_secure(uuid,jsonb) rename to _submit_exam_secure_before_city;
  end if;
end $$;

revoke all on function public._submit_exam_secure_before_city(uuid,jsonb) from public,anon,authenticated;

create or replace function public._submit_city_activity(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare
  a public.exam_attempts%rowtype;e public.exams%rowtype;ch jsonb:='[]'::jsonb;
  ds jsonb:=coalesce(p_topology->'devices','[]'::jsonb);cs jsonb:=coalesce(p_topology->'connections','[]'::jsonb);
  rs jsonb:=coalesce(p_topology->'racks','[]'::jsonb);scene_active boolean:=lower(coalesce(p_topology#>>'{cityScene,active}','false'))='true';
  towers integer;houses integer;people integer;data_centers integer;satellites integer;serving_towers integer;orbital_towers integer;
  ok boolean;total integer;passed integer;grade integer;deadline timestamptz;final_status text;
begin
  select * into a from public.exam_attempts where attempt_token=p_attempt_token for update;
  if a.id is null then raise exception 'Tentativa não encontrada.';end if;
  if a.status<>'in_progress'then raise exception 'Esta atividade já foi entregue.';end if;
  select * into e from public.exams where id=a.exam_id;
  if e.activity_key not in('city1','city2','city3')then raise exception 'Atividade da Sala Cidade inválida.';end if;
  if p_topology is null or jsonb_typeof(p_topology)<>'object'or jsonb_typeof(ds)<>'array'or jsonb_typeof(cs)<>'array'or jsonb_typeof(rs)<>'array'then raise exception 'Topologia inválida.';end if;
  if pg_column_size(p_topology)>1048576 or jsonb_array_length(ds)>100 or jsonb_array_length(cs)>300 or jsonb_array_length(rs)>30 then raise exception 'Topologia excede os limites permitidos.';end if;
  if exists(select 1 from jsonb_array_elements(ds)d where coalesce(d->>'id','')=''or coalesce(d->>'type','')not in('pc','phone','router','switch','patchPanel','server','firewall','cloud','satDish','satellite','cellTower','house','person','dataCenter'))
     or(select count(*)from jsonb_array_elements(ds))<>(select count(distinct d->>'id')from jsonb_array_elements(ds)d)then raise exception 'A topologia contém equipamentos inválidos ou repetidos.';end if;

  select count(*)into towers from jsonb_array_elements(ds)d where d->>'type'='cellTower';
  select count(*)into houses from jsonb_array_elements(ds)d where d->>'type'='house';
  select count(*)into people from jsonb_array_elements(ds)d where d->>'type'='person';
  select count(*)into data_centers from jsonb_array_elements(ds)d where d->>'type'='dataCenter';
  select count(*)into satellites from jsonb_array_elements(ds)d where d->>'type'='satellite';
  select count(*)into serving_towers from jsonb_array_elements(ds)t where t->>'type'='cellTower'and exists(
    select 1 from jsonb_array_elements(cs)c where c->>'kind'='cellular'and coalesce(c->>'active','true')<>'false'and(c->>'from'=t->>'id'or c->>'to'=t->>'id'));
  select count(*)into orbital_towers from jsonb_array_elements(ds)t where t->>'type'='cellTower'and exists(
    select 1 from jsonb_array_elements(cs)c where c->>'kind'='satellite'and coalesce(c->>'active','true')<>'false'and lower(coalesce(c->>'towerBackhaul','false'))='true'and(c->>'from'=t->>'id'or c->>'to'=t->>'id'));

  ch:=public._exam_check(ch,'Cenário de cidade ativado',scene_active);
  if e.activity_key='city1'then
    ch:=public._exam_check(ch,'Pelo menos 1 torre 4G/5G',towers>=1);
    ch:=public._exam_check(ch,'Pelo menos 3 residências',houses>=3);
    select not exists(select 1 from jsonb_array_elements(ds)h where h->>'type'='house'and not exists(
      select 1 from jsonb_array_elements(cs)c where c->>'kind'='cellular'and coalesce(c->>'active','true')<>'false'and(c->>'from'=h->>'id'or c->>'to'=h->>'id')and exists(
        select 1 from jsonb_array_elements(ds)t where t->>'type'='cellTower'and(t->>'id'=c->>'from'or t->>'id'=c->>'to'))))into ok;
    ch:=public._exam_check(ch,'Todas as residências conectadas por 4G/5G',houses>=3 and ok);
    select exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='cellTower'and coalesce(d->>'status','up')='up')into ok;
    ch:=public._exam_check(ch,'Torre ativa',ok);
  elsif e.activity_key='city2'then
    ch:=public._exam_check(ch,'Pelo menos 2 torres 4G/5G',towers>=2);
    ch:=public._exam_check(ch,'Pelo menos 4 residências',houses>=4);
    ch:=public._exam_check(ch,'Pelo menos 4 pessoas com celular',people>=4);
    select not exists(select 1 from jsonb_array_elements(ds)x where x->>'type'in('house','person')and not exists(
      select 1 from jsonb_array_elements(cs)c where c->>'kind'='cellular'and coalesce(c->>'active','true')<>'false'and(c->>'from'=x->>'id'or c->>'to'=x->>'id')and exists(
        select 1 from jsonb_array_elements(ds)t where t->>'type'='cellTower'and(t->>'id'=c->>'from'or t->>'id'=c->>'to'))))into ok;
    ch:=public._exam_check(ch,'Casas e pessoas conectadas por 4G/5G',houses>=4 and people>=4 and ok);
    ch:=public._exam_check(ch,'Assinantes distribuídos entre as duas torres',serving_towers>=2);
  else
    ch:=public._exam_check(ch,'1 Data Center, 2 torres e 1 satélite',data_centers>=1 and towers>=2 and satellites>=1);
    ch:=public._exam_check(ch,'4 residências e 6 pessoas com celular',houses>=4 and people>=6);
    select exists(select 1 from jsonb_array_elements(cs)c where c->>'kind'='satellite'and coalesce(c->>'active','true')<>'false'
      and lower(coalesce(c->>'dataCenterBackhaul','false'))='true'
      and exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='dataCenter'and(d->>'id'=c->>'from'or d->>'id'=c->>'to'))
      and exists(select 1 from jsonb_array_elements(ds)s where s->>'type'='satellite'and(s->>'id'=c->>'from'or s->>'id'=c->>'to')))into ok;
    ch:=public._exam_check(ch,'Data Center conectado ao satélite',ok);
    ch:=public._exam_check(ch,'As duas torres conectadas ao satélite',orbital_towers>=2);
    select not exists(select 1 from jsonb_array_elements(ds)x where x->>'type'in('house','person')and not exists(
      select 1 from jsonb_array_elements(cs)c where c->>'kind'='cellular'and coalesce(c->>'active','true')<>'false'and(c->>'from'=x->>'id'or c->>'to'=x->>'id')and exists(
        select 1 from jsonb_array_elements(ds)t where t->>'type'='cellTower'and(t->>'id'=c->>'from'or t->>'id'=c->>'to'))))into ok;
    ch:=public._exam_check(ch,'Todos os assinantes com cobertura 4G/5G',houses+people>=10 and ok);
    ch:=public._exam_check(ch,'Assinantes distribuídos entre as duas torres',serving_towers>=2);
  end if;

  total:=jsonb_array_length(ch);select count(*)into passed from jsonb_array_elements(ch)c where(c->>'ok')::boolean;
  grade:=round(passed::numeric/greatest(1,total)*100);deadline:=least(e.ends_at,a.started_at+make_interval(mins=>e.duration_minutes));
  final_status:=case when now()>deadline then'expired'else'submitted'end;
  update public.exam_attempts set submitted_at=now(),status=final_status,score=grade,passed_checks=passed,total_checks=total,checks=ch,topology=p_topology where id=a.id;
  return jsonb_build_object('ok',true,'status',final_status,'message','Atividade da Sala Cidade corrigida e entregue ao professor.');
end $$;

revoke all on function public._submit_city_activity(uuid,jsonb) from public,anon,authenticated;

create or replace function public.submit_exam_secure(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare v_key text;
begin
  select e.activity_key into v_key from public.exam_attempts a join public.exams e on e.id=a.exam_id where a.attempt_token=p_attempt_token;
  if v_key is null then raise exception 'Tentativa não encontrada.';end if;
  if v_key in('city1','city2','city3')then return public._submit_city_activity(p_attempt_token,p_topology);end if;
  return public._submit_exam_secure_before_city(p_attempt_token,p_topology);
end $$;

revoke all on function public.submit_exam_secure(uuid,jsonb) from public;
grant execute on function public.submit_exam_secure(uuid,jsonb) to anon,authenticated;

notify pgrst,'reload schema';

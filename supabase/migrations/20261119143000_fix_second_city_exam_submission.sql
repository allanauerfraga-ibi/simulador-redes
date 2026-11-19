-- Corrige a entrega da Prova 2 das 15 versoes praticas.
-- As chaves city101..city115 e provaCidade01..provaCidade15 representam
-- cenarios avancados da Sala Cidade e precisam usar a correcao de cidade.

create or replace function public._submit_balanced_city_exam(p_attempt_token uuid,p_topology jsonb)
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
  if a.status<>'in_progress'then raise exception 'Esta prova já foi entregue.';end if;
  select * into e from public.exams where id=a.exam_id;
  if e.activity_key!~'^(city(10[1-9]|11[0-5])|provaCidade(0[1-9]|1[0-5]))$'then raise exception 'Prova da Sala Cidade inválida.';end if;
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

  total:=jsonb_array_length(ch);select count(*)into passed from jsonb_array_elements(ch)c where(c->>'ok')::boolean;
  grade:=round(passed::numeric/greatest(1,total)*100);deadline:=least(e.ends_at,a.started_at+make_interval(mins=>e.duration_minutes));
  final_status:=case when now()>deadline then'expired'else'submitted'end;
  update public.exam_attempts set submitted_at=now(),status=final_status,score=grade,passed_checks=passed,total_checks=total,checks=ch,topology=p_topology where id=a.id;
  return jsonb_build_object('ok',true,'status',final_status,'message','Prova 2 da Sala Cidade corrigida e entregue ao professor.');
end $$;

revoke all on function public._submit_balanced_city_exam(uuid,jsonb) from public,anon,authenticated;

create or replace function public.submit_exam_secure(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare v_key text;
begin
  select e.activity_key into v_key from public.exam_attempts a join public.exams e on e.id=a.exam_id where a.attempt_token=p_attempt_token;
  if v_key is null then raise exception 'Tentativa não encontrada.';end if;
  if v_key in('city1','city2','city3')then return public._submit_city_activity(p_attempt_token,p_topology);end if;
  if v_key~'^(city(10[1-9]|11[0-5])|provaCidade(0[1-9]|1[0-5]))$'then return public._submit_balanced_city_exam(p_attempt_token,p_topology);end if;
  return public._submit_exam_secure_before_city(p_attempt_token,p_topology);
end $$;

revoke all on function public.submit_exam_secure(uuid,jsonb) from public;
grant execute on function public.submit_exam_secure(uuid,jsonb) to anon,authenticated;

notify pgrst,'reload schema';

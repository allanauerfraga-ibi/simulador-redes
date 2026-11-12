-- Atividades inéditas da Sala Cidade com os mesmos níveis do gerador de redes.

do $$
begin
  if to_regprocedure('public._submit_generated_network_activity(uuid,jsonb)') is null then
    alter function public._submit_generated_activity(uuid,jsonb) rename to _submit_generated_network_activity;
  end if;
end $$;

create or replace function public._submit_generated_city_activity(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare
  a public.exam_attempts%rowtype;e public.exams%rowtype;r jsonb;ch jsonb:='[]'::jsonb;
  ds jsonb:=coalesce(p_topology->'devices','[]'::jsonb);cs jsonb:=coalesce(p_topology->'connections','[]'::jsonb);
  rs jsonb:=coalesce(p_topology->'racks','[]'::jsonb);k text;typ text;lbl text;req integer;n integer;ok boolean;
  total integer;passed integer;grade integer;deadline timestamptz;final_status text;
begin
  select * into a from public.exam_attempts where attempt_token=p_attempt_token for update;
  if a.id is null then raise exception 'Tentativa não encontrada.';end if;
  if a.status<>'in_progress'then raise exception 'Esta atividade já foi entregue.';end if;
  select * into e from public.exams where id=a.exam_id;
  if e.activity_key<>'gerada'or jsonb_typeof(e.custom_rules)<>'object'then raise exception 'Atividade inédita inválida.';end if;
  r:=e.custom_rules;
  if coalesce((r->>'cityScene')::boolean,false)is not true then raise exception 'Atividade da Sala Cidade inválida.';end if;
  if p_topology is null or jsonb_typeof(p_topology)<>'object'or jsonb_typeof(ds)<>'array'or jsonb_typeof(cs)<>'array'or jsonb_typeof(rs)<>'array'then raise exception 'Topologia inválida.';end if;
  if pg_column_size(p_topology)>1048576 or jsonb_array_length(ds)>100 or jsonb_array_length(cs)>300 or jsonb_array_length(rs)>30 then raise exception 'Topologia excede os limites permitidos.';end if;
  if exists(select 1 from jsonb_array_elements(ds)d where coalesce(d->>'id','')=''or coalesce(d->>'type','')not in('cellTower','house','person','dataCenter','satellite'))
     or(select count(*)from jsonb_array_elements(ds))<>(select count(distinct d->>'id')from jsonb_array_elements(ds)d)then raise exception 'O cenário contém equipamentos inválidos ou repetidos.';end if;

  ch:=public._exam_check(ch,'Cenário da Sala Cidade ativado',coalesce((p_topology->'cityScene'->>'active')::boolean,false));
  for k,req in select key,(value#>>'{}')::integer from jsonb_each(r)
    where key in('cellTower','house','person','dataCenter','satellite')loop
    typ:=k;
    lbl:=case k when'cellTower'then'Torres 4G/5G'when'house'then'Residências'when'person'then'Pessoas com celular'when'dataCenter'then'Data Centers'else'Satélites'end;
    select count(*)into n from jsonb_array_elements(ds)d where d->>'type'=typ;
    ch:=public._exam_check(ch,lbl||': pelo menos '||req,n>=req);
  end loop;

  if r?'allCityClientsConnected'then
    ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'in('house','person'))and not exists(
      select 1 from jsonb_array_elements(ds)d where d->>'type'in('house','person')and not exists(
        select 1 from jsonb_array_elements(cs)c where c->>'kind'='cellular'and coalesce(c->>'active','true')<>'false'and(c->>'from'=d->>'id'or c->>'to'=d->>'id')));
    ch:=public._exam_check(ch,'Todos os assinantes conectados por 4G/5G',ok);
  end if;
  if r?'minServingTowers'then
    select count(distinct tower_id)into n from(
      select case when c->>'from'=t->>'id'then c->>'from'else c->>'to'end tower_id
      from jsonb_array_elements(cs)c cross join jsonb_array_elements(ds)t
      where t->>'type'='cellTower'and c->>'kind'='cellular'and coalesce(c->>'active','true')<>'false'and(c->>'from'=t->>'id'or c->>'to'=t->>'id'))q;
    ch:=public._exam_check(ch,'Assinantes distribuídos entre pelo menos '||(r->>'minServingTowers')||' torres',n>=(r->>'minServingTowers')::integer);
  end if;
  if r?'orbitalTowers'then
    select count(distinct t->>'id')into n from jsonb_array_elements(ds)t where t->>'type'='cellTower'and exists(
      select 1 from jsonb_array_elements(cs)c where c->>'kind'='satellite'and coalesce(c->>'towerBackhaul','false')='true'and coalesce(c->>'active','true')<>'false'and(c->>'from'=t->>'id'or c->>'to'=t->>'id'));
    ch:=public._exam_check(ch,'Torres com backhaul orbital: pelo menos '||(r->>'orbitalTowers'),n>=(r->>'orbitalTowers')::integer);
  end if;
  if r?'orbitalDataCenters'then
    select count(distinct d->>'id')into n from jsonb_array_elements(ds)d where d->>'type'='dataCenter'and exists(
      select 1 from jsonb_array_elements(cs)c where c->>'kind'='satellite'and coalesce(c->>'dataCenterBackhaul','false')='true'and coalesce(c->>'active','true')<>'false'and(c->>'from'=d->>'id'or c->>'to'=d->>'id'));
    ch:=public._exam_check(ch,'Data Centers conectados a satélite: pelo menos '||(r->>'orbitalDataCenters'),n>=(r->>'orbitalDataCenters')::integer);
  end if;

  total:=jsonb_array_length(ch);select count(*)into passed from jsonb_array_elements(ch)c where(c->>'ok')::boolean;
  grade:=round(passed::numeric/greatest(1,total)*100);deadline:=least(e.ends_at,a.started_at+make_interval(mins=>e.duration_minutes));
  final_status:=case when now()>deadline then'expired'else'submitted'end;
  update public.exam_attempts set submitted_at=now(),status=final_status,score=grade,passed_checks=passed,total_checks=total,checks=ch,topology=p_topology where id=a.id;
  return jsonb_build_object('ok',true,'status',final_status,'message','Atividade da Sala Cidade corrigida e entregue ao professor.');
end $$;

revoke all on function public._submit_generated_city_activity(uuid,jsonb) from public,anon,authenticated;

create or replace function public._submit_generated_activity(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare v_rules jsonb;
begin
  select e.custom_rules into v_rules from public.exam_attempts a join public.exams e on e.id=a.exam_id where a.attempt_token=p_attempt_token;
  if coalesce((v_rules->>'cityScene')::boolean,false)then return public._submit_generated_city_activity(p_attempt_token,p_topology);end if;
  return public._submit_generated_network_activity(p_attempt_token,p_topology);
end $$;

revoke all on function public._submit_generated_activity(uuid,jsonb) from public,anon,authenticated;
notify pgrst,'reload schema';

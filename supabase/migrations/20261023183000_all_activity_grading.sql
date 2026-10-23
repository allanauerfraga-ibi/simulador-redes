-- Permite provas criadas a partir de qualquer atividade LAN, Wi-Fi, Backbone ou VLAN.
-- As 15 versões práticas continuam usando a correção detalhada anterior.

do $$
begin
  if to_regprocedure('public._submit_exam_secure_practical(uuid,jsonb)') is null
     and to_regprocedure('public.submit_exam_secure(uuid,jsonb)') is not null then
    alter function public.submit_exam_secure(uuid,jsonb) rename to _submit_exam_secure_practical;
  end if;
end $$;

revoke all on function public._submit_exam_secure_practical(uuid,jsonb) from public,anon,authenticated;

create or replace function public.submit_exam_secure(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare
  a public.exam_attempts%rowtype; e public.exams%rowtype;
  r jsonb; ch jsonb:='[]'::jsonb;
  ds jsonb:=coalesce(p_topology->'devices','[]'::jsonb);
  cs jsonb:=coalesce(p_topology->'connections','[]'::jsonb);
  rs jsonb:=coalesce(p_topology->'racks','[]'::jsonb);
  k text; typ text; lbl text; req integer; n integer; ok boolean;
  ids text[]; first_id text; x text;
  total integer; passed integer; grade integer; deadline timestamptz; final_status text;
begin
  select * into a from public.exam_attempts where attempt_token=p_attempt_token for update;
  if a.id is null then raise exception 'Tentativa não encontrada.'; end if;
  if a.status<>'in_progress' then raise exception 'Esta prova já foi entregue.'; end if;
  select * into e from public.exams where id=a.exam_id;

  if e.activity_key ~ '^prova(0[1-9]|1[0-5])$' then
    return public._submit_exam_secure_practical(p_attempt_token,p_topology);
  end if;

  if p_topology is null or jsonb_typeof(p_topology)<>'object' or jsonb_typeof(ds)<>'array'
     or jsonb_typeof(cs)<>'array' or jsonb_typeof(rs)<>'array' then raise exception 'Topologia inválida.'; end if;
  if pg_column_size(p_topology)>1048576 or jsonb_array_length(ds)>100 or jsonb_array_length(cs)>300 or jsonb_array_length(rs)>30
     then raise exception 'Topologia excede os limites permitidos.'; end if;
  if exists(select 1 from jsonb_array_elements(ds)d where coalesce(d->>'id','')='' or coalesce(d->>'type','') not in
     ('pc','phone','router','switch','patchPanel','server','firewall','cloud','satDish','satellite'))
     or (select count(*)from jsonb_array_elements(ds))<>(select count(distinct d->>'id')from jsonb_array_elements(ds)d)
     then raise exception 'A topologia contém equipamentos inválidos ou repetidos.'; end if;

  r:=case e.activity_key
    when 'lan1' then '{"pc":3,"switch":1,"pcWire":true,"sameSubnet":true,"reach":true}'
    when 'lan2' then '{"pc":4,"switch":2,"pcWire":true,"sameSubnet":true,"reach":true}'
    when 'lan3' then '{"pc":4,"switch":2,"server":1,"pcWire":true,"serverWire":true,"sameSubnet":true,"reach":true}'
    when 'lan4' then '{"pc":6,"switch":2,"router":1,"pcWire":true,"minSubnets":2,"reach":true}'
    when 'lan5' then '{"pc":8,"switch":3,"router":1,"firewall":1,"server":2,"minSubnets":2,"rackServer":1,"reach":true}'
    when 'lan6' then '{"pc":4,"phone":3,"switch":2,"wirelessRouter":1,"firewall":1,"server":1,"pcWire":true,"wifi":true,"reach":true}'
    when 'lan7' then '{"pc":6,"phone":4,"switch":3,"wirelessRouter":1,"firewall":1,"server":2,"patchPanel":1,"rack":1,"pcWire":true,"wifi":true,"rackServer":1,"towerServer":1,"rackSwitch":1,"gigabit":true,"reach":true}'
    when 'wifi1' then '{"phone":2,"wirelessRouter":1,"wifi":true,"reach":true}'
    when 'wifi2' then '{"phone":4,"wirelessRouter":1,"wifi":true,"validIps":true,"reach":true}'
    when 'wifi3' then '{"phone":4,"wirelessRouter":2,"wifi":true,"wifiAreas":2,"reach":true}'
    when 'wifi4' then '{"phone":3,"pc":3,"switch":1,"wirelessRouter":1,"wifi":true,"pcWire":true,"reach":true}'
    when 'wifi5' then '{"phone":6,"wirelessRouter":2,"server":1,"firewall":1,"wifi":true,"wifiAreas":2,"reach":true}'
    when 'wifi6' then '{"phone":4,"pc":2,"wirelessRouter":2,"switch":1,"firewall":1,"server":1,"wifi":true,"pcWire":true,"desktopSwitch8":true,"towerServer":1,"gigabit":true,"reach":true}'
    when 'wifi7' then '{"phone":6,"pc":2,"wirelessRouter":2,"switch":1,"firewall":1,"server":2,"patchPanel":1,"rack":1,"cloud":1,"wifi":true,"wifiAreas":2,"rackServer":1,"towerServer":1,"rackSwitch":1,"satellite":true,"reach":true}'
    when 'backbone1' then '{"core":2,"backbones":1,"rack":1,"rackServer":1,"coreReach":true}'
    when 'backbone2' then '{"core":3,"backbones":2,"rack":1,"rackServer":1,"coreReach":true}'
    when 'backbone3' then '{"core":4,"backbones":3,"rack":2,"rackServer":2,"coreReach":true}'
    when 'backbone4' then '{"switch":1,"router":1,"firewall":1,"cloud":1,"backbones":4,"rack":2,"rackServer":2,"coreReach":true}'
    when 'backbone5' then '{"switch":2,"router":2,"firewall":1,"cloud":1,"backbones":5,"rack":3,"rackServer":3,"backboneSpeed":10000,"coreReach":true}'
    when 'backbone6' then '{"cloud":2,"backbones":4,"rack":2,"rackServer":2,"rackSwitch":2,"towerServer":1,"providers":2,"fiberSpeed":10000,"coreReach":true}'
    when 'backbone7' then '{"switch":3,"router":2,"firewall":1,"server":2,"cloud":2,"backbones":5,"rackServer":1,"towerServer":1,"rackSwitch":1,"providers":2,"fiberSpeed":1,"satellite":true,"backboneSpeed":40000,"coreReach":true}'
    when 'vlan1' then '{"switch":1,"router":1,"assigned":2,"vlans":2,"validIps":true}'
    when 'vlan2' then '{"switch":1,"router":1,"assigned":4,"vlans":2,"validIps":true,"assignedReach":true}'
    when 'vlan3' then '{"switch":2,"router":1,"assigned":6,"vlans":3,"validIps":true,"assignedReach":true}'
    when 'vlan4' then '{"router":1,"server":1,"firewall":1,"assigned":6,"vlans":3,"assignedReach":true}'
    when 'vlan5' then '{"switch":2,"router":1,"firewall":1,"server":1,"assigned":8,"vlans":4,"rackServer":1,"validIps":true,"assignedReach":true}'
    when 'vlan6' then '{"pc":2,"phone":2,"switch":2,"router":1,"firewall":1,"server":2,"patchPanel":1,"assigned":10,"vlans":4,"wifi":true,"rackServer":1,"towerServer":1,"rackSwitch":1,"assignedReach":true}'
    when 'vlan7' then '{"switch":3,"router":1,"firewall":1,"server":2,"patchPanel":1,"cloud":2,"assigned":12,"vlans":5,"rackServer":1,"towerServer":1,"rackSwitch24":true,"providers":2,"fiberSpeed":1,"satellite":true,"assignedReach":true}'
    else null end;
  if r is null then raise exception 'Atividade de prova não autorizada.'; end if;

  for k,req in select key,(value#>>'{}')::integer from jsonb_each(r)
    where key in('pc','phone','switch','router','server','firewall','wirelessRouter','patchPanel','rack','cloud') loop
    typ:=case k when 'wirelessRouter' then 'router' when 'rack' then null else k end;
    lbl:=case k when 'pc' then 'Computadores' when 'phone' then 'Celulares' when 'switch' then 'Switches' when 'router' then 'Roteadores' when 'server' then 'Servidores' when 'firewall' then 'Firewalls' when 'wirelessRouter' then 'Roteadores sem fio' when 'patchPanel' then 'Patch panels' when 'rack' then 'Racks' else 'Nuvens/Internet' end;
    if k='rack'then n:=jsonb_array_length(rs);elsif k='wirelessRouter'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'='router'and(coalesce(d->>'ssid','')<>''or d->>'routerType'in('soho','mesh_node'));else select count(*)into n from jsonb_array_elements(ds)d where d->>'type'=typ;end if;
    ch:=public._exam_check(ch,lbl||': pelo menos '||req,n>=req);
  end loop;

  if r?'pcWire'then ok:=not exists(select 1 from jsonb_array_elements(ds)p where p->>'type'='pc'and not exists(select 1 from jsonb_array_elements(ds)s cross join jsonb_array_elements(cs)c where s->>'type'='switch'and coalesce(c->>'active','true')<>'false'and((c->>'from'=p->>'id'and c->>'to'=s->>'id')or(c->>'to'=p->>'id'and c->>'from'=s->>'id'))));ch:=public._exam_check(ch,'Computadores ligados diretamente aos switches',ok);end if;
  if r?'serverWire'then ok:=exists(select 1 from jsonb_array_elements(ds)s cross join jsonb_array_elements(ds)w cross join jsonb_array_elements(cs)c where s->>'type'='server'and w->>'type'='switch'and((c->>'from'=s->>'id'and c->>'to'=w->>'id')or(c->>'to'=s->>'id'and c->>'from'=w->>'id')));ch:=public._exam_check(ch,'Servidor ligado diretamente a um switch',ok);end if;
  if r?'wifi'then ok:=not exists(select 1 from jsonb_array_elements(ds)p where p->>'type'='phone'and not exists(select 1 from jsonb_array_elements(cs)c where coalesce(c->>'active','true')<>'false'and c->>'kind'='wifi'and(c->>'from'=p->>'id'or c->>'to'=p->>'id')));ch:=public._exam_check(ch,'Todos os celulares associados por Wi-Fi',ok);end if;
  if r?'wifiAreas'then select count(distinct d->>'wifiRouterId')into n from jsonb_array_elements(ds)d where d->>'type'='phone'and coalesce(d->>'wifiRouterId','')<>'';ch:=public._exam_check(ch,'Celulares distribuídos entre '||(r->>'wifiAreas')||' áreas Wi-Fi',n>=(r->>'wifiAreas')::integer);end if;
  if r?'sameSubnet'then select count(distinct split_part(d->>'ip','.',1)||'.'||split_part(d->>'ip','.',2)||'.'||split_part(d->>'ip','.',3))into n from jsonb_array_elements(ds)d where d->>'type'in('pc','server');ch:=public._exam_check(ch,'Equipamentos na mesma rede /24',n=1);end if;
  if r?'minSubnets'then select count(distinct split_part(d->>'ip','.',1)||'.'||split_part(d->>'ip','.',2)||'.'||split_part(d->>'ip','.',3))into n from jsonb_array_elements(ds)d where d->>'type'='pc';ch:=public._exam_check(ch,'Pelo menos '||(r->>'minSubnets')||' redes /24',n>=(r->>'minSubnets')::integer);end if;
  if r?'validIps'then ok:=not exists(select 1 from jsonb_array_elements(ds)d where(d->>'vlanAssigned'='true'or d->>'type'='phone')and coalesce(d->>'ip','')!~'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$');ch:=public._exam_check(ch,'Endereços IP válidos',ok);end if;
  if r?'backbones'then select count(*)into n from jsonb_array_elements(cs)c where c->>'kind'='backbone'and coalesce(c->>'active','true')<>'false';ch:=public._exam_check(ch,'Enlaces de backbone: pelo menos '||(r->>'backbones'),n>=(r->>'backbones')::integer);end if;
  if r?'backboneSpeed'then ok:=exists(select 1 from jsonb_array_elements(cs)c where c->>'kind'='backbone'and coalesce((c->>'bw')::numeric,0)>=(r->>'backboneSpeed')::numeric);ch:=public._exam_check(ch,'Velocidade mínima do backbone atendida',ok);end if;
  if r?'core'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'in('switch','router');ch:=public._exam_check(ch,'Equipamentos centrais: pelo menos '||(r->>'core'),n>=(r->>'core')::integer);end if;
  if r?'rackServer'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'='server'and coalesce(d->>'serverType','rack')='rack'and coalesce(d->>'rackId','')<>'';ch:=public._exam_check(ch,'Servidores de rack instalados: pelo menos '||(r->>'rackServer'),n>=(r->>'rackServer')::integer);end if;
  if r?'towerServer'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'='server'and coalesce(d->>'serverType','rack')='tower';ch:=public._exam_check(ch,'Servidores torre: pelo menos '||(r->>'towerServer'),n>=(r->>'towerServer')::integer);end if;
  if r?'rackSwitch'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'='switch'and coalesce(d->>'switchForm','rack')='rack'and coalesce(d->>'rackId','')<>'';ch:=public._exam_check(ch,'Switches de rack instalados: pelo menos '||(r->>'rackSwitch'),n>=(r->>'rackSwitch')::integer);end if;
  if r?'desktopSwitch8'then ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='switch'and coalesce(d->>'switchForm','rack')='desktop'and coalesce((d->>'portCount')::integer,0)>=8);ch:=public._exam_check(ch,'Switch de mesa com pelo menos 8 portas',ok);end if;
  if r?'rackSwitch24'then ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='switch'and coalesce(d->>'switchForm','rack')='rack'and coalesce((d->>'portCount')::integer,0)>=24);ch:=public._exam_check(ch,'Switch de rack com pelo menos 24 portas',ok);end if;
  if r?'gigabit'then ok:=exists(select 1 from jsonb_array_elements(cs)c where coalesce(c->>'kind','')<>'wifi'and coalesce((c->>'bw')::numeric,0)>=1000);ch:=public._exam_check(ch,'Enlace central de pelo menos 1 Gb/s',ok);end if;
  if r?'providers'then select count(*)into n from jsonb_array_elements(ds)d where d->>'type'='cloud'and d#>>'{ispData,type}'='fibra';ch:=public._exam_check(ch,'Provedores de Internet: pelo menos '||(r->>'providers'),n>=(r->>'providers')::integer);end if;
  if r?'fiberSpeed'then ok:=exists(select 1 from jsonb_array_elements(cs)c where c->>'kind'='ispFiber'and coalesce((c->>'bw')::numeric,0)>=(r->>'fiberSpeed')::numeric);ch:=public._exam_check(ch,'Provedores interligados por fibra',ok);end if;
  if r?'satellite'then ok:=exists(select 1 from jsonb_array_elements(ds)sat where sat->>'type'='satellite'and exists(select 1 from jsonb_array_elements(ds)d cross join jsonb_array_elements(cs)c where d->>'type'='satDish'and c->>'kind'='satellite'and((c->>'from'=sat->>'id'and c->>'to'=d->>'id')or(c->>'to'=sat->>'id'and c->>'from'=d->>'id')))and exists(select 1 from jsonb_array_elements(ds)cl cross join jsonb_array_elements(cs)c where cl->>'type'='cloud'and c->>'kind'='satellite'and((c->>'from'=sat->>'id'and c->>'to'=cl->>'id')or(c->>'to'=sat->>'id'and c->>'from'=cl->>'id'))));ch:=public._exam_check(ch,'Acesso completo Antena → Satélite → Internet',ok);end if;
  if r?'assigned'then select count(*)into n from jsonb_array_elements(ds)d where d->>'vlanAssigned'='true'and d->>'type'not in('switch','cloud');ch:=public._exam_check(ch,'Dispositivos atribuídos a VLANs: pelo menos '||(r->>'assigned'),n>=(r->>'assigned')::integer);end if;
  if r?'vlans'then select count(distinct d->>'vlan')into n from jsonb_array_elements(ds)d where d->>'vlanAssigned'='true'and coalesce(d->>'vlan','')<>'';ch:=public._exam_check(ch,'VLANs diferentes: pelo menos '||(r->>'vlans'),n>=(r->>'vlans')::integer);end if;

  if r ? 'reach' or r ? 'coreReach' or r ? 'assignedReach' then
    if r?'assignedReach'then select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'vlanAssigned'='true'and d->>'type'not in('switch','cloud');
    elsif r?'coreReach'then select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'type'in('switch','router','firewall','cloud','server');
    else select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'type'in('pc','phone','server');end if;
    ok:=coalesce(array_length(ids,1),0)>1;if ok then first_id:=ids[1];foreach x in array ids loop if not public._exam_path(p_topology,first_id,x)then ok:=false;exit;end if;end loop;end if;
    ch:=public._exam_check(ch,'Comunicação entre todos os equipamentos solicitados',ok);
  end if;

  total:=jsonb_array_length(ch);select count(*)into passed from jsonb_array_elements(ch)c where(c->>'ok')::boolean;grade:=round(passed::numeric/greatest(1,total)*100);
  deadline:=least(e.ends_at,a.started_at+make_interval(mins=>e.duration_minutes));final_status:=case when now()>deadline then 'expired' else 'submitted' end;
  update public.exam_attempts set submitted_at=now(),status=final_status,score=grade,passed_checks=passed,total_checks=total,checks=ch,topology=p_topology where id=a.id;
  return jsonb_build_object('ok',true,'status',final_status,'message','Prova corrigida e entregue ao professor.');
end $$;

revoke all on function public.submit_exam_secure(uuid,jsonb) from public;
grant execute on function public.submit_exam_secure(uuid,jsonb) to anon,authenticated;
notify pgrst,'reload schema';

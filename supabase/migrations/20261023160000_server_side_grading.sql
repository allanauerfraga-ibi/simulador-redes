-- Correção automática executada no banco. O navegador envia somente a topologia.

create or replace function public._exam_path(p_topology jsonb,p_from text,p_to text,p_blocked text[] default array[]::text[])
returns boolean language sql stable set search_path=public as $$
  with recursive edges(a,b) as (
    select c->>'from',c->>'to' from jsonb_array_elements(coalesce(p_topology->'connections','[]'::jsonb)) c
    where coalesce(c->>'active','true')<>'false' and c->>'from' is not null and c->>'to' is not null
  ), walk(id) as (
    select p_from where not (p_from=any(coalesce(p_blocked,array[]::text[])))
    union
    select case when e.a=w.id then e.b else e.a end from walk w join edges e on e.a=w.id or e.b=w.id
    where not (case when e.a=w.id then e.b else e.a end=any(coalesce(p_blocked,array[]::text[])))
  ) select exists(select 1 from walk where id=p_to)
$$;

create or replace function public._exam_check(p_checks jsonb,p_label text,p_ok boolean)
returns jsonb language sql immutable set search_path=public as $$
  select coalesce(p_checks,'[]'::jsonb)||jsonb_build_array(jsonb_build_object('label',p_label,'ok',coalesce(p_ok,false)))
$$;

revoke all on function public._exam_path(jsonb,text,text,text[]) from public,anon,authenticated;
revoke all on function public._exam_check(jsonb,text,boolean) from public,anon,authenticated;

create or replace function public.submit_exam_secure(p_attempt_token uuid,p_topology jsonb)
returns jsonb language plpgsql security definer set search_path=public as $$
declare
  a public.exam_attempts%rowtype; e public.exams%rowtype;
  r jsonb; ch jsonb:='[]'::jsonb;
  ds jsonb:=coalesce(p_topology->'devices','[]'::jsonb);
  cs jsonb:=coalesce(p_topology->'connections','[]'::jsonb);
  rs jsonb:=coalesce(p_topology->'racks','[]'::jsonb);
  k text; typ text; lbl text; req integer; n integer; ok boolean;
  ids text[]; targets text[]; blocked text[]; first_id text; x text; y text;
  total integer; passed integer; grade integer; deadline timestamptz; final_status text;
begin
  if p_topology is null or jsonb_typeof(p_topology)<>'object' or jsonb_typeof(ds)<>'array'
     or jsonb_typeof(cs)<>'array' or jsonb_typeof(rs)<>'array' then raise exception 'Topologia inválida.'; end if;
  if pg_column_size(p_topology)>1048576 or jsonb_array_length(ds)>100 or jsonb_array_length(cs)>300 or jsonb_array_length(rs)>30
     then raise exception 'Topologia excede os limites permitidos.'; end if;
  if exists(select 1 from jsonb_array_elements(ds) d where coalesce(d->>'id','')='' or coalesce(d->>'type','') not in
     ('pc','phone','router','switch','patchPanel','server','firewall','cloud','satDish','satellite'))
     or (select count(*) from jsonb_array_elements(ds))<>(select count(distinct d->>'id') from jsonb_array_elements(ds) d)
     then raise exception 'A topologia contém equipamentos inválidos ou repetidos.'; end if;

  select * into a from public.exam_attempts where attempt_token=p_attempt_token for update;
  if a.id is null then raise exception 'Tentativa não encontrada.'; end if;
  if a.status<>'in_progress' then raise exception 'Esta prova já foi entregue.'; end if;
  select * into e from public.exams where id=a.exam_id;
  r:=case e.activity_key
    when 'prova01' then '{"pc":4,"phone":2,"switch":2,"wirelessRouter":1,"server":1,"mixedComputers":true,"towerServer":true,"pcToSwitch":true,"phonesWifi":true,"switchesLinked":true,"gigabit":true,"allReachServers":true}'
    when 'prova02' then '{"pc":6,"switch":2,"router":1,"firewall":1,"server":1,"towerServer":true,"pcToSwitch":true,"routerToSwitch":true,"minSubnets":2,"allReachServers":true,"firewallPath":true}'
    when 'prova03' then '{"pc":4,"phone":4,"switch":2,"wirelessRouter":2,"server":1,"towerServer":true,"pcToSwitch":true,"phonesWifi":true,"twoWifiAreas":true,"wirelessRoutersLinked":true,"switchesLinked":true,"gigabit":true,"allReachServers":true}'
    when 'prova04' then '{"pc":6,"switch":3,"firewall":1,"server":2,"patchPanel":1,"rack":1,"towerServer":true,"rackServer":true,"rackSwitch":true,"rackPatchLinked":true,"pcToSwitch":true,"switchesLinked":true,"gigabit":true,"allReachServers":true}'
    when 'prova05' then '{"pc":4,"phone":4,"switch":2,"wirelessRouter":2,"firewall":1,"server":1,"towerServer":true,"pcToSwitch":true,"phonesWifi":true,"twoWifiAreas":true,"switchesLinked":true,"gigabit":true,"allReachServers":true,"firewallPath":true}'
    when 'prova06' then '{"pc":6,"phone":2,"switch":3,"wirelessRouter":1,"firewall":1,"server":2,"patchPanel":1,"rack":1,"towerServer":true,"rackServer":true,"rackSwitch":true,"rackPatchLinked":true,"pcToSwitch":true,"phonesWifi":true,"minSubnets":2,"gigabit":true,"allReachServers":true}'
    when 'prova07' then '{"pc":4,"phone":4,"switch":2,"wirelessRouter":2,"firewall":1,"server":1,"cloud":1,"towerServer":true,"pcToSwitch":true,"phonesWifi":true,"twoWifiAreas":true,"gigabit":true,"allReachServers":true,"internetReach":true}'
    when 'prova08' then '{"pc":6,"phone":4,"switch":3,"wirelessRouter":2,"firewall":1,"server":2,"patchPanel":1,"rack":1,"towerServer":true,"rackServer":true,"rackSwitch":true,"rackPatchLinked":true,"pcToSwitch":true,"phonesWifi":true,"twoWifiAreas":true,"gigabit":true,"allReachServers":true}'
    when 'prova09' then '{"pc":4,"phone":6,"switch":2,"wirelessRouter":2,"firewall":1,"server":1,"towerServer":true,"pcToSwitch":true,"phonesWifi":true,"twoWifiAreas":true,"wirelessRoutersLinked":true,"gigabit":true,"allReachServers":true,"firewallPath":true}'
    when 'prova10' then '{"pc":6,"phone":4,"switch":3,"wirelessRouter":2,"firewall":1,"server":2,"patchPanel":1,"rack":1,"desktopSwitch8":true,"towerServer":true,"rackServer":true,"rackSwitch":true,"rackPatchLinked":true,"pcToSwitch":true,"phonesWifi":true,"gigabit":true,"allReachServers":true}'
    when 'prova11' then '{"pc":4,"phone":6,"switch":2,"wirelessRouter":2,"firewall":1,"server":1,"cloud":1,"towerServer":true,"pcToSwitch":true,"phonesWifi":true,"twoWifiAreas":true,"satelliteInternet":true,"gigabit":true,"allReachServers":true,"internetReach":true}'
    when 'prova12' then '{"pc":6,"phone":4,"switch":3,"wirelessRouter":2,"firewall":1,"server":2,"patchPanel":1,"rack":1,"towerServer":true,"rackServer":true,"rackSwitch":true,"rackPatchLinked":true,"minBackbones":3,"pcToSwitch":true,"phonesWifi":true,"gigabit":true,"allReachServers":true}'
    when 'prova13' then '{"pc":4,"phone":4,"switch":2,"wirelessRouter":2,"firewall":1,"server":1,"cloud":2,"providers":2,"providerFiber":10000,"towerServer":true,"pcToSwitch":true,"phonesWifi":true,"twoWifiAreas":true,"gigabit":true,"allReachServers":true,"internetReach":true}'
    when 'prova14' then '{"pc":6,"phone":6,"switch":3,"wirelessRouter":2,"firewall":1,"server":2,"patchPanel":1,"rack":1,"cloud":2,"providers":2,"providerFiber":10000,"satelliteInternet":true,"towerServer":true,"rackServer":true,"rackSwitch":true,"rackPatchLinked":true,"pcToSwitch":true,"phonesWifi":true,"gigabit":true,"allReachServers":true,"internetReach":true}'
    when 'prova15' then '{"pc":6,"phone":6,"switch":3,"wirelessRouter":2,"firewall":1,"server":2,"patchPanel":1,"rack":1,"cloud":2,"providers":2,"providerFiber":10000,"satelliteInternet":true,"towerServer":true,"rackServer":true,"rackSwitch":true,"rackPatchLinked":true,"minBackbones":4,"pcToSwitch":true,"phonesWifi":true,"twoWifiAreas":true,"gigabit":true,"allReachServers":true,"internetReach":true}'
    else null end;
  if r is null then raise exception 'Atividade de prova não autorizada.'; end if;

  for k,req in select key,(value#>>'{}')::integer from jsonb_each(r)
    where key in ('pc','phone','switch','router','server','firewall','wirelessRouter','patchPanel','rack','cloud') loop
    typ:=case k when 'wirelessRouter' then 'router' when 'rack' then null else k end;
    lbl:=case k when 'pc' then 'Computadores' when 'phone' then 'Celulares' when 'switch' then 'Switches'
      when 'router' then 'Roteadores' when 'server' then 'Servidores' when 'firewall' then 'Firewalls'
      when 'wirelessRouter' then 'Roteadores sem fio' when 'patchPanel' then 'Patch panels' when 'rack' then 'Racks' else 'Nuvens/Internet' end;
    if k='rack' then n:=jsonb_array_length(rs);
    elsif k='wirelessRouter' then select count(*) into n from jsonb_array_elements(ds) d where d->>'type'='router' and (coalesce(d->>'ssid','')<>'' or d->>'routerType' in ('soho','mesh_node'));
    else select count(*) into n from jsonb_array_elements(ds) d where d->>'type'=typ; end if;
    ch:=public._exam_check(ch,lbl||': pelo menos '||req,n>=req);
  end loop;

  if r?'mixedComputers' then ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='pc' and coalesce(d->>'pcStyle','notebook')='notebook') and exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='pc' and d->>'pcStyle'='complete');ch:=public._exam_check(ch,'Notebook e Computador presentes',ok);end if;
  if r?'desktopSwitch8' then ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='switch' and coalesce(d->>'switchForm','rack')='desktop' and coalesce((d->>'portCount')::numeric,0)>=8);ch:=public._exam_check(ch,'Switch de mesa com pelo menos 8 portas',ok);end if;
  if r?'towerServer' then ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='server' and coalesce(d->>'serverType','rack')='tower');ch:=public._exam_check(ch,'Servidor do tipo torre presente',ok);end if;
  if r?'rackServer' then ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='server' and coalesce(d->>'serverType','rack')='rack' and coalesce(d->>'rackId','')<>'');ch:=public._exam_check(ch,'Servidor de rack instalado no rack',ok);end if;
  if r?'rackSwitch' then ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='switch' and coalesce(d->>'switchForm','rack')='rack' and coalesce(d->>'rackId','')<>'');ch:=public._exam_check(ch,'Switch de rack instalado',ok);end if;
  if r?'rackPatchLinked' then
    ok:=exists(select 1 from jsonb_array_elements(ds)p cross join jsonb_array_elements(ds)s where p->>'type'='patchPanel' and coalesce(p->>'rackId','')<>'' and s->>'type'='switch' and s->>'rackId'=p->>'rackId' and coalesce(s->>'switchForm','rack')='rack' and exists(select 1 from jsonb_array_elements(cs)c where coalesce(c->>'active','true')<>'false' and coalesce((c->>'rackCable')::boolean,false) and ((c->>'from'=p->>'id' and c->>'to'=s->>'id')or(c->>'to'=p->>'id' and c->>'from'=s->>'id'))));
    ch:=public._exam_check(ch,'Patch panel ligado ao switch dentro do rack',ok);end if;
  if r?'providers' then select count(*) into n from jsonb_array_elements(ds)d where d->>'type'='cloud' and d#>>'{ispData,type}'='fibra';ch:=public._exam_check(ch,'Pelo menos '||(r->>'providers')||' provedores de Internet',n>=(r->>'providers')::integer);end if;
  if r?'providerFiber' then ok:=exists(select 1 from jsonb_array_elements(cs)c where coalesce(c->>'active','true')<>'false' and c->>'kind'='ispFiber' and coalesce((c->>'bw')::numeric,0)>=(r->>'providerFiber')::numeric);ch:=public._exam_check(ch,'Provedores ligados por fibra de pelo menos 10 Gbps',ok);end if;
  if r?'satelliteInternet' then
    ok:=exists(select 1 from jsonb_array_elements(ds)sat where sat->>'type'='satellite' and exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='satDish' and exists(select 1 from jsonb_array_elements(cs)c where c->>'kind'='satellite' and ((c->>'from'=sat->>'id' and c->>'to'=d->>'id')or(c->>'to'=sat->>'id' and c->>'from'=d->>'id')))) and exists(select 1 from jsonb_array_elements(ds)cl where cl->>'type'='cloud' and exists(select 1 from jsonb_array_elements(cs)c where c->>'kind'='satellite' and ((c->>'from'=sat->>'id' and c->>'to'=cl->>'id')or(c->>'to'=sat->>'id' and c->>'from'=cl->>'id')))));
    ch:=public._exam_check(ch,'Acesso completo Antena → Satélite → Internet',ok);end if;
  if r?'minBackbones' then select count(*) into n from jsonb_array_elements(cs)c where coalesce(c->>'active','true')<>'false' and c->>'kind'='backbone';ch:=public._exam_check(ch,'Pelo menos '||(r->>'minBackbones')||' enlaces de backbone',n>=(r->>'minBackbones')::integer);end if;

  if r?'pcToSwitch' then
    ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='pc') and not exists(select 1 from jsonb_array_elements(ds)p where p->>'type'='pc' and not exists(select 1 from jsonb_array_elements(ds)s cross join jsonb_array_elements(cs)c where s->>'type'='switch' and coalesce(c->>'active','true')<>'false' and ((c->>'from'=p->>'id'and c->>'to'=s->>'id')or(c->>'to'=p->>'id'and c->>'from'=s->>'id'))));
    ch:=public._exam_check(ch,'Todos os computadores ligados diretamente aos switches',ok);end if;
  if r?'routerToSwitch' then ok:=exists(select 1 from jsonb_array_elements(ds)ro cross join jsonb_array_elements(ds)s cross join jsonb_array_elements(cs)c where ro->>'type'='router'and s->>'type'='switch'and coalesce(c->>'active','true')<>'false'and((c->>'from'=ro->>'id'and c->>'to'=s->>'id')or(c->>'to'=ro->>'id'and c->>'from'=s->>'id')));ch:=public._exam_check(ch,'Roteador ligado à infraestrutura de switches',ok);end if;
  if r?'phonesWifi' then ok:=exists(select 1 from jsonb_array_elements(ds)d where d->>'type'='phone')and not exists(select 1 from jsonb_array_elements(ds)p where p->>'type'='phone'and not exists(select 1 from jsonb_array_elements(cs)c where coalesce(c->>'active','true')<>'false'and c->>'kind'='wifi'and(c->>'from'=p->>'id'or c->>'to'=p->>'id')));ch:=public._exam_check(ch,'Todos os celulares associados por Wi-Fi',ok);end if;
  if r?'twoWifiAreas' then select count(distinct d->>'wifiRouterId')into n from jsonb_array_elements(ds)d where d->>'type'='phone'and coalesce(d->>'wifiRouterId','')<>'';ch:=public._exam_check(ch,'Celulares distribuídos entre pelo menos duas áreas Wi-Fi',n>=2);end if;

  if r?'wirelessRoutersLinked' then select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'type'='router'and(coalesce(d->>'ssid','')<>''or d->>'routerType'in('soho','mesh_node'));ok:=coalesce(array_length(ids,1),0)>1;if ok then first_id:=ids[1];foreach x in array ids loop if not public._exam_path(p_topology,first_id,x)then ok:=false;exit;end if;end loop;end if;ch:=public._exam_check(ch,'Roteadores sem fio interligados',ok);end if;
  if r?'switchesLinked' then select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'type'='switch';ok:=coalesce(array_length(ids,1),0)>1;if ok then first_id:=ids[1];foreach x in array ids loop if not public._exam_path(p_topology,first_id,x)then ok:=false;exit;end if;end loop;end if;ch:=public._exam_check(ch,'Todos os switches interligados',ok);end if;
  if r?'minSubnets' then
    select count(distinct split_part(d->>'ip','.',1)||'.'||split_part(d->>'ip','.',2)||'.'||split_part(d->>'ip','.',3)),bool_and(d->>'ip'~'^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$')into n,ok from jsonb_array_elements(ds)d where d->>'type'='pc';
    ch:=public._exam_check(ch,'Pelo menos '||(r->>'minSubnets')||' redes /24 diferentes',coalesce(ok,false)and n>=(r->>'minSubnets')::integer);end if;
  if r?'allReachServers' then select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'type'in('pc','phone');select array_agg(d->>'id')into targets from jsonb_array_elements(ds)d where d->>'type'='server';ok:=coalesce(array_length(ids,1),0)>0 and coalesce(array_length(targets,1),0)>0;if ok then foreach x in array ids loop foreach y in array targets loop if not public._exam_path(p_topology,x,y)then ok:=false;exit;end if;end loop;exit when not ok;end loop;end if;ch:=public._exam_check(ch,'Todos os clientes alcançam o servidor',ok);end if;
  if r?'internetReach' then select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'type'in('pc','phone');select array_agg(d->>'id')into targets from jsonb_array_elements(ds)d where d->>'type'='cloud';ok:=coalesce(array_length(ids,1),0)>0 and coalesce(array_length(targets,1),0)>0;if ok then foreach x in array ids loop foreach y in array targets loop if not public._exam_path(p_topology,x,y)then ok:=false;exit;end if;end loop;exit when not ok;end loop;end if;ch:=public._exam_check(ch,'Todos os clientes alcançam a Internet',ok);end if;
  if r?'firewallPath' then select array_agg(d->>'id')into ids from jsonb_array_elements(ds)d where d->>'type'in('pc','phone');select array_agg(d->>'id')into targets from jsonb_array_elements(ds)d where d->>'type'='server';select array_agg(d->>'id')into blocked from jsonb_array_elements(ds)d where d->>'type'='firewall';ok:=coalesce(array_length(ids,1),0)>0 and coalesce(array_length(targets,1),0)>0 and coalesce(array_length(blocked,1),0)>0;if ok then foreach x in array ids loop foreach y in array targets loop if not public._exam_path(p_topology,x,y)or public._exam_path(p_topology,x,y,blocked)then ok:=false;exit;end if;end loop;exit when not ok;end loop;end if;ch:=public._exam_check(ch,'O caminho de todos os clientes até o servidor passa pelo firewall',ok);end if;
  if r?'gigabit' then ok:=exists(select 1 from jsonb_array_elements(cs)c where coalesce(c->>'active','true')<>'false'and coalesce(c->>'kind','')<>'wifi'and coalesce((c->>'bw')::numeric,0)>=1000 and exists(select 1 from jsonb_array_elements(ds)d where d->>'id'=c->>'from'and d->>'type'in('switch','router','firewall','server','patchPanel'))and exists(select 1 from jsonb_array_elements(ds)d where d->>'id'=c->>'to'and d->>'type'in('switch','router','firewall','server','patchPanel')));ch:=public._exam_check(ch,'Pelo menos um enlace central configurado em 1 Gb/s',ok);end if;

  total:=jsonb_array_length(ch);select count(*)into passed from jsonb_array_elements(ch)c where(c->>'ok')::boolean;grade:=round(passed::numeric/greatest(1,total)*100);
  deadline:=least(e.ends_at,a.started_at+make_interval(mins=>e.duration_minutes));final_status:=case when now()>deadline then 'expired'else'submitted'end;
  update public.exam_attempts set submitted_at=now(),status=final_status,score=grade,passed_checks=passed,total_checks=total,checks=ch,topology=p_topology where id=a.id;
  return jsonb_build_object('ok',true,'status',final_status,'message','Prova corrigida e entregue ao professor.');
end $$;

revoke all on function public.submit_exam_secure(uuid,jsonb) from public;
grant execute on function public.submit_exam_secure(uuid,jsonb) to anon,authenticated;
notify pgrst,'reload schema';

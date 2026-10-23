const SUPABASE_URL = Deno.env.get('SUPABASE_URL') || '';
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '';
const ALLOWED_ORIGINS = new Set(['https://allanauerfraga-ibi.github.io', 'null']);
const DEVICE_TYPES = new Set(['pc','phone','router','switch','patchPanel','server','firewall','cloud','satDish','satellite']);

const RULES: Record<string, Record<string, number | boolean>> = {
  prova01:{pc:4,phone:2,switch:2,wirelessRouter:1,server:1,mixedComputers:true,towerServer:true,pcToSwitch:true,phonesWifi:true,switchesLinked:true,gigabit:true,allReachServers:true},
  prova02:{pc:6,switch:2,router:1,firewall:1,server:1,towerServer:true,pcToSwitch:true,routerToSwitch:true,minSubnets:2,allReachServers:true,firewallPath:true},
  prova03:{pc:4,phone:4,switch:2,wirelessRouter:2,server:1,towerServer:true,pcToSwitch:true,phonesWifi:true,twoWifiAreas:true,wirelessRoutersLinked:true,switchesLinked:true,gigabit:true,allReachServers:true},
  prova04:{pc:6,switch:3,firewall:1,server:2,patchPanel:1,rack:1,towerServer:true,rackServer:true,rackSwitch:true,rackPatchLinked:true,pcToSwitch:true,switchesLinked:true,gigabit:true,allReachServers:true},
  prova05:{pc:4,phone:4,switch:2,wirelessRouter:2,firewall:1,server:1,towerServer:true,pcToSwitch:true,phonesWifi:true,twoWifiAreas:true,switchesLinked:true,gigabit:true,allReachServers:true,firewallPath:true},
  prova06:{pc:6,phone:2,switch:3,wirelessRouter:1,firewall:1,server:2,patchPanel:1,rack:1,towerServer:true,rackServer:true,rackSwitch:true,rackPatchLinked:true,pcToSwitch:true,phonesWifi:true,minSubnets:2,gigabit:true,allReachServers:true},
  prova07:{pc:4,phone:4,switch:2,wirelessRouter:2,firewall:1,server:1,cloud:1,towerServer:true,pcToSwitch:true,phonesWifi:true,twoWifiAreas:true,gigabit:true,allReachServers:true,internetReach:true},
  prova08:{pc:6,phone:4,switch:3,wirelessRouter:2,firewall:1,server:2,patchPanel:1,rack:1,towerServer:true,rackServer:true,rackSwitch:true,rackPatchLinked:true,pcToSwitch:true,phonesWifi:true,twoWifiAreas:true,gigabit:true,allReachServers:true},
  prova09:{pc:4,phone:6,switch:2,wirelessRouter:2,firewall:1,server:1,towerServer:true,pcToSwitch:true,phonesWifi:true,twoWifiAreas:true,wirelessRoutersLinked:true,gigabit:true,allReachServers:true,firewallPath:true},
  prova10:{pc:6,phone:4,switch:3,wirelessRouter:2,firewall:1,server:2,patchPanel:1,rack:1,desktopSwitch8:true,towerServer:true,rackServer:true,rackSwitch:true,rackPatchLinked:true,pcToSwitch:true,phonesWifi:true,gigabit:true,allReachServers:true},
  prova11:{pc:4,phone:6,switch:2,wirelessRouter:2,firewall:1,server:1,cloud:1,towerServer:true,pcToSwitch:true,phonesWifi:true,twoWifiAreas:true,satelliteInternet:true,gigabit:true,allReachServers:true,internetReach:true},
  prova12:{pc:6,phone:4,switch:3,wirelessRouter:2,firewall:1,server:2,patchPanel:1,rack:1,towerServer:true,rackServer:true,rackSwitch:true,rackPatchLinked:true,minBackbones:3,pcToSwitch:true,phonesWifi:true,gigabit:true,allReachServers:true},
  prova13:{pc:4,phone:4,switch:2,wirelessRouter:2,firewall:1,server:1,cloud:2,providers:2,providerFiber:10000,towerServer:true,pcToSwitch:true,phonesWifi:true,twoWifiAreas:true,gigabit:true,allReachServers:true,internetReach:true},
  prova14:{pc:6,phone:6,switch:3,wirelessRouter:2,firewall:1,server:2,patchPanel:1,rack:1,cloud:2,providers:2,providerFiber:10000,satelliteInternet:true,towerServer:true,rackServer:true,rackSwitch:true,rackPatchLinked:true,pcToSwitch:true,phonesWifi:true,gigabit:true,allReachServers:true,internetReach:true},
  prova15:{pc:6,phone:6,switch:3,wirelessRouter:2,firewall:1,server:2,patchPanel:1,rack:1,cloud:2,providers:2,providerFiber:10000,satelliteInternet:true,towerServer:true,rackServer:true,rackSwitch:true,rackPatchLinked:true,minBackbones:4,pcToSwitch:true,phonesWifi:true,twoWifiAreas:true,gigabit:true,allReachServers:true,internetReach:true}
};

function cors(origin: string | null) {
  const allowed = origin && ALLOWED_ORIGINS.has(origin) ? origin : 'https://allanauerfraga-ibi.github.io';
  return {'Access-Control-Allow-Origin':allowed,'Vary':'Origin','Access-Control-Allow-Headers':'authorization, x-client-info, apikey, content-type','Access-Control-Allow-Methods':'POST, OPTIONS','Cache-Control':'no-store'};
}
function reply(status:number,body:Record<string,unknown>,origin:string|null){return new Response(JSON.stringify(body),{status,headers:{...cors(origin),'Content-Type':'application/json; charset=utf-8'}});}
function asId(value:unknown){return String(value??'');}
function asNumber(value:unknown){const number=Number(value);return Number.isFinite(number)?number:0;}

export function grade(activityKey:string,topology:any){
  const rules=RULES[activityKey];if(!rules)throw new Error('Atividade de prova não autorizada.');
  if(!topology||typeof topology!=='object'||!Array.isArray(topology.devices)||!Array.isArray(topology.connections))throw new Error('Topologia inválida.');
  if(topology.devices.length>100||topology.connections.length>300)throw new Error('Topologia excede os limites permitidos.');
  const devices=topology.devices.filter((d:any)=>d&&DEVICE_TYPES.has(String(d.type))).map((d:any)=>({...d,id:asId(d.id)}));
  const ids=new Set(devices.map((d:any)=>d.id));if(ids.size!==devices.length)throw new Error('A topologia contém equipamentos repetidos.');
  const connections=topology.connections.filter((c:any)=>c&&c.active!==false&&ids.has(asId(c.from))&&ids.has(asId(c.to))&&asId(c.from)!==asId(c.to)).map((c:any)=>({...c,from:asId(c.from),to:asId(c.to),bw:asNumber(c.bw)}));
  const racks=Array.isArray(topology.racks)?topology.racks.slice(0,30):[];
  const byType=(type:string)=>devices.filter((d:any)=>d.type===type),pcs=byType('pc'),phones=byType('phone'),switches=byType('switch'),routers=byType('router'),servers=byType('server'),firewalls=byType('firewall'),clouds=byType('cloud'),patchPanels=byType('patchPanel');
  const wirelessRouters=routers.filter((d:any)=>d.ssid||d.routerType==='soho'||d.routerType==='mesh_node');
  const providers=clouds.filter((d:any)=>d.ispData?.type==='fibra');
  const clients=[...pcs,...phones],coreTypes=new Set(['switch','router','firewall','server','patchPanel']);
  const adjacency=new Map<string,Set<string>>();devices.forEach((d:any)=>adjacency.set(d.id,new Set()));connections.forEach((c:any)=>{adjacency.get(c.from)?.add(c.to);adjacency.get(c.to)?.add(c.from);});
  const linked=(a:any,b:any,kind?:string)=>connections.some((c:any)=>(!kind||c.kind===kind)&&((c.from===a.id&&c.to===b.id)||(c.to===a.id&&c.from===b.id)));
  const reachable=(from:string,to:string,blocked=new Set<string>())=>{if(blocked.has(from)||blocked.has(to))return false;const queue=[from],seen=new Set([from]);while(queue.length){const current=queue.shift()!;if(current===to)return true;for(const next of adjacency.get(current)||[]){if(!seen.has(next)&&!blocked.has(next)){seen.add(next);queue.push(next);}}}return false;};
  const everyDirect=(items:any[],targets:any[])=>items.length>0&&items.every(a=>targets.some(b=>linked(a,b)));
  const pairReachable=(items:any[])=>items.length>1&&items.slice(1).every(d=>reachable(items[0].id,d.id));
  const allReach=(items:any[],targets:any[])=>items.length>0&&targets.length>0&&items.every(a=>targets.every(b=>reachable(a.id,b.id)));
  const validIp=(d:any)=>/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(String(d.ip||''))&&String(d.ip).split('.').every((v:string)=>+v>=0&&+v<=255);
  const subnetCount=(items:any[])=>new Set(items.filter(validIp).map((d:any)=>String(d.ip).split('.').slice(0,3).join('.'))).size;
  const wifiLinks=connections.filter((c:any)=>c.kind==='wifi');
  const phonesWifi=phones.length>0&&phones.every((p:any)=>wifiLinks.some((c:any)=>c.from===p.id||c.to===p.id));
  const twoWifiAreas=new Set(phones.map((p:any)=>asId(p.wifiRouterId)).filter(Boolean)).size>=2;
  const towerServer=servers.some((d:any)=>(d.serverType||'rack')==='tower'),rackServer=servers.some((d:any)=>(d.serverType||'rack')==='rack'&&d.rackId);
  const rackSwitch=switches.some((d:any)=>(d.switchForm||'rack')==='rack'&&d.rackId),desktopSwitch8=switches.some((d:any)=>(d.switchForm||'rack')==='desktop'&&asNumber(d.portCount)>=8);
  const rackPatchLinked=patchPanels.some((p:any)=>p.rackId&&switches.some((s:any)=>s.rackId===p.rackId&&(s.switchForm||'rack')==='rack'&&connections.some((c:any)=>c.rackCable&&((c.from===p.id&&c.to===s.id)||(c.to===p.id&&c.from===s.id)))));
  const gigabit=connections.some((c:any)=>c.kind!=='wifi'&&c.bw>=1000&&[c.from,c.to].every((id:string)=>coreTypes.has(devices.find((d:any)=>d.id===id)?.type)));
  const providerFiber=connections.some((c:any)=>c.kind==='ispFiber'&&c.bw>=asNumber(rules.providerFiber));
  const satelliteInternet=byType('satellite').some((sat:any)=>byType('satDish').some((dish:any)=>linked(sat,dish,'satellite'))&&clouds.some((cloud:any)=>linked(sat,cloud,'satellite')));
  const firewallIds=new Set(firewalls.map((d:any)=>d.id));
  const firewallPath=clients.length>0&&servers.length>0&&firewalls.length>0&&clients.every((c:any)=>servers.every((s:any)=>reachable(c.id,s.id)&&!reachable(c.id,s.id,firewallIds)));
  const checks:Array<{label:string,ok:boolean}>=[],add=(label:string,ok:boolean)=>checks.push({label,ok:!!ok}),atLeast=(label:string,current:number,required:unknown)=>{const n=asNumber(required);if(n)add(`${label}: pelo menos ${n}`,current>=n);};
  atLeast('Computadores',pcs.length,rules.pc);atLeast('Celulares',phones.length,rules.phone);atLeast('Switches',switches.length,rules.switch);atLeast('Roteadores',routers.length,rules.router);atLeast('Servidores',servers.length,rules.server);atLeast('Firewalls',firewalls.length,rules.firewall);atLeast('Roteadores sem fio',wirelessRouters.length,rules.wirelessRouter);atLeast('Patch panels',patchPanels.length,rules.patchPanel);atLeast('Racks',racks.length,rules.rack);atLeast('Nuvens/Internet',clouds.length,rules.cloud);
  if(rules.mixedComputers)add('Notebook e Computador presentes',pcs.some((p:any)=>(p.pcStyle||'notebook')==='notebook')&&pcs.some((p:any)=>p.pcStyle==='complete'));
  if(rules.desktopSwitch8)add('Switch de mesa com pelo menos 8 portas',desktopSwitch8);if(rules.towerServer)add('Servidor do tipo torre presente',towerServer);if(rules.rackServer)add('Servidor de rack instalado no rack',rackServer);if(rules.rackSwitch)add('Switch de rack instalado',rackSwitch);if(rules.rackPatchLinked)add('Patch panel ligado ao switch dentro do rack',rackPatchLinked);
  if(rules.providers)add(`Pelo menos ${rules.providers} provedores de Internet`,providers.length>=asNumber(rules.providers));if(rules.providerFiber)add('Provedores ligados por fibra de pelo menos 10 Gbps',providerFiber);if(rules.satelliteInternet)add('Acesso completo Antena → Satélite → Internet',satelliteInternet);if(rules.minBackbones)add(`Pelo menos ${rules.minBackbones} enlaces de backbone`,connections.filter((c:any)=>c.kind==='backbone').length>=asNumber(rules.minBackbones));
  if(rules.pcToSwitch)add('Todos os computadores ligados diretamente aos switches',everyDirect(pcs,switches));if(rules.routerToSwitch)add('Roteador ligado à infraestrutura de switches',routers.some((r:any)=>switches.some((s:any)=>linked(r,s))));if(rules.phonesWifi)add('Todos os celulares associados por Wi-Fi',phonesWifi);if(rules.twoWifiAreas)add('Celulares distribuídos entre pelo menos duas áreas Wi-Fi',twoWifiAreas);if(rules.wirelessRoutersLinked)add('Roteadores sem fio interligados',pairReachable(wirelessRouters));if(rules.switchesLinked)add('Todos os switches interligados',pairReachable(switches));
  if(rules.minSubnets)add(`Pelo menos ${rules.minSubnets} redes /24 diferentes`,pcs.length>0&&pcs.every(validIp)&&subnetCount(pcs)>=asNumber(rules.minSubnets));if(rules.allReachServers)add('Todos os clientes alcançam o servidor',allReach(clients,servers));if(rules.internetReach)add('Todos os clientes alcançam a Internet',allReach(clients,clouds));if(rules.firewallPath)add('O caminho de todos os clientes até o servidor passa pelo firewall',firewallPath);if(rules.gigabit)add('Pelo menos um enlace central configurado em 1 Gb/s',gigabit);
  const passed=checks.filter(item=>item.ok).length,total=checks.length,score=Math.round(passed/Math.max(1,total)*100);
  return {checks,passed,total,score};
}

Deno.serve(async req=>{
  const origin=req.headers.get('origin');
  if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors(origin)});
  if(req.method!=='POST')return reply(405,{message:'Método não permitido.'},origin);
  if(origin&&!ALLOWED_ORIGINS.has(origin))return reply(403,{message:'Origem não autorizada.'},origin);
  if(!SUPABASE_URL||!SERVICE_KEY)return reply(503,{message:'Serviço de correção indisponível.'},origin);
  try{
    const raw=await req.text();if(raw.length>1100000)return reply(413,{message:'Entrega excede o limite permitido.'},origin);
    const body=JSON.parse(raw),token=String(body.attempt_token||'');
    if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token))return reply(400,{message:'Tentativa inválida.'},origin);
    const headers={apikey:SERVICE_KEY,Authorization:`Bearer ${SERVICE_KEY}`,'Content-Type':'application/json'};
    const attemptResponse=await fetch(`${SUPABASE_URL}/rest/v1/exam_attempts?attempt_token=eq.${encodeURIComponent(token)}&select=id,exam_id,status`,{headers});
    const attempts=await attemptResponse.json();if(!attemptResponse.ok)throw new Error('Falha ao localizar a tentativa.');
    const attempt=attempts?.[0];if(!attempt||attempt.status!=='in_progress')return reply(409,{message:'Tentativa não encontrada ou já entregue.'},origin);
    const examResponse=await fetch(`${SUPABASE_URL}/rest/v1/exams?id=eq.${encodeURIComponent(attempt.exam_id)}&select=activity_key`,{headers});
    const exams=await examResponse.json();if(!examResponse.ok||!exams?.[0])throw new Error('Prova não encontrada.');
    const result=grade(exams[0].activity_key,body.topology);
    const submitResponse=await fetch(`${SUPABASE_URL}/rest/v1/rpc/submit_exam`,{method:'POST',headers,body:JSON.stringify({p_attempt_token:token,p_score:result.score,p_passed_checks:result.passed,p_total_checks:result.total,p_checks:result.checks,p_topology:body.topology})});
    const submitted=await submitResponse.json();if(!submitResponse.ok)throw new Error(submitted?.message||'Não foi possível finalizar a prova.');
    return reply(200,{ok:true,status:submitted?.status||'submitted',message:'Prova corrigida e entregue ao professor.'},origin);
  }catch(error){return reply(400,{message:error instanceof Error?error.message:'Entrega inválida.'},origin);}
});

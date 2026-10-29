-- AllanNet EDU - Sala de Prova (Supabase)
-- Execute este arquivo uma única vez no SQL Editor do projeto Supabase.

create extension if not exists pgcrypto;

create table if not exists public.teacher_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Professor',
  created_at timestamptz not null default now()
);

create table if not exists public.exams (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  activity_key text not null,
  target_grade text not null default '',
  target_class text not null default '',
  max_score numeric(8,2) not null default 10 check (max_score > 0 and max_score <= 1000),
  duration_minutes integer not null default 50 check (duration_minutes between 5 and 240),
  starts_at timestamptz not null default now(),
  ends_at timestamptz not null,
  active boolean not null default true,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.exam_attempts (
  id uuid primary key default gen_random_uuid(),
  exam_id uuid not null references public.exams(id) on delete cascade,
  attempt_token uuid not null default gen_random_uuid() unique,
  student_name text not null,
  student_grade text not null,
  student_class text not null,
  started_at timestamptz not null default now(),
  submitted_at timestamptz,
  status text not null default 'in_progress' check (status in ('in_progress','submitted','expired')),
  score integer check (score between 0 and 100),
  passed_checks integer,
  total_checks integer,
  checks jsonb not null default '[]'::jsonb,
  topology jsonb not null default '{}'::jsonb
);

create unique index if not exists one_attempt_per_student
on public.exam_attempts (exam_id, lower(trim(student_name)), lower(trim(student_grade)), lower(trim(student_class)));

alter table public.teacher_profiles enable row level security;
alter table public.exams enable row level security;
alter table public.exam_attempts enable row level security;

-- A primeira conta criada no projeto é o professor proprietário. Novas contas
-- não recebem autorização automaticamente.
insert into public.teacher_profiles(user_id,display_name)
select id,coalesce(nullif(raw_user_meta_data->>'name',''),'Professor') from auth.users
where not exists(select 1 from public.teacher_profiles)
order by created_at asc limit 1 on conflict(user_id) do nothing;

drop policy if exists teacher_own_profile on public.teacher_profiles;
create policy teacher_own_profile on public.teacher_profiles
for select to authenticated using (user_id = auth.uid());

drop policy if exists teacher_own_exams on public.exams;
create policy teacher_own_exams on public.exams
for all to authenticated
using (teacher_id=auth.uid() and exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid()))
with check (teacher_id=auth.uid() and exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid()));

drop policy if exists teacher_reads_attempts on public.exam_attempts;
create policy teacher_reads_attempts on public.exam_attempts
for select to authenticated using (
  exists (select 1 from public.exams e join public.teacher_profiles p on p.user_id=e.teacher_id where e.id=exam_id and e.teacher_id=auth.uid())
);

create or replace function public.teacher_access() returns boolean
language sql stable security definer set search_path=public
as $$ select auth.uid() is not null and exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid()) $$;

create or replace function public.create_exam(
  p_title text, p_activity_key text, p_password text,
  p_target_grade text, p_target_class text,
  p_duration_minutes integer, p_max_score numeric,
  p_starts_at timestamptz, p_ends_at timestamptz
) returns uuid
language plpgsql security definer set search_path = public, extensions
as $$
declare v_id uuid;
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid()) then raise exception 'Conta não autorizada como professor.'; end if;
  if length(trim(p_password)) < 8 then raise exception 'A senha deve possuir pelo menos 8 caracteres.'; end if;
  if p_ends_at <= p_starts_at then raise exception 'O encerramento deve ser posterior ao início.'; end if;
  insert into public.exams(teacher_id,title,activity_key,target_grade,target_class,duration_minutes,max_score,starts_at,ends_at,password_hash)
  values(auth.uid(),trim(p_title),p_activity_key,trim(coalesce(p_target_grade,'')),trim(coalesce(p_target_class,'')),
    greatest(5,least(240,p_duration_minutes)),greatest(0.1,least(1000,p_max_score)),p_starts_at,p_ends_at,crypt(p_password,gen_salt('bf')))
  returning id into v_id;
  return v_id;
end $$;

create or replace function public.start_exam(
  p_password text, p_student_name text, p_student_grade text, p_student_class text
) returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_exam public.exams%rowtype; v_attempt public.exam_attempts%rowtype;
begin
  if length(trim(p_student_name)) < 3 then raise exception 'Informe o nome completo.'; end if;
  if trim(coalesce(p_student_grade,'')) = '' or trim(coalesce(p_student_class,'')) = '' then
    raise exception 'Informe a série e a turma.';
  end if;
  select * into v_exam from public.exams e
   where e.active and now() between e.starts_at and e.ends_at
     and e.password_hash = crypt(p_password,e.password_hash)
   order by e.created_at desc limit 1;
  if v_exam.id is null then raise exception 'Senha inválida ou prova fora do período de liberação.'; end if;
  if v_exam.target_grade <> '' and lower(trim(v_exam.target_grade)) <> lower(trim(p_student_grade)) then
    raise exception 'Esta prova não está liberada para a série informada.';
  end if;
  if v_exam.target_class <> '' and lower(trim(v_exam.target_class)) <> lower(trim(p_student_class)) then
    raise exception 'Esta prova não está liberada para a turma informada.';
  end if;
  if exists(select 1 from public.exam_attempts a where a.exam_id=v_exam.id
    and lower(trim(a.student_name))=lower(trim(p_student_name))
    and lower(trim(a.student_grade))=lower(trim(p_student_grade))
    and lower(trim(a.student_class))=lower(trim(p_student_class))) then
    raise exception 'Já existe uma tentativa registrada para este aluno.';
  end if;
  insert into public.exam_attempts(exam_id,student_name,student_grade,student_class)
  values(v_exam.id,trim(p_student_name),trim(p_student_grade),trim(p_student_class)) returning * into v_attempt;
  return jsonb_build_object(
    'attempt_token',v_attempt.attempt_token,'exam_id',v_exam.id,'title',v_exam.title,
    'activity_key',v_exam.activity_key,'duration_minutes',v_exam.duration_minutes,'max_score',v_exam.max_score,
    'deadline',least(v_exam.ends_at,v_attempt.started_at + make_interval(mins=>v_exam.duration_minutes))
  );
end $$;

create or replace function public.submit_exam(
  p_attempt_token uuid, p_score integer, p_passed_checks integer,
  p_total_checks integer, p_checks jsonb, p_topology jsonb
) returns jsonb
language plpgsql security definer set search_path = public
as $$
declare v_attempt public.exam_attempts%rowtype; v_exam public.exams%rowtype;
begin
  select * into v_attempt from public.exam_attempts where attempt_token=p_attempt_token for update;
  if v_attempt.id is null then raise exception 'Tentativa não encontrada.'; end if;
  if v_attempt.status <> 'in_progress' then raise exception 'Esta prova já foi entregue.'; end if;
  select * into v_exam from public.exams where id=v_attempt.exam_id;
  update public.exam_attempts set
    submitted_at=now(), status=case when now()>least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes)) then 'expired' else 'submitted' end,
    score=greatest(0,least(100,p_score)), passed_checks=p_passed_checks,
    total_checks=p_total_checks, checks=coalesce(p_checks,'[]'::jsonb), topology=coalesce(p_topology,'{}'::jsonb)
  where id=v_attempt.id;
  return jsonb_build_object('ok',true,'message','Prova entregue ao professor.');
end $$;

revoke all on public.exams, public.exam_attempts, public.teacher_profiles from anon;
grant usage on schema public to anon, authenticated;
grant execute on function public.start_exam(text,text,text,text) to anon, authenticated;
revoke all on function public.submit_exam(uuid,integer,integer,integer,jsonb,jsonb) from public,anon,authenticated;
grant execute on function public.submit_exam(uuid,integer,integer,integer,jsonb,jsonb) to service_role;
grant execute on function public.create_exam(text,text,text,text,text,integer,numeric,timestamptz,timestamptz) to authenticated;
revoke all on function public.teacher_access() from public,anon;
grant execute on function public.teacher_access() to authenticated;
grant select,update on public.teacher_profiles to authenticated;
grant select,update,delete on public.exams to authenticated;
grant select on public.exam_attempts to authenticated;

create or replace function public.exam_deadline(p_attempt_token uuid) returns jsonb
language plpgsql security definer set search_path=public
as $$
declare v_attempt public.exam_attempts%rowtype;v_exam public.exams%rowtype;
begin
  select * into v_attempt from public.exam_attempts where attempt_token=p_attempt_token;
  if v_attempt.id is null then raise exception 'Tentativa não encontrada.';end if;
  select * into v_exam from public.exams where id=v_attempt.exam_id;
  return jsonb_build_object('deadline',least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes)),'exam_ends_at',v_exam.ends_at);
end $$;
grant execute on function public.exam_deadline(uuid) to anon,authenticated;
-- Libera uma tentativa específica para o aluno entrar novamente com o nome correto.
create or replace function public.release_exam_attempt(p_attempt_id uuid)
returns jsonb
language plpgsql
security definer
set search_path=public
as $
declare
  v_student_name text;
  v_exam_title text;
  v_status text;
begin
  if auth.uid() is null or not exists(
    select 1 from public.teacher_profiles p where p.user_id=auth.uid()
  )then
    raise exception 'Conta não autorizada como professor.';
  end if;

  select a.student_name,e.title,a.status
  into v_student_name,v_exam_title,v_status
  from public.exam_attempts a
  join public.exams e on e.id=a.exam_id
  where a.id=p_attempt_id and e.teacher_id=auth.uid()
  for update of a;

  if v_student_name is null then
    raise exception 'Tentativa não encontrada ou sem autorização.';
  end if;

  delete from public.exam_attempts where id=p_attempt_id;

  return jsonb_build_object(
    'released',true,
    'student_name',v_student_name,
    'exam_title',v_exam_title,
    'previous_status',v_status
  );
end $;

revoke all on function public.release_exam_attempt(uuid) from public,anon;
grant execute on function public.release_exam_attempt(uuid) to authenticated;

-- Exclui todo o histórico de um aluno na escola e turma selecionadas.
create or replace function public.delete_student_records(
  p_student_name text,
  p_student_school text,
  p_student_class text
) returns jsonb
language plpgsql
security definer
set search_path=public
as $
declare
  v_name text:=trim(coalesce(p_student_name,''));
  v_school text:=lower(trim(coalesce(p_student_school,'')));
  v_class text:=upper(trim(coalesce(p_student_class,'')));
  v_deleted integer:=0;
begin
  if auth.uid() is null or not exists(
    select 1 from public.teacher_profiles p where p.user_id=auth.uid()
  )then
    raise exception 'Conta não autorizada como professor.';
  end if;
  if length(v_name)<3 then raise exception 'Nome do aluno inválido.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Escola inválida.';end if;
  if(v_school='narceu'and v_class<>'UNICA')or(v_school='joao_neiva'and v_class not in('01','02'))then raise exception 'Turma inválida para a escola.';end if;

  delete from public.exam_attempts a
  using public.exams e
  where a.exam_id=e.id
    and e.teacher_id=auth.uid()
    and lower(trim(a.student_name))=lower(v_name)
    and a.student_school=v_school
    and upper(trim(a.student_class))=v_class;
  get diagnostics v_deleted=row_count;

  if v_deleted=0 then raise exception 'Nenhum registro deste aluno foi encontrado.';end if;
  return jsonb_build_object('deleted',true,'student_name',v_name,'deleted_records',v_deleted);
end $;

revoke all on function public.delete_student_records(text,text,text) from public,anon;
grant execute on function public.delete_student_records(text,text,text) to authenticated;

-- Corrige a seleção quando a mesma senha foi liberada para turmas diferentes.
create or replace function public.start_exam(
  p_password text,p_student_name text,p_student_school text,p_student_grade text,p_student_class text
) returns jsonb
language plpgsql security definer set search_path=public,extensions as $
declare
  v_exam public.exams%rowtype;
  v_attempt public.exam_attempts%rowtype;
  v_school text:=lower(trim(coalesce(p_student_school,'')));
  v_grade text:=trim(coalesce(p_student_grade,''));
  v_class text:=upper(trim(coalesce(p_student_class,'')));
begin
  if length(trim(coalesce(p_student_name,'')))<3 then raise exception 'Informe o nome completo.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione a escola correta.';end if;
  if v_grade=''or v_class=''then raise exception 'Informe a série e a turma.';end if;
  if(v_school='narceu'and v_class<>'UNICA')or(v_school='joao_neiva'and v_class not in('01','02'))then raise exception 'Turma inválida para a escola selecionada.';end if;

  select * into v_exam from public.exams e
  where e.active
    and e.school_code=v_school
    and now()between e.starts_at and e.ends_at
    and e.password_hash=crypt(p_password,e.password_hash)
    and(coalesce(trim(e.target_grade),'')=''or lower(trim(e.target_grade))=lower(v_grade))
    and(upper(trim(coalesce(e.target_class,'')))in('','TODAS')or upper(trim(e.target_class))=v_class)
  order by e.created_at desc limit 1;

  if v_exam.id is null then
    if exists(
      select 1 from public.exams e
      where e.active and e.school_code=v_school and now()between e.starts_at and e.ends_at
        and e.password_hash=crypt(p_password,e.password_hash)
    )then
      raise exception 'A senha foi encontrada, mas não está liberada para a série ou turma informada. Confira a turma selecionada.';
    end if;
    raise exception 'Senha inválida, escola incorreta ou prova/atividade fora do período de liberação.';
  end if;

  if exists(
    select 1 from public.exam_attempts a
    where a.exam_id=v_exam.id
      and lower(trim(a.student_name))=lower(trim(p_student_name))
      and lower(trim(a.student_grade))=lower(v_grade)
      and upper(trim(a.student_class))=v_class
  )then
    raise exception 'Já existe uma tentativa registrada para este aluno. Peça ao professor para usar “Liberar aluno”.';
  end if;

  insert into public.exam_attempts(exam_id,student_name,student_school,student_grade,student_class)
  values(v_exam.id,trim(p_student_name),v_school,v_grade,v_class)returning * into v_attempt;
  return jsonb_build_object(
    'attempt_token',v_attempt.attempt_token,'exam_id',v_exam.id,'title',v_exam.title,
    'assessment_type',v_exam.assessment_type,'school_code',v_exam.school_code,'activity_key',v_exam.activity_key,
    'custom_prompt',v_exam.custom_prompt,'knowledge_level',v_exam.knowledge_level,
    'duration_minutes',v_exam.duration_minutes,'max_score',v_exam.max_score,
    'deadline',least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes))
  );
end $;

revoke all on function public.start_exam(text,text,text,text,text) from public;
grant execute on function public.start_exam(text,text,text,text,text) to anon,authenticated;

notify pgrst,'reload schema';
-- Permite ao professor substituir a senha de uma prova ou atividade própria.
-- A senha original nunca é recuperada; somente o hash é substituído.

create or replace function public.update_exam_password(p_exam_id uuid,p_new_password text)
returns boolean
language plpgsql security definer set search_path=public,extensions as $$
declare v_updated integer;
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())then
    raise exception 'Conta não autorizada como professor.';
  end if;
  if length(coalesce(p_new_password,''))<8 then
    raise exception 'A nova senha deve possuir pelo menos 8 caracteres.';
  end if;
  if length(p_new_password)>128 then
    raise exception 'A nova senha deve possuir no máximo 128 caracteres.';
  end if;

  update public.exams
  set password_hash=crypt(p_new_password,gen_salt('bf'))
  where id=p_exam_id and teacher_id=auth.uid();
  get diagnostics v_updated=row_count;

  if v_updated<>1 then
    raise exception 'Registro não encontrado ou sem permissão para alterar a senha.';
  end if;
  return true;
end $$;

revoke all on function public.update_exam_password(uuid,text) from public,anon;
grant execute on function public.update_exam_password(uuid,text) to authenticated;

notify pgrst,'reload schema';
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


-- Separa provas e resultados por escola.

alter table public.exams add column if not exists school_code text not null default 'narceu';
alter table public.exam_attempts add column if not exists student_school text not null default 'narceu';

update public.exam_attempts a set student_school=e.school_code
from public.exams e where e.id=a.exam_id and a.student_school is distinct from e.school_code;

do $$
begin
  if not exists(select 1 from pg_constraint where conname='exams_school_code_check' and conrelid='public.exams'::regclass) then
    alter table public.exams add constraint exams_school_code_check check(school_code in('narceu','joao_neiva'));
  end if;
  if not exists(select 1 from pg_constraint where conname='attempts_student_school_check' and conrelid='public.exam_attempts'::regclass) then
    alter table public.exam_attempts add constraint attempts_student_school_check check(student_school in('narceu','joao_neiva'));
  end if;
end $$;

create or replace function public.create_exam(
  p_title text,p_activity_key text,p_password text,p_school text,
  p_target_grade text,p_target_class text,p_duration_minutes integer,p_max_score numeric,
  p_starts_at timestamptz,p_ends_at timestamptz
) returns uuid
language plpgsql security definer set search_path=public,extensions as $$
declare v_id uuid;v_school text:=lower(trim(coalesce(p_school,'')));
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid()) then raise exception 'Conta não autorizada como professor.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione uma escola válida.';end if;
  if length(trim(coalesce(p_title,'')))<3 then raise exception 'Informe um título válido.';end if;
  if p_activity_key!~'^(lan|wifi|backbone|vlan|prova)[0-9]+$'then raise exception 'Atividade inválida.';end if;
  if length(trim(coalesce(p_password,'')))<8 then raise exception 'A senha deve possuir pelo menos 8 caracteres.';end if;
  if p_ends_at<=p_starts_at then raise exception 'O encerramento deve ser posterior ao início.';end if;
  insert into public.exams(teacher_id,title,activity_key,school_code,target_grade,target_class,duration_minutes,max_score,starts_at,ends_at,password_hash)
  values(auth.uid(),left(trim(p_title),160),p_activity_key,v_school,left(trim(coalesce(p_target_grade,'')),40),left(trim(coalesce(p_target_class,'')),40),greatest(5,least(240,p_duration_minutes)),greatest(0.1,least(1000,p_max_score)),p_starts_at,p_ends_at,crypt(p_password,gen_salt('bf')))
  returning id into v_id;return v_id;
end $$;

revoke all on function public.create_exam(text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) from public,anon;
grant execute on function public.create_exam(text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) to authenticated;

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
  if v_exam.id is null then raise exception 'Senha inválida, escola incorreta ou prova fora do período de liberação.';end if;
  if v_exam.target_grade<>''and lower(trim(v_exam.target_grade))<>lower(trim(p_student_grade))then raise exception 'Esta prova não está liberada para a série informada.';end if;
  if v_exam.target_class<>''and lower(trim(v_exam.target_class))<>lower(trim(p_student_class))then raise exception 'Esta prova não está liberada para a turma informada.';end if;
  if exists(select 1 from public.exam_attempts a where a.exam_id=v_exam.id and lower(trim(a.student_name))=lower(trim(p_student_name)) and lower(trim(a.student_grade))=lower(trim(p_student_grade)) and lower(trim(a.student_class))=lower(trim(p_student_class)))then raise exception 'Já existe uma tentativa registrada para este aluno.';end if;
  insert into public.exam_attempts(exam_id,student_name,student_school,student_grade,student_class)
  values(v_exam.id,trim(p_student_name),v_school,trim(p_student_grade),trim(p_student_class))returning * into v_attempt;
  return jsonb_build_object('attempt_token',v_attempt.attempt_token,'exam_id',v_exam.id,'title',v_exam.title,'school_code',v_exam.school_code,'activity_key',v_exam.activity_key,'duration_minutes',v_exam.duration_minutes,'max_score',v_exam.max_score,'deadline',least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes)));
end $$;

revoke all on function public.start_exam(text,text,text,text,text) from public;
grant execute on function public.start_exam(text,text,text,text,text) to anon,authenticated;
notify pgrst,'reload schema';

-- Narceu possui uma única turma de 3º ano; João Neiva possui 01 e 02.

update public.exams set target_class='UNICA' where school_code='narceu' and target_class<>'UNICA';
update public.exam_attempts set student_class='UNICA' where student_school='narceu' and student_class<>'UNICA';

do $$
begin
  if not exists(select 1 from pg_constraint where conname='exams_school_class_check' and conrelid='public.exams'::regclass)then
    alter table public.exams add constraint exams_school_class_check check(
      (school_code='narceu' and target_class='UNICA')or
      (school_code='joao_neiva' and target_class in('01','02'))
    );
  end if;
  if not exists(select 1 from pg_constraint where conname='attempts_school_class_check' and conrelid='public.exam_attempts'::regclass)then
    alter table public.exam_attempts add constraint attempts_school_class_check check(
      (student_school='narceu' and student_class='UNICA')or
      (student_school='joao_neiva' and student_class in('01','02'))
    );
  end if;
end $$;

notify pgrst,'reload schema';


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

-- Planejamento separado entre provas e atividades.
-- Separa o planejamento do professor entre provas e atividades.

alter table public.exams add column if not exists assessment_type text not null default 'prova';

do $$
begin
  if not exists(select 1 from pg_constraint where conname='exams_assessment_type_check' and conrelid='public.exams'::regclass)then
    alter table public.exams add constraint exams_assessment_type_check check(assessment_type in('prova','atividade'));
  end if;
end $$;

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
  if p_activity_key!~'^(lan|wifi|backbone|vlan|prova)[0-9]+$'then raise exception 'Atividade inválida.';end if;
  if length(trim(coalesce(p_password,'')))<8 then raise exception 'A senha deve possuir pelo menos 8 caracteres.';end if;
  if p_ends_at<=p_starts_at then raise exception 'O encerramento deve ser posterior ao início.';end if;
  insert into public.exams(teacher_id,title,activity_key,assessment_type,school_code,target_grade,target_class,duration_minutes,max_score,starts_at,ends_at,password_hash)
  values(auth.uid(),left(trim(p_title),160),p_activity_key,v_type,v_school,left(trim(coalesce(p_target_grade,'')),40),left(trim(coalesce(p_target_class,'')),40),greatest(5,least(240,p_duration_minutes)),greatest(0.1,least(1000,p_max_score)),p_starts_at,p_ends_at,crypt(p_password,gen_salt('bf')))
  returning id into v_id;return v_id;
end $$;

revoke all on function public.create_exam(text,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) from public,anon;
grant execute on function public.create_exam(text,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) to authenticated;

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
  if v_exam.target_class<>''and lower(trim(v_exam.target_class))<>lower(trim(p_student_class))then raise exception 'Este registro não está liberado para a turma informada.';end if;
  if exists(select 1 from public.exam_attempts a where a.exam_id=v_exam.id and lower(trim(a.student_name))=lower(trim(p_student_name)) and lower(trim(a.student_grade))=lower(trim(p_student_grade)) and lower(trim(a.student_class))=lower(trim(p_student_class)))then raise exception 'Já existe uma tentativa registrada para este aluno.';end if;
  insert into public.exam_attempts(exam_id,student_name,student_school,student_grade,student_class)
  values(v_exam.id,trim(p_student_name),v_school,trim(p_student_grade),trim(p_student_class))returning * into v_attempt;
  return jsonb_build_object('attempt_token',v_attempt.attempt_token,'exam_id',v_exam.id,'title',v_exam.title,'assessment_type',v_exam.assessment_type,'school_code',v_exam.school_code,'activity_key',v_exam.activity_key,'duration_minutes',v_exam.duration_minutes,'max_score',v_exam.max_score,'deadline',least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes)));
end $$;

revoke all on function public.start_exam(text,text,text,text,text) from public;
grant execute on function public.start_exam(text,text,text,text,text) to anon,authenticated;

notify pgrst,'reload schema';
-- Atividades inéditas compartilhadas, geradas pelo professor a partir de LAN e Wi-Fi.

alter table public.exams add column if not exists custom_prompt text;
alter table public.exams add column if not exists custom_rules jsonb;
alter table public.exams add column if not exists knowledge_level text;
alter table public.exams add column if not exists generation_key text;

create unique index if not exists exams_teacher_generation_key_unique
on public.exams(teacher_id,generation_key) where generation_key is not null;

do $$
begin
  if exists(select 1 from pg_constraint where conname='exams_knowledge_level_check' and conrelid='public.exams'::regclass)then
    alter table public.exams drop constraint exams_knowledge_level_check;
  end if;
  alter table public.exams add constraint exams_knowledge_level_check
  check(knowledge_level is null or knowledge_level in('basico','intermediario','avancado','profissional'));
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

-- Permite alterar o valor e sincronizá-lo com alunos que já iniciaram.
create or replace function public.update_exam_value(p_exam_id uuid,p_max_score numeric)
returns numeric
language plpgsql
security definer
set search_path=public
as $$
declare v_value numeric(8,2);
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())then raise exception 'Conta não autorizada como professor.';end if;
  if p_max_score is null or p_max_score<0.1 or p_max_score>1000 then raise exception 'O valor deve estar entre 0,1 e 1.000 pontos.';end if;
  update public.exams set max_score=p_max_score
  where id=p_exam_id and teacher_id=auth.uid()
  returning max_score into v_value;
  if v_value is null then raise exception 'Prova ou atividade não encontrada ou sem autorização.';end if;
  return v_value;
end $$;

revoke all on function public.update_exam_value(uuid,numeric) from public,anon;
grant execute on function public.update_exam_value(uuid,numeric) to authenticated;

create or replace function public.exam_deadline(p_attempt_token uuid)
returns jsonb
language plpgsql
security definer
set search_path=public
as $$
declare v_attempt public.exam_attempts%rowtype;v_exam public.exams%rowtype;
begin
  select * into v_attempt from public.exam_attempts where attempt_token=p_attempt_token;
  if v_attempt.id is null then raise exception 'Tentativa não encontrada.';end if;
  select * into v_exam from public.exams where id=v_attempt.exam_id;
  return jsonb_build_object(
    'deadline',least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes)),
    'exam_ends_at',v_exam.ends_at,
    'max_score',v_exam.max_score
  );
end $$;

revoke all on function public.exam_deadline(uuid) from public;
grant execute on function public.exam_deadline(uuid) to anon,authenticated;

notify pgrst,'reload schema';

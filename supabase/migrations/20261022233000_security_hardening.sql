-- AllanNet EDU: endurecimento de autenticação, autorização e entrega de provas.

create extension if not exists pgcrypto;

alter table public.exams
  add column if not exists max_score numeric(8,2) not null default 10
  check (max_score > 0 and max_score <= 1000);

-- Preserva o professor já cadastrado. Em uma instalação antiga sem perfil,
-- autoriza somente a primeira conta criada no projeto (a conta proprietária).
insert into public.teacher_profiles(user_id, display_name)
select u.id, coalesce(nullif(u.raw_user_meta_data->>'name',''),'Professor')
from auth.users u
where not exists (select 1 from public.teacher_profiles)
order by u.created_at asc
limit 1
on conflict (user_id) do nothing;

alter table public.teacher_profiles enable row level security;
alter table public.exams enable row level security;
alter table public.exam_attempts enable row level security;

drop policy if exists teacher_own_profile on public.teacher_profiles;
drop policy if exists teacher_reads_own_profile on public.teacher_profiles;
drop policy if exists teacher_updates_own_profile on public.teacher_profiles;
create policy teacher_reads_own_profile on public.teacher_profiles
for select to authenticated using (user_id = auth.uid());
create policy teacher_updates_own_profile on public.teacher_profiles
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists teacher_own_exams on public.exams;
create policy teacher_own_exams on public.exams
for all to authenticated
using (
  teacher_id = auth.uid()
  and exists (select 1 from public.teacher_profiles p where p.user_id = auth.uid())
)
with check (
  teacher_id = auth.uid()
  and exists (select 1 from public.teacher_profiles p where p.user_id = auth.uid())
);

drop policy if exists teacher_reads_attempts on public.exam_attempts;
create policy teacher_reads_attempts on public.exam_attempts
for select to authenticated using (
  exists (
    select 1 from public.exams e
    join public.teacher_profiles p on p.user_id=e.teacher_id
    where e.id=exam_id and e.teacher_id=auth.uid()
  )
);

revoke all on public.teacher_profiles from anon;
revoke insert, delete on public.teacher_profiles from authenticated;
grant select, update on public.teacher_profiles to authenticated;
revoke insert on public.exams from authenticated;
grant select, update, delete on public.exams to authenticated;
revoke all on public.exam_attempts from anon;
grant select on public.exam_attempts to authenticated;

create or replace function public.teacher_access()
returns boolean
language sql stable security definer set search_path=public
as $$
  select auth.uid() is not null
    and exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid());
$$;
revoke all on function public.teacher_access() from public, anon;
grant execute on function public.teacher_access() to authenticated;

drop function if exists public.create_exam(text,text,text,text,text,integer,timestamptz,timestamptz);
create or replace function public.create_exam(
  p_title text, p_activity_key text, p_password text,
  p_target_grade text, p_target_class text,
  p_duration_minutes integer, p_max_score numeric,
  p_starts_at timestamptz, p_ends_at timestamptz
) returns uuid
language plpgsql security definer set search_path=public,extensions
as $$
declare v_id uuid;
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid()) then
    raise exception 'Conta não autorizada como professor.';
  end if;
  if length(trim(coalesce(p_title,''))) < 3 then raise exception 'Informe um título válido.'; end if;
  if p_activity_key !~ '^(lan|wifi|backbone|vlan|prova)[0-9]+$' then raise exception 'Atividade inválida.'; end if;
  if length(trim(coalesce(p_password,''))) < 8 then raise exception 'A senha deve possuir pelo menos 8 caracteres.'; end if;
  if p_ends_at <= p_starts_at then raise exception 'O encerramento deve ser posterior ao início.'; end if;
  insert into public.exams(teacher_id,title,activity_key,target_grade,target_class,duration_minutes,max_score,starts_at,ends_at,password_hash)
  values(auth.uid(),left(trim(p_title),160),p_activity_key,left(trim(coalesce(p_target_grade,'')),40),left(trim(coalesce(p_target_class,'')),40),
    greatest(5,least(240,p_duration_minutes)),greatest(0.1,least(1000,p_max_score)),p_starts_at,p_ends_at,crypt(p_password,gen_salt('bf')))
  returning id into v_id;
  return v_id;
end $$;
revoke all on function public.create_exam(text,text,text,text,text,integer,numeric,timestamptz,timestamptz) from public, anon;
grant execute on function public.create_exam(text,text,text,text,text,integer,numeric,timestamptz,timestamptz) to authenticated;

-- O navegador não pode mais decidir a própria nota. Somente a Edge Function,
-- usando a função de serviço, pode finalizar uma tentativa.
revoke all on function public.submit_exam(uuid,integer,integer,integer,jsonb,jsonb) from public, anon, authenticated;
grant execute on function public.submit_exam(uuid,integer,integer,integer,jsonb,jsonb) to service_role;

create or replace function public.submit_exam(
  p_attempt_token uuid, p_score integer, p_passed_checks integer,
  p_total_checks integer, p_checks jsonb, p_topology jsonb
) returns jsonb
language plpgsql security definer set search_path=public
as $$
declare
  v_attempt public.exam_attempts%rowtype;
  v_exam public.exams%rowtype;
  v_deadline timestamptz;
  v_status text;
begin
  if current_user not in ('service_role','postgres') and auth.role() <> 'service_role' then
    raise exception 'Entrega deve ser corrigida pelo servidor.';
  end if;
  if pg_column_size(coalesce(p_topology,'{}'::jsonb)) > 1048576 then raise exception 'Topologia excede 1 MB.'; end if;
  if jsonb_typeof(p_topology) <> 'object' then raise exception 'Topologia inválida.'; end if;
  if jsonb_array_length(coalesce(p_topology->'devices','[]'::jsonb)) > 100
     or jsonb_array_length(coalesce(p_topology->'connections','[]'::jsonb)) > 300 then
    raise exception 'Topologia excede os limites permitidos.';
  end if;
  select * into v_attempt from public.exam_attempts where attempt_token=p_attempt_token for update;
  if v_attempt.id is null then raise exception 'Tentativa não encontrada.'; end if;
  if v_attempt.status <> 'in_progress' then raise exception 'Esta prova já foi entregue.'; end if;
  select * into v_exam from public.exams where id=v_attempt.exam_id;
  v_deadline:=least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes));
  v_status:=case when now()>v_deadline then 'expired' else 'submitted' end;
  update public.exam_attempts set
    submitted_at=now(),status=v_status,score=greatest(0,least(100,p_score)),
    passed_checks=greatest(0,least(p_passed_checks,p_total_checks)),total_checks=greatest(0,p_total_checks),
    checks=coalesce(p_checks,'[]'::jsonb),topology=p_topology
  where id=v_attempt.id;
  return jsonb_build_object('ok',true,'status',v_status,'message','Prova corrigida e entregue ao professor.');
end $$;
revoke all on function public.submit_exam(uuid,integer,integer,integer,jsonb,jsonb) from public, anon, authenticated;
grant execute on function public.submit_exam(uuid,integer,integer,integer,jsonb,jsonb) to service_role;

notify pgrst, 'reload schema';

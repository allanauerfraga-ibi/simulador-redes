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

drop policy if exists teacher_own_profile on public.teacher_profiles;
create policy teacher_own_profile on public.teacher_profiles
for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists teacher_own_exams on public.exams;
create policy teacher_own_exams on public.exams
for all to authenticated using (teacher_id = auth.uid()) with check (teacher_id = auth.uid());

drop policy if exists teacher_reads_attempts on public.exam_attempts;
create policy teacher_reads_attempts on public.exam_attempts
for select to authenticated using (
  exists (select 1 from public.exams e where e.id = exam_id and e.teacher_id = auth.uid())
);

create or replace function public.create_exam(
  p_title text, p_activity_key text, p_password text,
  p_target_grade text, p_target_class text,
  p_duration_minutes integer, p_starts_at timestamptz, p_ends_at timestamptz
) returns uuid
language plpgsql security definer set search_path = public, extensions
as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception 'Professor não autenticado.'; end if;
  if length(trim(p_password)) < 4 then raise exception 'A senha deve possuir pelo menos 4 caracteres.'; end if;
  if p_ends_at <= p_starts_at then raise exception 'O encerramento deve ser posterior ao início.'; end if;
  insert into public.teacher_profiles(user_id) values (auth.uid()) on conflict (user_id) do nothing;
  insert into public.exams(teacher_id,title,activity_key,target_grade,target_class,duration_minutes,starts_at,ends_at,password_hash)
  values(auth.uid(),trim(p_title),p_activity_key,trim(coalesce(p_target_grade,'')),trim(coalesce(p_target_class,'')),
    greatest(5,least(240,p_duration_minutes)),p_starts_at,p_ends_at,crypt(p_password,gen_salt('bf')))
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
    'activity_key',v_exam.activity_key,'duration_minutes',v_exam.duration_minutes,
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
    submitted_at=now(), status=case when now()>v_exam.ends_at then 'expired' else 'submitted' end,
    score=greatest(0,least(100,p_score)), passed_checks=p_passed_checks,
    total_checks=p_total_checks, checks=coalesce(p_checks,'[]'::jsonb), topology=coalesce(p_topology,'{}'::jsonb)
  where id=v_attempt.id;
  return jsonb_build_object('ok',true,'message','Prova entregue ao professor.');
end $$;

revoke all on public.exams, public.exam_attempts from anon;
grant usage on schema public to anon, authenticated;
grant execute on function public.start_exam(text,text,text,text) to anon, authenticated;
grant execute on function public.submit_exam(uuid,integer,integer,integer,jsonb,jsonb) to anon, authenticated;
grant execute on function public.create_exam(text,text,text,text,text,integer,timestamptz,timestamptz) to authenticated;
grant select,insert,update,delete on public.teacher_profiles, public.exams to authenticated;
grant select on public.exam_attempts to authenticated;

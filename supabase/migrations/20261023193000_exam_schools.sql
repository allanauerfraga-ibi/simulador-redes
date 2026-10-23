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

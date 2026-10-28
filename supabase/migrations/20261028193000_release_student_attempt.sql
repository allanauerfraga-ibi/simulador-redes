-- Permite ao professor proprietário liberar um aluno para entrar novamente.

create or replace function public.release_exam_attempt(p_attempt_id uuid)
returns jsonb
language plpgsql
security definer
set search_path=public
as $$
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
end $$;

revoke all on function public.release_exam_attempt(uuid) from public,anon;
grant execute on function public.release_exam_attempt(uuid) to authenticated;

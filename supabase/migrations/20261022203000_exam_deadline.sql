-- Permite que uma prova aberta reconheça prorrogações feitas pelo professor.
create or replace function public.exam_deadline(p_attempt_token uuid)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare v_attempt public.exam_attempts%rowtype; v_exam public.exams%rowtype;
begin
  select * into v_attempt from public.exam_attempts where attempt_token=p_attempt_token;
  if v_attempt.id is null then raise exception 'Tentativa não encontrada.'; end if;
  select * into v_exam from public.exams where id=v_attempt.exam_id;
  return jsonb_build_object(
    'deadline',least(v_exam.ends_at,v_attempt.started_at + make_interval(mins=>v_exam.duration_minutes)),
    'exam_ends_at',v_exam.ends_at
  );
end $$;

grant execute on function public.exam_deadline(uuid) to anon, authenticated;
notify pgrst, 'reload schema';

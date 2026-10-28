-- Permite alterar o valor da prova/atividade e sincroniza o novo valor com alunos em andamento.

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

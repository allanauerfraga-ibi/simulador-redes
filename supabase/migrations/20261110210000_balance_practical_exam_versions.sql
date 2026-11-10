-- Equaliza a segunda etapa dos lotes de 15 versões que ainda não foram iniciados.
-- Entregas e tentativas já abertas são preservadas para não alterar o histórico.
update public.exams as exam
set activity_key = 'provaCidade' || lpad(exam.version_number::text, 2, '0')
where exam.exam_set_id is not null
  and exam.stage_number = 2
  and exam.version_number between 1 and 15
  and exam.activity_key is distinct from ('provaCidade' || lpad(exam.version_number::text, 2, '0'))
  and not exists (
    select 1
    from public.exam_attempts as attempt
    where attempt.exam_id = exam.id
  );

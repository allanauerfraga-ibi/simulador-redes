-- Seleciona a prova/atividade pela senha, escola, série e turma antes de criar a tentativa.
-- Evita conflito quando a mesma senha é usada em liberações de turmas diferentes.

create or replace function public.start_exam(
  p_password text,p_student_name text,p_student_school text,p_student_grade text,p_student_class text
) returns jsonb
language plpgsql security definer set search_path=public,extensions as $$
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
end $$;

revoke all on function public.start_exam(text,text,text,text,text) from public;
grant execute on function public.start_exam(text,text,text,text,text) to anon,authenticated;

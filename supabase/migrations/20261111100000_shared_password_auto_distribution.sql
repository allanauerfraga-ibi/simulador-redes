-- Uma senha para as 15 provas/atividades e distribuição automática de versões.

create or replace function public.create_generated_activity_variant(
  p_title text,p_prompt text,p_rules jsonb,p_knowledge_level text,p_generation_key text,
  p_password text,p_school text,p_target_grade text,p_target_class text,
  p_duration_minutes integer,p_max_score numeric,p_starts_at timestamptz,p_ends_at timestamptz,
  p_version_number integer
) returns uuid
language plpgsql security definer set search_path=public,extensions as $$
declare v_id uuid;
begin
  if p_version_number not between 1 and 15 then raise exception 'Número da versão inválido.';end if;
  v_id:=public.create_generated_activity(
    p_title,p_prompt,p_rules,p_knowledge_level,p_generation_key,p_password,p_school,
    p_target_grade,p_target_class,p_duration_minutes,p_max_score,p_starts_at,p_ends_at
  );
  update public.exams set version_number=p_version_number where id=v_id and teacher_id=auth.uid();
  return v_id;
end $$;

revoke all on function public.create_generated_activity_variant(text,text,jsonb,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz,integer) from public,anon;
grant execute on function public.create_generated_activity_variant(text,text,jsonb,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz,integer) to authenticated;

create or replace function public.start_exam_team(
  p_password text,p_student_name text,p_student_name_2 text,p_is_pair boolean,
  p_student_school text,p_student_grade text,p_student_class text
) returns jsonb
language plpgsql security definer set search_path=public,extensions as $$
declare
  v_exam public.exams%rowtype;v_attempt public.exam_attempts%rowtype;
  v_school text:=lower(trim(coalesce(p_student_school,'')));v_grade text:=trim(coalesce(p_student_grade,''));
  v_class text:=upper(trim(coalesce(p_student_class,'')));v_name_1 text:=trim(coalesce(p_student_name,''));v_name_2 text:=trim(coalesce(p_student_name_2,''));
  v_password text:=trim(coalesce(p_password,''));v_time timestamptz;v_pool_size integer:=0;
begin
  if length(v_name_1)<3 then raise exception 'Informe o nome completo do primeiro aluno.';end if;
  if coalesce(p_is_pair,false)and length(v_name_2)<3 then raise exception 'Informe o nome completo do segundo aluno.';end if;
  if coalesce(p_is_pair,false)and lower(v_name_1)=lower(v_name_2)then raise exception 'Os dois alunos precisam ter nomes diferentes.';end if;
  if not coalesce(p_is_pair,false)then v_name_2:=null;end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione a escola correta.';end if;
  if v_grade=''or v_class=''then raise exception 'Informe a série e a turma.';end if;
  if(v_school='narceu'and v_class<>'UNICA')or(v_school='joao_neiva'and v_class not in('01','02'))then raise exception 'Turma inválida para a escola selecionada.';end if;

  select count(*)into v_pool_size from public.exams e
  where e.active and e.school_code=v_school and now()between e.starts_at and e.ends_at
    and e.password_hash=crypt(v_password,e.password_hash)
    and(coalesce(trim(e.target_grade),'')=''or lower(trim(e.target_grade))=lower(v_grade))
    and(upper(trim(coalesce(e.target_class,'')))in('','TODAS')or upper(trim(e.target_class))=v_class)
    and(e.stage_number is null or e.stage_number=1)and e.version_number is not null;

  if v_pool_size>1 then
    -- Se o aluno atualizar ou sair, retorna à mesma versão ainda em andamento.
    select e.* into v_exam from public.exams e join public.exam_attempts a on a.exam_id=e.id
    where e.active and e.school_code=v_school and now()between e.starts_at and e.ends_at
      and e.password_hash=crypt(v_password,e.password_hash)
      and(coalesce(trim(e.target_grade),'')=''or lower(trim(e.target_grade))=lower(v_grade))
      and(upper(trim(coalesce(e.target_class,'')))in('','TODAS')or upper(trim(e.target_class))=v_class)
      and(e.stage_number is null or e.stage_number=1)and e.version_number is not null and upper(trim(a.student_class))=v_class
      and(lower(trim(a.student_name))in(lower(v_name_1),lower(coalesce(v_name_2,'__sem_parceiro__')))
       or lower(trim(coalesce(a.student_name_2,'')))in(lower(v_name_1),lower(coalesce(v_name_2,'__sem_parceiro__'))))
    order by a.started_at desc limit 1;
    if v_exam.id is not null then
      select * into v_attempt from public.exam_attempts a where a.exam_id=v_exam.id
        and(lower(trim(a.student_name))in(lower(v_name_1),lower(coalesce(v_name_2,'__sem_parceiro__')))
         or lower(trim(coalesce(a.student_name_2,'')))in(lower(v_name_1),lower(coalesce(v_name_2,'__sem_parceiro__'))))
      order by a.started_at desc limit 1;
      if v_attempt.status<>'in_progress'then raise exception 'Esta atividade já foi entregue por este aluno ou dupla.';end if;
    else
      -- O bloqueio da linha evita que duas entradas simultâneas recebam a mesma versão.
      select e.* into v_exam from public.exams e
      where e.active and e.school_code=v_school and now()between e.starts_at and e.ends_at
        and e.password_hash=crypt(v_password,e.password_hash)
        and(coalesce(trim(e.target_grade),'')=''or lower(trim(e.target_grade))=lower(v_grade))
        and(upper(trim(coalesce(e.target_class,'')))in('','TODAS')or upper(trim(e.target_class))=v_class)
        and(e.stage_number is null or e.stage_number=1)and e.version_number is not null
        and not exists(select 1 from public.exam_attempts used where used.exam_id=e.id and upper(trim(used.student_class))=v_class)
      order by e.version_number,e.created_at desc limit 1 for update of e skip locked;
      if v_exam.id is null then raise exception 'As 15 versões já foram distribuídas. Procure o professor.';end if;
      insert into public.exam_attempts(exam_id,student_name,student_name_2,is_pair,student_school,student_grade,student_class)
      values(v_exam.id,v_name_1,v_name_2,coalesce(p_is_pair,false),v_school,v_grade,v_class)returning * into v_attempt;
    end if;
  else
    select * into v_exam from public.exams e
    where e.active and e.school_code=v_school and now()between e.starts_at and e.ends_at
      and e.password_hash=crypt(v_password,e.password_hash)
      and(coalesce(trim(e.target_grade),'')=''or lower(trim(e.target_grade))=lower(v_grade))
      and(upper(trim(coalesce(e.target_class,'')))in('','TODAS')or upper(trim(e.target_class))=v_class)
      and(e.stage_number is null or e.stage_number=1)
    order by e.created_at desc limit 1;
    if v_exam.id is not null then
      if exists(select 1 from public.exam_attempts a where a.exam_id=v_exam.id and upper(trim(a.student_class))=v_class
        and(lower(trim(a.student_name))in(lower(v_name_1),lower(coalesce(v_name_2,'__sem_parceiro__')))
         or lower(trim(coalesce(a.student_name_2,'')))in(lower(v_name_1),lower(coalesce(v_name_2,'__sem_parceiro__'))))
      )then raise exception 'Um dos alunos já possui tentativa nesta atividade. Peça ao professor para usar “Liberar aluno”.';end if;
      insert into public.exam_attempts(exam_id,student_name,student_name_2,is_pair,student_school,student_grade,student_class)
      values(v_exam.id,v_name_1,v_name_2,coalesce(p_is_pair,false),v_school,v_grade,v_class)returning * into v_attempt;
    end if;
  end if;

  if v_exam.id is null then
    select min(e.starts_at)into v_time from public.exams e where e.active and e.school_code=v_school and now()<e.starts_at and e.password_hash=crypt(v_password,e.password_hash)and(e.stage_number is null or e.stage_number=1);
    if v_time is not null then raise exception 'Esta atividade ainda não começou. Início: %.',to_char(timezone('America/Sao_Paulo',v_time),'DD/MM/YYYY HH24:MI');end if;
    select max(e.ends_at)into v_time from public.exams e where e.school_code=v_school and now()>e.ends_at and e.password_hash=crypt(v_password,e.password_hash)and(e.stage_number is null or e.stage_number=1);
    if v_time is not null then raise exception 'O prazo desta atividade terminou em %.',to_char(timezone('America/Sao_Paulo',v_time),'DD/MM/YYYY HH24:MI');end if;
    if exists(select 1 from public.exams e where not e.active and e.password_hash=crypt(v_password,e.password_hash)and(e.stage_number is null or e.stage_number=1))then raise exception 'Esta atividade foi encerrada pelo professor.';end if;
    if exists(select 1 from public.exams e where e.active and now()between e.starts_at and e.ends_at and e.password_hash=crypt(v_password,e.password_hash)and(e.stage_number is null or e.stage_number=1))then raise exception 'A senha foi encontrada, mas a atividade não está liberada para a escola ou turma selecionada.';end if;
    raise exception 'Senha não localizada. Confira a senha única informada pelo professor.';
  end if;

  return jsonb_build_object(
    'attempt_token',v_attempt.attempt_token,'exam_id',v_exam.id,'title',v_exam.title,
    'assessment_type',v_exam.assessment_type,'school_code',v_exam.school_code,'activity_key',v_exam.activity_key,
    'custom_prompt',v_exam.custom_prompt,'knowledge_level',v_exam.knowledge_level,
    'duration_minutes',v_exam.duration_minutes,'max_score',v_exam.max_score,
    'exam_set_id',v_exam.exam_set_id,'version_number',v_exam.version_number,'stage_number',v_exam.stage_number,'total_set_score',v_exam.total_set_score,
    'student_name_2',v_attempt.student_name_2,'is_pair',v_attempt.is_pair,
    'deadline',least(v_exam.ends_at,v_attempt.started_at+make_interval(mins=>v_exam.duration_minutes))
  );
end $$;

revoke all on function public.start_exam_team(text,text,text,boolean,text,text,text) from public;
grant execute on function public.start_exam_team(text,text,text,boolean,text,text,text) to anon,authenticated;

notify pgrst,'reload schema';

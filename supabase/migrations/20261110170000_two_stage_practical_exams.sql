-- Provas práticas em duas etapas, com duração única, nota somada e opção de dupla.

alter table public.exams add column if not exists exam_set_id uuid;
alter table public.exams add column if not exists version_number integer;
alter table public.exams add column if not exists stage_number integer;
alter table public.exams add column if not exists total_set_score numeric(8,2);

alter table public.exam_attempts add column if not exists student_name_2 text;
alter table public.exam_attempts add column if not exists is_pair boolean not null default false;

create unique index if not exists exams_set_stage_unique
on public.exams(exam_set_id,stage_number) where exam_set_id is not null;

do $$
begin
  if not exists(select 1 from pg_constraint where conname='exams_stage_number_check' and conrelid='public.exams'::regclass)then
    alter table public.exams add constraint exams_stage_number_check
    check(stage_number is null or stage_number in(1,2));
  end if;
  if not exists(select 1 from pg_constraint where conname='exams_version_number_check' and conrelid='public.exams'::regclass)then
    alter table public.exams add constraint exams_version_number_check
    check(version_number is null or version_number between 1 and 15);
  end if;
end $$;

create or replace function public.create_two_stage_exam(
  p_title text,p_activity_key_1 text,p_activity_key_2 text,p_password text,p_school text,
  p_target_grade text,p_target_class text,p_duration_minutes integer,p_total_score numeric,
  p_starts_at timestamptz,p_ends_at timestamptz,p_version_number integer
) returns jsonb
language plpgsql security definer set search_path=public,extensions as $$
declare
  v_set uuid:=gen_random_uuid();v_first uuid;v_second uuid;
  v_school text:=lower(trim(coalesce(p_school,'')));v_class text:=upper(trim(coalesce(p_target_class,'')));
  v_half numeric(8,2);v_other_half numeric(8,2);v_version text;
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())then raise exception 'Conta não autorizada como professor.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione uma escola válida.';end if;
  if(v_school='narceu'and v_class<>'UNICA')or(v_school='joao_neiva'and v_class not in('01','02'))then raise exception 'Selecione uma turma válida para a escola.';end if;
  if p_version_number not between 1 and 15 then raise exception 'Número da versão inválido.';end if;
  if p_activity_key_1!~'^(lan|wifi|backbone|vlan|city|prova)[0-9]+$'or p_activity_key_2!~'^(lan|wifi|backbone|vlan|city|prova)[0-9]+$'then raise exception 'Atividade inválida.';end if;
  if p_activity_key_1=p_activity_key_2 then raise exception 'As duas provas precisam ser diferentes.';end if;
  if length(trim(coalesce(p_title,'')))<3 then raise exception 'Informe um título válido.';end if;
  if length(trim(coalesce(p_password,'')))<8 then raise exception 'A senha deve possuir pelo menos 8 caracteres.';end if;
  if p_ends_at<=p_starts_at then raise exception 'O encerramento deve ser posterior ao início.';end if;
  if p_total_score is null or p_total_score<0.2 or p_total_score>1000 then raise exception 'O valor total deve estar entre 0,2 e 1.000 pontos.';end if;
  v_half:=round(p_total_score/2.0,2);v_other_half:=p_total_score-v_half;v_version:=lpad(p_version_number::text,2,'0');

  insert into public.exams(teacher_id,title,activity_key,assessment_type,school_code,target_grade,target_class,duration_minutes,max_score,starts_at,ends_at,password_hash,exam_set_id,version_number,stage_number,total_set_score)
  values(auth.uid(),left(trim(p_title)||' — Versão '||v_version||' — Prova 1',160),p_activity_key_1,'prova',v_school,left(trim(coalesce(p_target_grade,'')),40),v_class,greatest(5,least(240,p_duration_minutes)),v_half,p_starts_at,p_ends_at,crypt(p_password,gen_salt('bf')),v_set,p_version_number,1,p_total_score)
  returning id into v_first;

  insert into public.exams(teacher_id,title,activity_key,assessment_type,school_code,target_grade,target_class,duration_minutes,max_score,starts_at,ends_at,password_hash,exam_set_id,version_number,stage_number,total_set_score)
  values(auth.uid(),left(trim(p_title)||' — Versão '||v_version||' — Prova 2',160),p_activity_key_2,'prova',v_school,left(trim(coalesce(p_target_grade,'')),40),v_class,greatest(5,least(240,p_duration_minutes)),v_other_half,p_starts_at,p_ends_at,crypt(p_password,gen_salt('bf')),v_set,p_version_number,2,p_total_score)
  returning id into v_second;

  return jsonb_build_object('exam_set_id',v_set,'exam_1_id',v_first,'exam_2_id',v_second,'version_number',p_version_number,'score_1',v_half,'score_2',v_other_half,'total_score',p_total_score);
end $$;

revoke all on function public.create_two_stage_exam(text,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz,integer) from public,anon;
grant execute on function public.create_two_stage_exam(text,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz,integer) to authenticated;

create or replace function public.start_exam_team(
  p_password text,p_student_name text,p_student_name_2 text,p_is_pair boolean,
  p_student_school text,p_student_grade text,p_student_class text
) returns jsonb
language plpgsql security definer set search_path=public,extensions as $$
declare
  v_exam public.exams%rowtype;v_attempt public.exam_attempts%rowtype;
  v_school text:=lower(trim(coalesce(p_student_school,'')));v_grade text:=trim(coalesce(p_student_grade,''));
  v_class text:=upper(trim(coalesce(p_student_class,'')));v_name_1 text:=trim(coalesce(p_student_name,''));v_name_2 text:=trim(coalesce(p_student_name_2,''));
begin
  if length(v_name_1)<3 then raise exception 'Informe o nome completo do primeiro aluno.';end if;
  if coalesce(p_is_pair,false)and length(v_name_2)<3 then raise exception 'Informe o nome completo do segundo aluno.';end if;
  if coalesce(p_is_pair,false)and lower(v_name_1)=lower(v_name_2)then raise exception 'Os dois alunos precisam ter nomes diferentes.';end if;
  if not coalesce(p_is_pair,false)then v_name_2:=null;end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione a escola correta.';end if;
  if v_grade=''or v_class=''then raise exception 'Informe a série e a turma.';end if;
  if(v_school='narceu'and v_class<>'UNICA')or(v_school='joao_neiva'and v_class not in('01','02'))then raise exception 'Turma inválida para a escola selecionada.';end if;

  select * into v_exam from public.exams e
  where e.active and e.school_code=v_school and now()between e.starts_at and e.ends_at
    and e.password_hash=crypt(p_password,e.password_hash)
    and(coalesce(trim(e.target_grade),'')=''or lower(trim(e.target_grade))=lower(v_grade))
    and(upper(trim(coalesce(e.target_class,'')))in('','TODAS')or upper(trim(e.target_class))=v_class)
    and(e.stage_number is null or e.stage_number=1)
  order by e.created_at desc limit 1;

  if v_exam.id is null then raise exception 'Senha inválida, escola incorreta ou prova/atividade fora do período de liberação.';end if;
  if exists(
    select 1 from public.exam_attempts a where a.exam_id=v_exam.id and upper(trim(a.student_class))=v_class
      and(lower(trim(a.student_name))in(lower(v_name_1),lower(coalesce(v_name_2,'__sem_parceiro__')))
       or lower(trim(coalesce(a.student_name_2,'')))in(lower(v_name_1),lower(coalesce(v_name_2,'__sem_parceiro__'))))
  )then raise exception 'Um dos alunos já possui tentativa nesta versão. Peça ao professor para usar “Liberar aluno”.';end if;

  insert into public.exam_attempts(exam_id,student_name,student_name_2,is_pair,student_school,student_grade,student_class)
  values(v_exam.id,v_name_1,v_name_2,coalesce(p_is_pair,false),v_school,v_grade,v_class)returning * into v_attempt;
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

create or replace function public.start_exam_part_two(p_attempt_token uuid)
returns jsonb
language plpgsql security definer set search_path=public as $$
declare
  v_first_attempt public.exam_attempts%rowtype;v_first_exam public.exams%rowtype;
  v_second_exam public.exams%rowtype;v_second_attempt public.exam_attempts%rowtype;v_deadline timestamptz;
begin
  select * into v_first_attempt from public.exam_attempts where attempt_token=p_attempt_token for update;
  if v_first_attempt.id is null then raise exception 'Tentativa da Prova 1 não encontrada.';end if;
  select * into v_first_exam from public.exams where id=v_first_attempt.exam_id;
  if v_first_exam.exam_set_id is null or v_first_exam.stage_number<>1 then raise exception 'Esta avaliação não possui Prova 2 vinculada.';end if;
  if v_first_attempt.status not in('submitted','expired')then raise exception 'Entregue a Prova 1 antes de iniciar a Prova 2.';end if;
  select * into v_second_exam from public.exams where exam_set_id=v_first_exam.exam_set_id and stage_number=2 and active;
  if v_second_exam.id is null then raise exception 'A Prova 2 não está liberada.';end if;
  v_deadline:=least(v_first_exam.ends_at,v_second_exam.ends_at,v_first_attempt.started_at+make_interval(mins=>v_first_exam.duration_minutes));
  if now()>=v_deadline then raise exception 'O tempo total de prova foi encerrado.';end if;

  select * into v_second_attempt from public.exam_attempts where exam_id=v_second_exam.id
    and lower(trim(student_name))=lower(trim(v_first_attempt.student_name))
    and upper(trim(student_class))=upper(trim(v_first_attempt.student_class)) limit 1;
  if v_second_attempt.id is null then
    insert into public.exam_attempts(exam_id,student_name,student_name_2,is_pair,student_school,student_grade,student_class,started_at)
    values(v_second_exam.id,v_first_attempt.student_name,v_first_attempt.student_name_2,v_first_attempt.is_pair,v_first_attempt.student_school,v_first_attempt.student_grade,v_first_attempt.student_class,v_first_attempt.started_at)
    returning * into v_second_attempt;
  end if;
  return jsonb_build_object(
    'attempt_token',v_second_attempt.attempt_token,'exam_id',v_second_exam.id,'title',v_second_exam.title,
    'assessment_type',v_second_exam.assessment_type,'school_code',v_second_exam.school_code,'activity_key',v_second_exam.activity_key,
    'custom_prompt',v_second_exam.custom_prompt,'knowledge_level',v_second_exam.knowledge_level,
    'duration_minutes',v_second_exam.duration_minutes,'max_score',v_second_exam.max_score,
    'exam_set_id',v_second_exam.exam_set_id,'version_number',v_second_exam.version_number,'stage_number',v_second_exam.stage_number,'total_set_score',v_second_exam.total_set_score,
    'student_name_2',v_second_attempt.student_name_2,'is_pair',v_second_attempt.is_pair,'deadline',v_deadline
  );
end $$;

revoke all on function public.start_exam_part_two(uuid) from public;
grant execute on function public.start_exam_part_two(uuid) to anon,authenticated;

notify pgrst,'reload schema';

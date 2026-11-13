-- Atividade objetiva de revisão geral com correção automática no servidor.

create table if not exists public.objective_quiz_attempts(
  id uuid primary key default gen_random_uuid(),
  student_name text not null,
  student_school text not null,
  student_class text not null,
  answers jsonb not null,
  correct_answers integer not null,
  total_questions integer not null default 15,
  score numeric(5,2) not null,
  submitted_at timestamptz not null default now(),
  constraint objective_quiz_school_check check(student_school in('narceu','joao_neiva')),
  constraint objective_quiz_class_check check(
    (student_school='narceu' and student_class='UNICA')or
    (student_school='joao_neiva' and student_class in('01','02'))
  ),
  constraint objective_quiz_answers_check check(jsonb_typeof(answers)='array' and jsonb_array_length(answers)=15),
  constraint objective_quiz_score_check check(score between 0 and 100),
  constraint objective_quiz_correct_check check(correct_answers between 0 and total_questions)
);

alter table public.objective_quiz_attempts enable row level security;
drop policy if exists objective_quiz_teacher_read on public.objective_quiz_attempts;
create policy objective_quiz_teacher_read on public.objective_quiz_attempts
for select to authenticated using(
  exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())
);

revoke all on table public.objective_quiz_attempts from public,anon,authenticated;
grant select on table public.objective_quiz_attempts to authenticated;

create or replace function public.submit_objective_activity(
  p_student_name text,p_student_school text,p_student_class text,p_answers jsonb
) returns jsonb
language plpgsql security definer set search_path=public as $$
declare
  v_name text:=trim(coalesce(p_student_name,''));
  v_school text:=lower(trim(coalesce(p_student_school,'')));
  v_class text:=upper(trim(coalesce(p_student_class,'')));
  v_key integer[]:=array[1,0,2,0,2,1,0,1,0,0,0,2,1,3,4];
  v_correct integer:=0;v_score numeric(5,2);v_id uuid;v_submitted_at timestamptz;
begin
  if length(v_name)<3 or length(v_name)>120 then raise exception 'Informe o nome completo do aluno.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione uma escola válida.';end if;
  if(v_school='narceu'and v_class<>'UNICA')or(v_school='joao_neiva'and v_class not in('01','02'))then raise exception 'Selecione uma turma válida para a escola.';end if;
  if jsonb_typeof(p_answers)<>'array'or jsonb_array_length(p_answers)<>15 then raise exception 'Responda todas as 15 questões.';end if;
  if exists(select 1 from jsonb_array_elements(p_answers)a where jsonb_typeof(a)<>'number'or(a#>>'{}')::integer not between 0 and 4)then raise exception 'Uma ou mais respostas são inválidas.';end if;

  select count(*) into v_correct
  from jsonb_array_elements_text(p_answers)with ordinality a(value,position)
  where a.value::integer=v_key[a.position::integer];
  v_score:=round(v_correct::numeric/15*100,2);

  insert into public.objective_quiz_attempts(student_name,student_school,student_class,answers,correct_answers,total_questions,score)
  values(v_name,v_school,v_class,p_answers,v_correct,15,v_score)
  returning id,submitted_at into v_id,v_submitted_at;

  return jsonb_build_object('ok',true,'attempt_id',v_id,'correct_answers',v_correct,'total_questions',15,'score',v_score,'submitted_at',v_submitted_at);
end $$;

revoke all on function public.submit_objective_activity(text,text,text,jsonb) from public;
grant execute on function public.submit_objective_activity(text,text,text,jsonb) to anon,authenticated;
notify pgrst,'reload schema';

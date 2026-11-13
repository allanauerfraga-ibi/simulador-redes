-- Registra saídas de tela e permite entrega automática da atividade objetiva.

alter table public.objective_quiz_attempts
  add column if not exists security_violations integer not null default 0,
  add column if not exists security_status text not null default 'normal',
  add column if not exists security_reason text;

do $$
begin
  if not exists(select 1 from pg_constraint where conname='objective_quiz_security_violations_check' and conrelid='public.objective_quiz_attempts'::regclass)then
    alter table public.objective_quiz_attempts add constraint objective_quiz_security_violations_check check(security_violations between 0 and 20);
  end if;
  if not exists(select 1 from pg_constraint where conname='objective_quiz_security_status_check' and conrelid='public.objective_quiz_attempts'::regclass)then
    alter table public.objective_quiz_attempts add constraint objective_quiz_security_status_check check(security_status in('normal','attention'));
  end if;
end $$;

create or replace function public.submit_objective_activity_secure(
  p_student_name text,p_student_school text,p_student_class text,p_answers jsonb,
  p_security_violations integer,p_security_reason text
) returns jsonb
language plpgsql security definer set search_path=public as $$
declare
  v_name text:=trim(coalesce(p_student_name,''));
  v_school text:=lower(trim(coalesce(p_student_school,'')));
  v_class text:=upper(trim(coalesce(p_student_class,'')));
  v_violations integer:=greatest(0,least(20,coalesce(p_security_violations,0)));
  v_key integer[]:=array[1,0,2,0,2,1,0,1,0,0,0,2,1,3,4];
  v_correct integer:=0;v_score numeric(5,2);v_id uuid;v_submitted_at timestamptz;
begin
  if length(v_name)<3 or length(v_name)>120 then raise exception 'Informe o nome completo do aluno.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione uma escola válida.';end if;
  if(v_school='narceu'and v_class<>'UNICA')or(v_school='joao_neiva'and v_class not in('01','02'))then raise exception 'Selecione uma turma válida para a escola.';end if;
  if jsonb_typeof(p_answers)<>'array'or jsonb_array_length(p_answers)<>15 then raise exception 'A atividade deve possuir 15 respostas.';end if;
  if exists(select 1 from jsonb_array_elements(p_answers)a where jsonb_typeof(a)<>'number'or(a#>>'{}')::integer not between -1 and 4)then raise exception 'Uma ou mais respostas são inválidas.';end if;

  select count(*) into v_correct
  from jsonb_array_elements_text(p_answers)with ordinality a(value,position)
  where a.value::integer=v_key[a.position::integer];
  v_score:=round(v_correct::numeric/15*100,2);

  insert into public.objective_quiz_attempts(
    student_name,student_school,student_class,answers,correct_answers,total_questions,score,
    security_violations,security_status,security_reason
  )values(
    v_name,v_school,v_class,p_answers,v_correct,15,v_score,v_violations,
    case when v_violations>0 then'attention'else'normal'end,
    nullif(left(trim(coalesce(p_security_reason,'')),200),'')
  )returning id,submitted_at into v_id,v_submitted_at;

  return jsonb_build_object(
    'ok',true,'attempt_id',v_id,'correct_answers',v_correct,'total_questions',15,
    'score',v_score,'submitted_at',v_submitted_at,'security_violations',v_violations,
    'security_status',case when v_violations>0 then'attention'else'normal'end
  );
end $$;

revoke all on function public.submit_objective_activity_secure(text,text,text,jsonb,integer,text) from public;
grant execute on function public.submit_objective_activity_secure(text,text,text,jsonb,integer,text) to anon,authenticated;
notify pgrst,'reload schema';

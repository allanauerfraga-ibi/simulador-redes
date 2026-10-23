-- Narceu possui uma única turma de 3º ano; João Neiva possui 01 e 02.

update public.exams set target_class='UNICA' where school_code='narceu' and target_class<>'UNICA';
update public.exam_attempts set student_class='UNICA' where student_school='narceu' and student_class<>'UNICA';

do $$
begin
  if not exists(select 1 from pg_constraint where conname='exams_school_class_check' and conrelid='public.exams'::regclass)then
    alter table public.exams add constraint exams_school_class_check check(
      (school_code='narceu' and target_class='UNICA')or
      (school_code='joao_neiva' and target_class in('01','02'))
    );
  end if;
  if not exists(select 1 from pg_constraint where conname='attempts_school_class_check' and conrelid='public.exam_attempts'::regclass)then
    alter table public.exam_attempts add constraint attempts_school_class_check check(
      (student_school='narceu' and student_class='UNICA')or
      (student_school='joao_neiva' and student_class in('01','02'))
    );
  end if;
end $$;

notify pgrst,'reload schema';

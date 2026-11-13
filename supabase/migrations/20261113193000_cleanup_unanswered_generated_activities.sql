-- Remove atividades inéditas automáticas sem nenhuma participação após 36 horas.
-- Qualquer tentativa de aluno preserva a atividade e todo o seu histórico.

create or replace function public._cleanup_unanswered_generated_activities()
returns integer
language plpgsql
security definer
set search_path=public
as $$
declare
  v_deleted integer:=0;
begin
  with removed as(
    delete from public.exams e
    where e.activity_key='gerada'
      and e.created_at<=now()-interval '36 hours'
      and not exists(
        select 1 from public.exam_attempts a where a.exam_id=e.id
      )
    returning e.id
  )
  select count(*)::integer into v_deleted from removed;

  return v_deleted;
end $$;

revoke all on function public._cleanup_unanswered_generated_activities() from public,anon,authenticated;

create or replace function public.cleanup_unanswered_generated_activities()
returns integer
language plpgsql
security definer
set search_path=public
as $$
begin
  if auth.uid() is null or not exists(
    select 1 from public.teacher_profiles p where p.user_id=auth.uid()
  )then
    raise exception 'Conta não autorizada como professor.';
  end if;

  return public._cleanup_unanswered_generated_activities();
end $$;

revoke all on function public.cleanup_unanswered_generated_activities() from public,anon;
grant execute on function public.cleanup_unanswered_generated_activities() to authenticated;

comment on function public.cleanup_unanswered_generated_activities() is
'Exclui atividades automáticas criadas há mais de 36 horas que não possuem nenhuma tentativa de aluno.';

-- Agenda a verificação de hora em hora no próprio Supabase. A chamada feita pelo
-- painel do professor permanece como redundância caso o agendador esteja indisponível.
do $$
begin
  if not exists(select 1 from pg_extension where extname='pg_cron')then
    begin
      execute 'create extension pg_cron with schema pg_catalog';
    exception
      when insufficient_privilege or feature_not_supported or object_not_in_prerequisite_state then
        raise notice 'pg_cron indisponível; a limpeza será executada pelo painel do professor.';
    end;
  end if;
end $$;

do $$
declare
  v_job_id bigint;
begin
  if to_regclass('cron.job') is null then
    raise notice 'Agendador pg_cron não encontrado; usando a limpeza pelo painel do professor.';
    return;
  end if;

  execute 'select jobid from cron.job where jobname=$1 limit 1'
    into v_job_id using 'allannet-cleanup-generated-activities';
  if v_job_id is not null then
    execute 'select cron.unschedule($1)' using v_job_id;
  end if;

  execute 'select cron.schedule($1,$2,$3)'
    using
      'allannet-cleanup-generated-activities',
      '17 * * * *',
      'select public._cleanup_unanswered_generated_activities();';
exception
  when insufficient_privilege or undefined_function or undefined_table or invalid_schema_name then
    raise notice 'Não foi possível agendar o pg_cron; a limpeza será executada pelo painel do professor.';
end $$;

select pg_notify('pgrst','reload schema');

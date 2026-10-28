-- Exclui todo o histórico de um aluno na escola e turma selecionadas.

create or replace function public.delete_student_records(
  p_student_name text,
  p_student_school text,
  p_student_class text
) returns jsonb
language plpgsql
security definer
set search_path=public
as $$
declare
  v_name text:=trim(coalesce(p_student_name,''));
  v_school text:=lower(trim(coalesce(p_student_school,'')));
  v_class text:=upper(trim(coalesce(p_student_class,'')));
  v_deleted integer:=0;
begin
  if auth.uid() is null or not exists(
    select 1 from public.teacher_profiles p where p.user_id=auth.uid()
  )then
    raise exception 'Conta não autorizada como professor.';
  end if;
  if length(v_name)<3 then raise exception 'Nome do aluno inválido.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Escola inválida.';end if;
  if(v_school='narceu'and v_class<>'UNICA')or(v_school='joao_neiva'and v_class not in('01','02'))then raise exception 'Turma inválida para a escola.';end if;

  delete from public.exam_attempts a
  using public.exams e
  where a.exam_id=e.id
    and e.teacher_id=auth.uid()
    and lower(trim(a.student_name))=lower(v_name)
    and a.student_school=v_school
    and upper(trim(a.student_class))=v_class;
  get diagnostics v_deleted=row_count;

  if v_deleted=0 then raise exception 'Nenhum registro deste aluno foi encontrado.';end if;
  return jsonb_build_object('deleted',true,'student_name',v_name,'deleted_records',v_deleted);
end $$;

revoke all on function public.delete_student_records(text,text,text) from public,anon;
grant execute on function public.delete_student_records(text,text,text) to authenticated;

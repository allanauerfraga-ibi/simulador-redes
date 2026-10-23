-- Permite ao professor substituir a senha de uma prova ou atividade própria.
-- A senha original nunca é recuperada; somente o hash é substituído.

create or replace function public.update_exam_password(p_exam_id uuid,p_new_password text)
returns boolean
language plpgsql security definer set search_path=public,extensions as $$
declare v_updated integer;
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())then
    raise exception 'Conta não autorizada como professor.';
  end if;
  if length(coalesce(p_new_password,''))<8 then
    raise exception 'A nova senha deve possuir pelo menos 8 caracteres.';
  end if;
  if length(p_new_password)>128 then
    raise exception 'A nova senha deve possuir no máximo 128 caracteres.';
  end if;

  update public.exams
  set password_hash=crypt(p_new_password,gen_salt('bf'))
  where id=p_exam_id and teacher_id=auth.uid();
  get diagnostics v_updated=row_count;

  if v_updated<>1 then
    raise exception 'Registro não encontrado ou sem permissão para alterar a senha.';
  end if;
  return true;
end $$;

revoke all on function public.update_exam_password(uuid,text) from public,anon;
grant execute on function public.update_exam_password(uuid,text) to authenticated;

notify pgrst,'reload schema';

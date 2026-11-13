-- Autoriza com segurança os critérios usados pelo gerador da Sala Cidade.

create or replace function public.create_generated_activity(
  p_title text,p_prompt text,p_rules jsonb,p_knowledge_level text,p_generation_key text,
  p_password text,p_school text,p_target_grade text,p_target_class text,
  p_duration_minutes integer,p_max_score numeric,p_starts_at timestamptz,p_ends_at timestamptz
) returns uuid
language plpgsql security definer set search_path=public,extensions as $$
declare
  v_id uuid;v_school text:=lower(trim(coalesce(p_school,'')));
  v_level text:=lower(trim(coalesce(p_knowledge_level,'')));v_class text:=upper(trim(coalesce(p_target_class,'')));
  v_city boolean:=coalesce((p_rules->>'cityScene')::boolean,false);
  allowed_keys text[]:=array[
    'pc','phone','switch','wirelessRouter','server','firewall','notebook','desktopComputer',
    'pcWire','wifi','sameSubnet','switchesLinked','routerSwitch','minSubnets','gigabit','reach',
    'minAssigned','minVlans','minBackbones','backboneSpeed',
    'cityScene','cellTower','house','person','dataCenter','satellite','allCityClientsConnected',
    'minServingTowers','orbitalTowers','orbitalDataCenters'
  ];
begin
  if auth.uid() is null or not exists(select 1 from public.teacher_profiles p where p.user_id=auth.uid())then raise exception 'Conta não autorizada como professor.';end if;
  if v_school not in('narceu','joao_neiva')then raise exception 'Selecione uma escola válida.';end if;
  if(v_school='narceu'and v_class not in('UNICA','TODAS'))or(v_school='joao_neiva'and v_class not in('01','02','TODAS'))then raise exception 'Selecione uma turma válida para a escola.';end if;
  if v_level not in('basico','intermediario','avancado','profissional')then raise exception 'Selecione o nível básico, intermediário, avançado ou profissional.';end if;
  if length(trim(coalesce(p_title,'')))<3 or length(trim(coalesce(p_prompt,'')))<40 then raise exception 'A atividade gerada está incompleta.';end if;
  if jsonb_typeof(p_rules)<>'object' or pg_column_size(p_rules)>4096 then raise exception 'Critérios automáticos inválidos.';end if;
  if exists(select 1 from jsonb_object_keys(p_rules)k where not(k=any(allowed_keys)))then raise exception 'A atividade contém um critério não autorizado.';end if;
  if length(trim(coalesce(p_generation_key,'')))<8 or length(p_generation_key)>80 then raise exception 'Identificador da atividade inválido.';end if;
  if length(trim(coalesce(p_password,'')))<8 then raise exception 'A senha deve possuir pelo menos 8 caracteres.';end if;
  if p_ends_at<=p_starts_at then raise exception 'O encerramento deve ser posterior ao início.';end if;

  if v_city then
    if coalesce((p_rules->>'cellTower')::integer,0) not between 1 and 6
       or coalesce((p_rules->>'house')::integer,0) not between 1 and 20
       or coalesce((p_rules->>'person')::integer,0) not between 0 and 30
       or coalesce((p_rules->>'dataCenter')::integer,0) not between 0 and 4
       or coalesce((p_rules->>'satellite')::integer,0) not between 0 and 4 then
      raise exception 'Quantidade de elementos da cidade fora dos limites didáticos.';
    end if;
    if (p_rules?'minServingTowers' and (p_rules->>'minServingTowers')::integer not between 1 and 6)
       or (p_rules?'orbitalTowers' and (p_rules->>'orbitalTowers')::integer not between 1 and 6)
       or (p_rules?'orbitalDataCenters' and (p_rules->>'orbitalDataCenters')::integer not between 1 and 4) then
      raise exception 'Critérios de cobertura da cidade fora dos limites didáticos.';
    end if;
  else
    if coalesce((p_rules->>'pc')::integer,0) not between 2 and 12
       or coalesce((p_rules->>'phone')::integer,0) not between 1 and 12
       or coalesce((p_rules->>'switch')::integer,0) not between 1 and 6
       or coalesce((p_rules->>'wirelessRouter')::integer,0) not between 1 and 4
       or coalesce((p_rules->>'server')::integer,0) not between 0 and 4
       or coalesce((p_rules->>'firewall')::integer,0) not between 0 and 2 then
      raise exception 'Quantidade de equipamentos fora dos limites didáticos.';
    end if;
    if (p_rules?'minSubnets' and (p_rules->>'minSubnets')::integer not between 1 and 8)
       or (p_rules?'minAssigned' and (p_rules->>'minAssigned')::integer not between 2 and 30)
       or (p_rules?'minVlans' and (p_rules->>'minVlans')::integer not between 2 and 8)
       or (p_rules?'minBackbones' and (p_rules->>'minBackbones')::integer not between 1 and 10)
       or (p_rules?'backboneSpeed' and (p_rules->>'backboneSpeed')::integer not between 1000 and 100000) then
      raise exception 'Critérios profissionais fora dos limites didáticos.';
    end if;
  end if;

  insert into public.exams(
    teacher_id,title,activity_key,assessment_type,school_code,target_grade,target_class,
    duration_minutes,max_score,starts_at,ends_at,password_hash,custom_prompt,custom_rules,knowledge_level,generation_key
  )values(
    auth.uid(),left(trim(p_title),160),'gerada','atividade',v_school,left(trim(coalesce(p_target_grade,'')),40),v_class,
    greatest(5,least(240,p_duration_minutes)),greatest(0.1,least(1000,p_max_score)),p_starts_at,p_ends_at,
    crypt(p_password,gen_salt('bf')),left(trim(p_prompt),4000),p_rules,v_level,left(trim(p_generation_key),80)
  )returning id into v_id;
  return v_id;
exception when unique_violation then
  raise exception 'Esta proposta já foi utilizada. Gere uma nova atividade.';
end $$;

revoke all on function public.create_generated_activity(text,text,jsonb,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) from public,anon;
grant execute on function public.create_generated_activity(text,text,jsonb,text,text,text,text,text,text,integer,numeric,timestamptz,timestamptz) to authenticated;
notify pgrst,'reload schema';

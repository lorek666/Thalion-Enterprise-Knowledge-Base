\set ON_ERROR_STOP on

do $$
declare n int; d jsonb;
begin
  select count(*) into n from compile_output where output_id = 1 and status = 'accepted';
  if n <> 1 then raise exception 'output 1 was not accepted'; end if;

  select count(*) into n from wiki_revision where revision_id = 11 and status = 'pending';
  if n <> 1 then raise exception 'candidate 11 is not pending'; end if;

  select count(*) into n from wiki where wiki_id = 1 and published_revision_id = 10;
  if n <> 1 then raise exception 'published revision changed without approval'; end if;

  d := compile_diff(20,21,'{"amount":["unit","valid_from"],"approver":["citation"]}'::jsonb);
  if (d->>'publishable')::boolean is distinct from false
     or (d->>'citation_changed')::int is distinct from 0 then
    raise exception 'identical citations on new statement IDs should not create a diff: %', d;
  end if;
end $$;

do $$
declare diff jsonb;
begin
  update wiki_citation set source_version_id = 3
  where revision_id = 21 and statement_id = 401;
  diff := compile_diff(20,21);
  if (diff->>'publishable')::boolean is distinct from true
     or (diff->>'added')::int is distinct from 0
     or (diff->>'removed')::int is distinct from 0
     or (diff->>'changed')::int is distinct from 0
     or (diff->>'citation_changed')::int is distinct from 1
     or not coalesce(diff->'citation_changed_detail' @>
       '[{"statement_id":401,"old_citations":[{"source_version_id":2,"passage_id":1}],
         "new_citations":[{"source_version_id":3,"passage_id":1}]}]'::jsonb, false) then
    raise exception 'source version alone should be a reviewable citation change: %', diff;
  end if;
end $$;

do $$
declare diff jsonb;
begin
  update wiki_citation set source_version_id = 2, passage_id = 9
  where revision_id = 21 and statement_id = 401;
  diff := compile_diff(20,21);
  if (diff->>'publishable')::boolean is distinct from true
     or (diff->>'changed')::int is distinct from 0
     or (diff->>'citation_changed')::int is distinct from 1
     or not coalesce(diff->'citation_changed_detail' @>
       '[{"statement_id":401,"old_citations":[{"source_version_id":2,"passage_id":1}],
         "new_citations":[{"source_version_id":2,"passage_id":9}]}]'::jsonb, false) then
    raise exception 'passage alone should be a reviewable citation change: %', diff;
  end if;

  insert into compile_output(output_id,run_id,wiki_id,base_revision_id,candidate_revision_id,diff)
  overriding system value values (2,1,2,20,21,diff);
  perform compile_accept(2);
  if not exists (
    select 1 from wiki w join wiki_revision r on r.wiki_id = w.wiki_id
    where w.wiki_id = 2 and w.published_revision_id = 20
      and r.revision_id = 21 and r.status = 'pending'
  ) then
    raise exception 'citation-only candidate should be pending without replacing the published revision';
  end if;
end $$;

do $$
declare original_revision compile_template_rev; diff jsonb;
begin
  if to_regprocedure('compile_activate(bigint,bigint,text)') is null then
    raise exception 'no activation path for a previous template revision without copying its checksum';
  end if;
  select * into strict original_revision from compile_template_rev where template_rev_id = 1;
  perform compile_activate(1,9002,'首次启用');
  perform compile_activate(2,9002,'启用第二版');
  perform compile_activate(1,9003,'恢复第一版');

  if not exists (
    select 1 from v_compile_template_active where template_id = 1 and template_rev_id = 1
  ) or (select array_agg(template_rev_id order by activation_id) from compile_template_activation)
       is distinct from array[1,2,1]::bigint[]
    or not exists (
      select 1 from compile_template_activation
      where template_rev_id = 1 and activated_by = 9003 and reason = '恢复第一版'
    ) then
    raise exception 'template reactivation did not preserve the activation history';
  end if;

  if (select count(*) from compile_template_rev where template_id = 1) <> 2
     or (select tr from compile_template_rev tr where template_rev_id = 1) is distinct from original_revision
     or (select published_revision_id from wiki where wiki_id = 1) is distinct from 10
     or (select published_revision_id from wiki where wiki_id = 2) is distinct from 20 then
    raise exception 'template reactivation copied a revision, mutated it, or rolled back a published page';
  end if;
  select compile_diff(10,12,tr.required_fields) into strict diff
  from v_compile_template_active a join compile_template_rev tr using (template_rev_id)
  where a.template_id = 1 and tr.revision_no::text = (
    select compile_template_rev from wiki_revision where revision_id = 12
  );
  if (diff->>'publishable')::boolean is distinct from false
     or (diff->>'citation_changed')::int is distinct from 0 then
    raise exception 'a replay using the restored rules and same evidence must be skipped: %', diff;
  end if;
  begin
    update compile_template_rev set rules = '{}' where template_rev_id = 1;
    raise exception 'published revision content was mutable';
  exception when object_not_in_prerequisite_state then null;
  end;
end $$;

select 'compile assertions ok' as result;

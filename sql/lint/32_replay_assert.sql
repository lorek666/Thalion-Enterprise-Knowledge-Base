\set ON_ERROR_STOP on

begin;
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source)
values (206,6,2,'fixture publication','# fixture publication','published','user');

select lint_emit(p_run=>:run_id, p_space=>:space_id, p_key=>'fixture-repeat',
                 p_rule=>'PAGE_ORPHAN', p_sev=>'high', p_wiki=>6, p_rev=>106);
select lint_emit(p_run=>:run_id, p_space=>:space_id, p_key=>'fixture-repeat',
                 p_rule=>'PAGE_ORPHAN', p_sev=>'high', p_wiki=>6, p_rev=>206);

do $$
begin
  if not exists (
    select 1 from lint_finding
    where dedupe_key='fixture-repeat' and revision_id=106 and occurrence_count=2
  ) then
    raise exception 'repeated finding must preserve the first observed revision';
  end if;

  if (select array_agg(related.revision_id order by related.revision_id)
      from lint_finding_revision related
      join lint_finding finding using (finding_id)
      where finding.dedupe_key='fixture-repeat')
     is distinct from array[106,206]::bigint[] then
    raise exception 'repeated finding must retain both observed revisions';
  end if;
end $$;
rollback;

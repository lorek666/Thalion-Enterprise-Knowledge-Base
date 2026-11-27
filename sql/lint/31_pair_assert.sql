\set ON_ERROR_STOP on

do $$
declare bad int;
begin
  with expected(rule_code, a_wiki, a_rev, a_stmt, b_wiki, b_rev, b_stmt) as (values
    ('STATEMENT_CONFLICT', 1, 101, 1, 3, 103, 5),
    ('STATEMENT_CONFLICT', 2, 102, 4, 3, 103, 5),
    ('UNIT_MISMATCH', 14, 114, 12, 16, 116, 13)
  ),
  actual as (
    select rule_code,
           (evidence#>>'{a,wiki_id}')::int, (evidence#>>'{a,revision_id}')::int,
           (evidence#>>'{a,statement_id}')::int,
           (evidence#>>'{b,wiki_id}')::int, (evidence#>>'{b,revision_id}')::int,
           (evidence#>>'{b,statement_id}')::int
    from lint_finding
    where rule_code in ('STATEMENT_CONFLICT','UNIT_MISMATCH')
  ),
  diff as (
    (select * from expected except all select * from actual)
    union all
    (select * from actual except all select * from expected)
  )
  select count(*) into bad from diff;
  if bad <> 0 then raise exception 'conflict payload must identify both wiki revisions in stable order'; end if;

  if (select array_agg(distinct related.revision_id order by related.revision_id)
      from lint_finding_revision related
      join lint_finding finding using (finding_id)
      where finding.rule_code in ('STATEMENT_CONFLICT','UNIT_MISMATCH'))
     is distinct from array[101,102,103,114,116]::bigint[] then
    raise exception 'all conflict revisions must be retained as finding references';
  end if;

  if (select count(*)
      from lint_finding_revision related
      join lint_finding finding using (finding_id)
      where finding.rule_code in ('STATEMENT_CONFLICT','UNIT_MISMATCH')) <> 6 then
    raise exception 'each pair must retain exactly two finding references';
  end if;

  if exists (
    select 1 from lint_finding finding
    where finding.rule_code in ('STATEMENT_CONFLICT','UNIT_MISMATCH')
      and (
        finding.revision_id is distinct from (finding.evidence#>>'{a,revision_id}')::bigint
        or (select array_agg(related.revision_id order by related.revision_id)
            from lint_finding_revision related where related.finding_id=finding.finding_id)
           is distinct from array[
             (finding.evidence#>>'{a,revision_id}')::bigint,
             (finding.evidence#>>'{b,revision_id}')::bigint
           ]
      )
  ) then
    raise exception 'each pair must hold its own two revisions and anchor to the first side';
  end if;

  if (select array_agg(revision_id order by revision_id)
      from v_lint_revision_hold where revision_id in (101,102,103,114,116))
     is distinct from array[101,102,103,114,116]::bigint[] then
    raise exception 'both sides of open conflicts must be held';
  end if;
end $$;

begin;
update lint_finding set state='resolved' where rule_code='UNIT_MISMATCH';
do $$
begin
  if exists (select 1 from v_lint_revision_hold where revision_id in (114,116)) then
    raise exception 'resolved conflict must release both sides of the hold';
  end if;
end $$;
rollback;

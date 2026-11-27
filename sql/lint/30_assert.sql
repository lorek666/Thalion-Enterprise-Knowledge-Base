\set ON_ERROR_STOP on

do $$
declare total int; bad int;
begin
  select count(*) into total
  from lint_finding
  where last_run_id = (select max(run_id) from lint_run);
  if total <> 12 then
    raise exception 'expected 12 findings, got %', total;
  end if;

  with expected(rule_code,n) as (values
      ('LINK_BROKEN',1), ('LINK_UNPUBLISHED',2), ('PAGE_MISSING',1),
      ('PAGE_ORPHAN',1), ('CITE_EXPIRED',1), ('CITE_EXCERPT_STALE',1),
      ('STATEMENT_EXPIRED',1), ('STATEMENT_SUPERSEDED',1),
      ('STATEMENT_CONFLICT',2), ('UNIT_MISMATCH',1)),
  actual as (
    select rule_code, count(*)::int n
    from lint_finding
    where last_run_id = (select max(run_id) from lint_run)
    group by 1),
  diff as (
    (select * from expected except select * from actual)
    union all
    (select * from actual except select * from expected))
  select count(*) into bad from diff;
  if bad <> 0 then
    raise exception 'rule counts mismatch in % rows', bad;
  end if;
end $$;

insert into lint_waiver(dedupe_key,reason,waived_by,review_at)
select dedupe_key,'fixture waiver',7,(now() at time zone 'Asia/Shanghai')::date + 1
from lint_finding where rule_code = 'PAGE_ORPHAN';

do $$
begin
  if not (select waived from v_lint_open where rule_code = 'PAGE_ORPHAN') then
    raise exception 'waiver not applied';
  end if;
end $$;

select 'lint assertions ok' as result;

\set ON_ERROR_STOP on

-- T6 断言
do $$
declare n int; v numeric; st text;
begin
  select count(*) into n from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-10-31')
  where status='withdrawn';
  if n<>1 then raise exception 'withdrawn resolution missing'; end if;

  select count(*) into n from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12')
  where status='ambiguous';
  if n<>2 then raise exception 'expected 2 ambiguous candidates, got %', n; end if;

  select status into st from wiki_resolve(1,'city=上海','nightly_limit','',date '2027-01-01');
  if st<>'no_rule' then raise exception 'future/draft leaked: %', st; end if;

  select status,value_num into st,v
  from wiki_asserted_as_of(1,'city=上海','nightly_limit','',timestamptz '2026-09-01 23:59+08');
  if st<>'asserted' or v<>600 then raise exception 'as-of Sep wrong: % %',st,v; end if;

  select status,value_num into st,v
  from wiki_asserted_as_of(1,'city=上海','nightly_limit','',timestamptz '2026-11-01 23:59+08');
  if st<>'asserted' or v<>700 then raise exception 'as-of Nov wrong: % %',st,v; end if;

  select status into st
  from wiki_asserted_as_of(1,'city=上海','nightly_limit','',timestamptz '2026-01-01 23:59+08');
  if st<>'nothing_recorded' then raise exception 'as-of Jan should be empty: %',st; end if;
end $$;
select 'M6 assertions ok' as result;

\set ON_ERROR_STOP on

begin;
create temporary table temporal_mismatch (message text);

update wiki_statement set value_num=700, unit='CNY/room-night' where statement_id=200;
insert into temporal_mismatch
select 'equal numbers with different units must conflict on the business date'
where (select count(*) from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12')
       where status='ambiguous')<>2;
insert into temporal_mismatch
select 'equal numbers with different units must conflict in the audit snapshot'
where (select count(*) from wiki_asserted_as_of(1,'city=上海','nightly_limit','',timestamptz '2026-11-20 12:00+08')
       where status='ambiguous')<>2;

update wiki_statement set unit='CNY/person-night' where statement_id=200;
insert into temporal_mismatch
select 'identical business values must not conflict'
where (select count(*) from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12')
       where status='applicable')<>2;

update wiki set status='suspended' where wiki_id in (1,2);
insert into temporal_mismatch
select 'suspended pages must not supply candidate values'
where (select array_agg(status)
       from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12')
       where statement_id is null and value_num is null and passage_ids='{}'::bigint[])
      is distinct from array['suspended']::text[];
update wiki set status='published' where wiki_id in (1,2);

update wiki_statement set value_num=null, unit=null, statement_type='condition',
  value_text=case statement_id when 101 then '部门负责人书面批准' else '直属主管口头同意' end
where statement_id in (101,200);
insert into temporal_mismatch
select 'different text-valued conditions must conflict'
where (select count(*) from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12')
       where status='ambiguous')<>2;

update wiki_statement set value_num=case statement_id when 101 then 700 else 750 end,
  unit='CNY/person-night', statement_type='amount', value_text=null
where statement_id in (101,200);
update wiki_statement set superseded_by=200 where statement_id=101;
insert into temporal_mismatch
select 'replacement should leave the older rule valid before the new effective date'
where (select array_agg(statement_id order by statement_id)
       from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-11') where status='applicable')
      is distinct from array[101]::bigint[];
insert into temporal_mismatch
select 'explicit replacement must not be reported as a conflict on the effective day'
where (select array_agg(statement_id order by statement_id)
       from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12') where status='applicable')
      is distinct from array[200]::bigint[];

update wiki_revision set status='suspended', retired_at='2026-11-20 09:00+08' where revision_id=20;
insert into temporal_mismatch
select 'suspended replacement must not return a value or resurrect the old rule'
where (select array_agg(status)
       from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12')
       where statement_id is null and value_num is null and passage_ids='{}'::bigint[])
      is distinct from array['suspended']::text[];

update wiki_revision set withdrawn_at='2026-11-20 09:30+08' where revision_id=20;
insert into temporal_mismatch
select 'withdrawn replacement must not resurrect the old rule'
where (select array_agg(status)
       from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12')
       where statement_id is null and value_num is null and passage_ids='{}'::bigint[])
      is distinct from array['withdrawn']::text[];

do $$
declare failures text;
begin
  select string_agg(message, '; ') into failures from temporal_mismatch;
  if failures is not null then raise exception '%',failures; end if;
end $$;
rollback;
select 'M6 regression assertions ok' as result;

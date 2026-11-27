\set ON_ERROR_STOP on

-- T6 断言
do $$
declare n int; aid bigint; st text; cache boolean; wid bigint;
        affected_ids bigint[]; affected_keys text[];
begin
  select count(*) into n from ingest_plan(2,'m1','pa1') where state='changed';
  if n<>1 then raise exception 'expected 1 changed segment, got %',n; end if;

  select count(*) into n from ingest_plan(2,'m1','pa1') where state='unchanged' and cache_hit;
  if n<>2 then raise exception 'expected 2 cached unchanged segments, got %',n; end if;

  select array_agg(statement_id order by statement_id), array_agg(segment_key order by statement_id)
    into affected_ids,affected_keys from ingest_affected(2,'m1','pa1');
  if affected_ids is distinct from array[100,102]::bigint[]
     or affected_keys is distinct from array['lodging','obsolete'] then
    raise exception 'previous citations lost from impact plan: % %',affected_ids,affected_keys;
  end if;

  select count(*) into n from ingest_plan(2,'m1','pa1')
    where segment_key='obsolete' and state='removed' and analysis_id is null and not cache_hit;
  if n<>1 then raise exception 'removed segment missing or scheduled for analysis'; end if;

  select analysis_id,cache_hit into aid,cache
  from ingest_plan(2,'m1','pa1') where segment_key='lodging';
  if aid<>200 or not cache then raise exception 'analysis cache miss: % %',aid,cache; end if;

  if ingest_cache_hit(ingest_key('generation','200|tpl2|pg1|m1')) is not null then
    raise exception 'template bump reused generation cache';
  end if;

  select count(*) into n from source_summary where version_id=2;
  if n<>1 then raise exception 'source summary not idempotent: %',n; end if;
end $$;
select 'M7 assertions ok' as result;

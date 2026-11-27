\set ON_ERROR_STOP on

do $$
declare n int;
begin
  select count(*) into n from gap_cluster;
  if n <> 5 then raise exception 'expected 5 clusters, got %', n; end if;

  select sum(event_count) into n from v_gap_cluster;
  if n is distinct from 32 then raise exception 'expected 32 clustered events, got %', n; end if;

  select count(*) into n from gap_cluster where gap_type = 'permission_limited';
  if n <> 0 then raise exception 'permission-limited events leaked into clusters'; end if;

  select count(*) into n
  from v_gap_candidate
  where priority = 'P1' and topic_key = '采购/供应商准入';
  if n <> 1 then raise exception 'P1 routing wrong'; end if;

  select count(*) into n
  from gap_cluster
  where topic_key = '差旅/住宿上限'
    and status = 'converted'
    and converted_at::date - first_seen = 10;
  if n <> 1 then raise exception 'conversion days wrong'; end if;

  select count(*) into n
  from information_schema.columns
  where table_schema = 'public' and table_name in ('gap_event','gap_cluster')
    and column_name in ('employee_id','subject_id','raw_question','token','session_id');
  if n <> 0 then raise exception 'person-level columns present'; end if;

  select count(*) into n
  from information_schema.columns
  where table_schema = 'public' and table_name in ('v_gap_candidate','v_gap_cluster','v_gap_permission')
    and column_name in ('request_id','gap_event_id','department_id','representative_question',
                        'decision_note','role_snapshot','evidence');
  if n <> 0 then raise exception 'internal fields exposed by a gap projection'; end if;
end $$;

select 'gap assertions ok' as result;

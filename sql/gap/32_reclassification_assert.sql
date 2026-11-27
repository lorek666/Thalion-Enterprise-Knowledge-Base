\set ON_ERROR_STOP on

begin;
insert into gap_probe(cluster_id,role_snapshot,corpus_watermark,result,evidence)
select cluster_id,'fixture role',1,'ambiguous_clause','{"nearest_document_id":9002}'
from gap_cluster where topic_key='差旅/超标审批';

update gap_event set gap_type='permission_limited' where request_id='F-1';
do $$
begin
  if not exists (
    select 1 from v_gap_candidate
    where topic_key='差旅/超标审批' and event_count=1 and nearest_document_id is null
  ) then
    raise exception 'candidate must ignore reclassified events and old probe evidence';
  end if;
end $$;

update gap_event set gap_type='permission_limited' where topic_key='差旅/超标审批';

do $$
begin
  if exists (select 1 from v_gap_candidate where topic_key='差旅/超标审批')
     or exists (select 1 from v_gap_cluster where topic_key='差旅/超标审批') then
    raise exception 'reclassified cluster must disappear from list and details before the next rollup';
  end if;

  if not exists (
    select 1 from v_gap_permission where topic_key='差旅/超标审批' and events=2
  ) then
    raise exception 'reclassified events must still count in the permission view';
  end if;
end $$;

select gap_rollup(1, date '2026-11-02');
do $$
begin
  if exists (select 1 from v_gap_candidate where topic_key='差旅/超标审批')
     or exists (select 1 from v_gap_cluster where topic_key='差旅/超标审批') then
    raise exception 'rollup must not restore the old candidate';
  end if;
end $$;
rollback;

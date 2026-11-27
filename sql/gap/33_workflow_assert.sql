\set ON_ERROR_STOP on

begin;
update gap_cluster
set status='claimed', owner_id=77, decision_note='fixture decision'
where topic_key='差旅/住宿上限';
update gap_event
set gap_type='permission_limited'
where topic_key='差旅/住宿上限' and department_id=11;

do $$
begin
  if exists (
    select 1 from gap_cluster aggregate
    where topic_key='差旅/住宿上限'
      and to_jsonb(aggregate)->>'sample_question' is not null
  ) then
    raise exception 'claimed workflow must not retain a stale sample';
  end if;

  if not exists (
    select 1 from v_gap_cluster
    where topic_key='差旅/住宿上限' and status='claimed' and owner_id=77
      and event_count=8 and department_count=2 and high_count=1
      and sample_question is null and nearest_document_id is null
  ) then
    raise exception 'claimed projection must refresh evidence without rewriting the decision';
  end if;

  perform gap_rollup(1, date '2026-11-02');
  if not exists (
    select 1 from v_gap_cluster
    where topic_key='差旅/住宿上限' and status='claimed' and owner_id=77
      and event_count=8 and department_count=2 and high_count=1
      and sample_question is null and nearest_document_id is null
  ) or not exists (
    select 1 from gap_cluster
    where topic_key='差旅/住宿上限' and decision_note='fixture decision'
  ) then
    raise exception 'rollup must preserve the refreshed evidence and workflow decision';
  end if;

  update gap_event set gap_type='permission_limited' where topic_key='差旅/住宿上限';
  if exists (select 1 from v_gap_cluster where topic_key='差旅/住宿上限')
     or not exists (
       select 1 from gap_cluster where topic_key='差旅/住宿上限'
         and status='claimed' and owner_id=77 and decision_note='fixture decision'
     ) then
    raise exception 'claimed details must disappear without deleting the workflow record';
  end if;
end $$;
rollback;

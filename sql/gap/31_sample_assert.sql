\set ON_ERROR_STOP on

begin;
update gap_event
set representative_question='夹具示例：如何申请测试权限', text_retention_ok=true
where request_id='D-1';
select gap_rollup(1, date '2026-11-02');

do $$
begin
  if not exists (
    select 1 from v_gap_candidate
    where topic_key='IT/权限申请' and department_count=1 and event_count=8
      and sample_question is null
  ) then
    raise exception 'single-department candidate must show counts without a sample';
  end if;

  if not exists (
    select 1 from v_gap_cluster
    where topic_key='差旅/住宿上限' and department_count=3
      and sample_question='上海住宿上限是多少'
  ) then
    raise exception 'three departments must allow an eligible sample';
  end if;
end $$;

update gap_event
set representative_question=null, text_retention_ok=false
where request_id='A-1';

do $$
begin
  if not exists (
    select 1 from v_gap_cluster
    where topic_key='差旅/住宿上限' and department_count=3 and event_count=12
      and sample_question is null
  ) then
    raise exception 'revoked text retention must remove the sample even above the department threshold';
  end if;
end $$;
rollback;

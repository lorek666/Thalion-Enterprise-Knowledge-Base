\set ON_ERROR_STOP on

-- T1 首轮汇总：5 个簇，权限受限事件不入簇
select gap_rollup(1, date '2026-11-02') as created;
select topic_key, gap_type, event_count, department_count, high_count,
       sample_question, nearest_document_id
from v_gap_cluster order by topic_key;

-- T2 幂等
select gap_rollup(1, date '2026-11-02') as created_again;
select count(*) clusters, sum(event_count) events from v_gap_cluster;

-- T3 优先级与处置路由
select topic_key, priority, next_action, high_count, event_count
from v_gap_candidate
order by case priority when 'P1' then 0 when 'P2' then 1 else 2 end,
         high_count desc, event_count desc;

-- T4 权限受限单独统计，不出现在候选里
select * from v_gap_permission;
select count(*) as permission_in_candidates from v_gap_candidate where gap_type='permission_limited';

-- T5 认领后重跑不改写人工决定
update gap_cluster set status='claimed', owner_id=77, decided_at=now()
where topic_key='差旅/住宿上限' and week_start=date '2026-11-02';
select gap_rollup(1, date '2026-11-02') as created_after_claim;
select topic_key, status, event_count, high_count from v_gap_cluster
where topic_key='差旅/住宿上限';

-- T6 转化与回答天数
update gap_cluster set status='converted', wiki_id=501, converted_at=timestamptz '2026-11-12 10:00+08',
       decision_note='新增主题页并引用 B 版表 2'
where topic_key='差旅/住宿上限' and week_start=date '2026-11-02';
select topic_key, status, wiki_id, (converted_at::date - first_seen) as days_to_answer
from gap_cluster where status='converted';

-- T7 隐私：不得出现员工级字段
select count(*) as forbidden_columns
from information_schema.columns
where table_schema = 'public' and table_name in ('gap_event','gap_cluster')
  and column_name in ('employee_id','subject_id','raw_question','token','session_id');

-- T8 同一请求同一缺口不重复计数
do $$
begin
  begin
    insert into gap_event(request_id,space_id,occurred_on,outcome,topic_key,missing_facet,gap_type)
    values ('A-1',1,date '2026-11-02','no_evidence','差旅/住宿上限','amount','no_source');
    raise exception 'duplicate not blocked';
  exception when unique_violation then null;
  end;
end $$;
select count(*) as events_after_duplicate from gap_event;

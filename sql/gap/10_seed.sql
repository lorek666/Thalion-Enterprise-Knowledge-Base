\set ON_ERROR_STOP on
insert into space values (1,'运营部');

-- A 12 次无源，3 个部门，2 次高后果
insert into gap_event(request_id,space_id,occurred_on,outcome,topic_key,intent_key,missing_facet,
                      department_id,consequence,gap_type,representative_question,text_retention_ok,nearest_document_id)
select 'A-'||g,1,date '2026-11-02'+(g%7),'no_evidence','差旅/住宿上限','limit_lookup','amount',
       10+(g%3),case when g<=2 then 'high' else 'normal' end,'no_source',
       case when g=1 then '上海住宿上限是多少' else null end, g=1,
       case when g=1 then 9001 else null end
from generate_series(1,12) g;

-- B 4 次，全是高后果 -> P1
insert into gap_event(request_id,space_id,occurred_on,outcome,topic_key,intent_key,missing_facet,
                      department_id,consequence,gap_type)
select 'B-'||g,1,date '2026-11-03','partial_evidence','采购/供应商准入','eligibility','eligibility',
       20,'high','no_source'
from generate_series(1,4) g;

-- C 50 次权限受限：行为正确，不应成为选题
insert into gap_event(request_id,space_id,occurred_on,outcome,topic_key,intent_key,missing_facet,
                      department_id,consequence,gap_type)
select 'C-'||g,1,date '2026-11-04','no_evidence','财务/成本明细','cost_detail','amount',
       30,'normal','permission_limited'
from generate_series(1,50) g;

-- D 8 次检索不到
insert into gap_event(request_id,space_id,occurred_on,outcome,topic_key,intent_key,missing_facet,
                      department_id,consequence,gap_type)
select 'D-'||g,1,date '2026-11-05','no_evidence','IT/权限申请','apply','other',
       40,'normal','not_retrievable'
from generate_series(1,8) g;

-- E 6 次有源未入库
insert into gap_event(request_id,space_id,occurred_on,outcome,topic_key,intent_key,missing_facet,
                      department_id,consequence,gap_type)
select 'E-'||g,1,date '2026-11-06','no_evidence','人事/调岗','process','other',
       50,'normal','not_ingested'
from generate_series(1,6) g;

-- F 2 次条款歧义
insert into gap_event(request_id,space_id,occurred_on,outcome,topic_key,intent_key,missing_facet,
                      department_id,consequence,gap_type)
select 'F-'||g,1,date '2026-11-07','partial_evidence','差旅/超标审批','approver','approver',
       10,'normal','ambiguous_clause'
from generate_series(1,2) g;

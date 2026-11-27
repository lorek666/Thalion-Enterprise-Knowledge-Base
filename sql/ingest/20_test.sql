\set ON_ERROR_STOP on

-- T1 增量计划：查出修改、删除和新增，未变片段复用已有分析
select segment_key,state,analysis_id,cache_hit
from ingest_plan(2,'m1','pa1') order by segment_key;

-- T2 受影响陈述：引用上一版被修改或删除片段的陈述
select * from ingest_affected(2,'m1','pa1') order by statement_id;

-- T3 分析缓存：注册后重放命中
insert into ingest_analysis(analysis_id,content_hash,model_rev,prompt_rev,payload)
values (200,'h2b','m1','pa1','{"summary":"lodging changed"}');
select ingest_register(ingest_key('analysis','h2b|m1|pa1'),'analysis',200);
select segment_key,state,analysis_id,cache_hit
from ingest_plan(2,'m1','pa1') where segment_key='lodging';

-- T4 生成缓存按模板隔离
select ingest_register(ingest_key('generation','200|tpl1|pg1|m1'),'generation',500);
select ingest_cache_hit(ingest_key('generation','200|tpl1|pg1|m1')) as tpl1_hit;
select ingest_cache_hit(ingest_key('generation','200|tpl2|pg1|m1')) as tpl2_hit;

-- T5 来源摘要兜底：缺失即建，重复调用幂等
select ensure_source_summary(2) as first_call;
select ensure_source_summary(2) as second_call;

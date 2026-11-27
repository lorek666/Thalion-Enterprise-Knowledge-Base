\set ON_ERROR_STOP on

-- T1 换版前日期：命中旧版
select status,statement_id,revision_id,value_num,unit,valid_from,valid_to
from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-10-31');

-- T2 换版后日期：两页都说 700/750，冲突不猜
select status,statement_id,revision_id,value_num
from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-11-12') order by statement_id;

-- T3 超出所有有效期：不回落
select status,statement_id,value_num from wiki_resolve(1,'city=上海','nightly_limit','',date '2027-01-01');

-- T4 记录时间：当时系统怎么说
select 'as-of 2026-09' as label, status,statement_id,revision_id,value_num
from wiki_asserted_as_of(1,'city=上海','nightly_limit','',timestamptz '2026-09-01 23:59+08')
union all
select 'as-of 2026-11', status,statement_id,revision_id,value_num
from wiki_asserted_as_of(1,'city=上海','nightly_limit','',timestamptz '2026-11-01 23:59+08')
union all
select 'as-of 2026-01', status,statement_id,revision_id,value_num
from wiki_asserted_as_of(1,'city=上海','nightly_limit','',timestamptz '2026-01-01 23:59+08');

-- T5 撤回后历史日期也不可用
update wiki_revision set withdrawn_at='2026-11-20 09:00+08' where revision_id=10;
select status,statement_id,value_num from wiki_resolve(1,'city=上海','nightly_limit','',date '2026-10-31');

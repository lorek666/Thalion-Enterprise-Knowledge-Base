\set ON_ERROR_STOP on
set timezone = 'Asia/Shanghai';

insert into space values (1,'运营部');

insert into document_version values
 (1,10,'A版','retired','2025-01-01','2026-11-01'),
 (2,10,'B版','active','2026-11-01',null);

insert into passage values
 (1,1,3,'表2 上海行',1),
 (2,2,3,'表2 上海行',1),
 (3,2,5,'事前审批 第2段',2);

-- 15 个主题页 + 1 个目录页 + 2 个草稿
insert into wiki(wiki_id,space_id,slug,title,page_type,status,owner_id,valid_from,valid_to) values
 (0,1,'index','知识目录','index','published',1,'2025-01-01',null),
 (1,1,'shanghai-lodging','上海住宿与审批','topic','published',1,'2025-01-01',null),
 (2,1,'lodging-summary','住宿标准汇总','topic','published',1,'2025-01-01',null),
 (3,1,'lodging-old-summary','差旅旧汇总','topic','published',1,'2025-01-01',null),
 (4,1,'lodging-2025','2025 年差旅标准','topic','published',1,'2025-01-01','2026-10-31'),
 (5,1,'approval-flow','审批流程','topic','published',1,'2025-01-01',null),
 (6,1,'no-inbound','无人引用页','topic','published',1,'2025-01-01',null),
 (7,1,'links-draft','链接到草稿','topic','published',1,'2025-01-01',null),
 (8,1,'links-ghost','单条断链','topic','published',1,'2025-01-01',null),
 (9,1,'refs-ghost-a','引用缺失主题 A','topic','published',1,'2025-01-01',null),
 (10,1,'refs-ghost-b','引用缺失主题 B','topic','published',1,'2025-01-01',null),
 (11,1,'refs-ghost-c','引用缺失主题 C','topic','published',1,'2025-01-01',null),
 (12,1,'expired-claim','过期金额页','topic','published',1,'2025-01-01',null),
 (13,1,'superseded-claim','已替代结论页','topic','published',1,'2025-01-01',null),
 (14,1,'unit-night','含早住宿（按晚）','topic','published',1,'2025-01-01',null),
 (15,1,'draft-target','尚未发布的主题','topic','draft',1,'2025-01-01',null),
 (16,1,'unit-person','含早住宿（按人）','topic','published',1,'2025-01-01',null),
 (17,1,'superseded-target','替代稿（草稿）','topic','draft',1,'2026-11-01',null);

insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id,approved_by,compile_template_rev,model_rev,published_at)
select 100 + wiki_id, wiki_id, 1, title, '# '||title, status, 'pipeline', 9001, 9002, 'tpl-1', 'm-1', '2026-11-01'
from wiki;

update wiki w set published_revision_id = 100 + w.wiki_id where w.status='published';

-- 目录页链接到除 wiki 6 以外的所有已发布页
insert into wiki_link(revision_id,wiki_id,space_id,line_no,target_slug,link_kind)
select 100, 0, 1, row_number() over (order by w.wiki_id)::int, w.slug, 'wikilink'
from wiki w where w.wiki_id <> 0 and w.wiki_id <> 6;

insert into wiki_link(revision_id,wiki_id,space_id,line_no,target_slug) values
 (107,7,1,1,'draft-target'),
 (108,8,1,1,'ghost-one'),
 (109,9,1,1,'ghost-three'),
 (110,10,1,1,'ghost-three'),
 (111,11,1,1,'ghost-three');

-- 陈述：上海普通住宿上限
insert into wiki_statement(statement_id,revision_id,statement_type,subject_key,predicate,qualifier,value_num,value_code,value_text,unit,valid_from,valid_to,superseded_by,text_excerpt) values
 (1,101,'amount','city=上海|grade=P7|expense=住宿','nightly_limit','',600,'CNY_600','600 元/人·晚','CNY/person-night','2026-11-01',null,null,'上海 600 元/人·晚'),
 (2,101,'approver','city=上海|expense=住宿','over_limit_approver','',null,'dept_head','部门负责人书面批准',null,'2026-11-01',null,null,'事前取得部门负责人书面批准'),
 (3,101,'deadline','city=上海|expense=住宿','claim_window','',null,'d30','30 日内报销','day','2026-11-01',null,null,'30 日内报销'),
 (4,102,'amount','city=上海|grade=P7|expense=住宿','nightly_limit','',600,'CNY_600','600 元/人·晚','CNY/person-night','2026-11-01',null,null,'上海 600 元/人·晚'),
 (5,103,'amount','city=上海|grade=P7|expense=住宿','nightly_limit','',700,'CNY_700','700 元/人·晚','CNY/person-night','2026-11-01',null,null,'上海 700 元/人·晚'),
 (6,104,'amount','city=上海|grade=P7|expense=住宿','nightly_limit','',500,'CNY_500','500 元/人·晚','CNY/person-night','2025-01-01','2026-10-31',null,'上海 500 元/人·晚'),
 (7,105,'approver','city=上海|expense=住宿','over_limit_approver','',null,'dept_head','部门负责人书面批准',null,'2025-01-01',null,null,'事前审批'),
 (8,106,'other','city=上海','misc','',null,null,'x',null,'2025-01-01',null,null,'说明'),
 (9,112,'amount','city=上海|grade=P7|expense=住宿','nightly_limit','',500,'CNY_500','500 元/人·晚','CNY/person-night','2025-01-01','2026-10-01',null,'上海 500 元/人·晚'),
 (10,113,'amount','city=北京|grade=P7|expense=住宿','nightly_limit','',800,'CNY_800','800 元/人·晚','CNY/person-night','2025-01-01',null,11,'北京 800 元/人·晚'),
 (11,117,'amount','city=北京|grade=P7|expense=住宿','nightly_limit','',900,'CNY_900','900 元/人·晚','CNY/person-night','2026-11-01',null,null,'北京 900 元/人·晚'),
 (12,114,'amount','city=上海|grade=P7|expense=住宿','nightly_limit','含早餐',600,'CNY_600','600 元/人·晚','CNY/person-night','2026-11-01',null,null,'含早 600 元/人·晚'),
 (13,116,'amount','city=上海|grade=P7|expense=住宿','nightly_limit','含早餐',600,'CNY_600','600 元/人','CNY/person','2026-11-01',null,null,'含早 600 元/人');

-- 引用：p3 的转录已修订到 2，但 wiki 1 仍引用 revision 1
insert into wiki_citation(revision_id,statement_id,space_id,passage_id,source_version_id,excerpt_revision,cite_order) values
 (101,1,1,2,2,1,1),
 (101,2,1,3,2,1,2),
 (101,3,1,2,2,1,3),
 (102,4,1,2,2,1,1),
 (103,5,1,2,2,1,1),
 (104,6,1,1,1,1,1),
 (105,7,1,1,1,1,1);

insert into lint_rule_set(space_id,rule_code,enabled,severity,params) values
 (1,'LINK_BROKEN',true,'high','{}'),
 (1,'PAGE_MISSING',true,'normal','{"min_pages":3}'),
 (1,'LINK_UNPUBLISHED',true,'normal','{}'),
 (1,'PAGE_ORPHAN',true,'normal','{}'),
 (1,'PAGE_NO_OUTLINK',false,'low','{"min_statements":3}'),
 (1,'CITE_EXPIRED',true,'high','{}'),
 (1,'CITE_WITHDRAWN',true,'blocker','{}'),
 (1,'CITE_EXCERPT_STALE',true,'high','{}'),
 (1,'STATEMENT_EXPIRED',true,'high','{}'),
 (1,'STATEMENT_SUPERSEDED',true,'normal','{}'),
 (1,'STATEMENT_CONFLICT',true,'blocker','{}'),
 (1,'UNIT_MISMATCH',true,'blocker','{}');

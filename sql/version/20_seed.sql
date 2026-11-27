\set ON_ERROR_STOP on
insert into space values (1,'运营部'),(2,'财务部'),(3,'人力资源部'),(4,'行政部');
insert into wiki(wiki_id,space_id,slug,title,published_revision_id) values
 (1,1,'shanghai-lodging','上海住宿与审批',5),
 (2,2,'held-page','保全页',105),
 (3,3,'flagged-page','有阻断发现的页',205),
 (4,4,'user-history','人工历史页',null);

insert into wiki_retention(space_id,hard_cap,keep_user) values (1,3,50),(2,3,50),(3,3,50),(4,10,2);

-- wiki 1：3 个 pipeline、1 个 agent、1 个人工发布、1 个回滚
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id,
                          approved_by,approved_at,rollback_of,published_at) values
 (1,1,1,'v1','A|B','draft','pipeline',null,null,null,null,null),
 (2,1,2,'v2','A|C','draft','pipeline',null,null,null,null,null),
 (3,1,3,'v3','A|B','draft','pipeline',null,null,null,null,null),
 (4,1,4,'v4','A|B2|D','draft','agent',300,null,null,null,null),
 (5,1,5,'v5','A|B2|D','published','user',200,100,now(),null,now()),
 (6,1,6,'v6','A|B2|D','draft','revert',200,null,null,4,null);

-- 第二个页：处于保全（第 5 版由人工发布）
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id)
select 100+g,2,g,'h'||g,'x','draft','pipeline',null from generate_series(1,4) g;
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id,approved_by,approved_at,published_at)
values (105,2,5,'h5','x','published','user',200,100,now(),now());

-- 第三个页：v1 上有 blocker 发现
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id)
select 200+g,3,g,'f'||g,'y','draft','pipeline',null from generate_series(1,4) g;
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id,approved_by,approved_at,published_at)
values (205,3,5,'f5','y','published','user',200,100,now(),now());
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id)
values (206,3,6,'f6','y','draft','pipeline',null);
insert into lint_finding values (1,201,'open','blocker');
insert into wiki_hold(wiki_id,reason,authority,review_at) values (2,'诉讼保全','法务','2027-06-30');

-- wiki 1 三个版本的陈述：A 不变，B 在 v4 被 agent 改写，D 新增
insert into wiki_statement(statement_id,revision_id,subject_key,predicate,qualifier,value_num,unit,valid_from,text_excerpt)
values
 (11,1,'city=上海','nightly_limit','',600,'CNY/person-night','2026-11-01','A'),
 (12,1,'city=上海','over_limit_approver','',null,null,'2026-11-01','B');
update wiki_statement set value_code='dept_head' where statement_id=12;
insert into wiki_statement(statement_id,revision_id,subject_key,predicate,qualifier,value_num,unit,valid_from,text_excerpt)
values
 (21,2,'city=上海','nightly_limit','',600,'CNY/person-night','2026-11-01','A'),
 (22,2,'city=上海','claim_window','',null,null,'2026-11-01','C');
update wiki_statement set value_code='d30' where statement_id=22;
insert into wiki_statement(statement_id,revision_id,subject_key,predicate,qualifier,value_num,unit,valid_from,text_excerpt)
values
 (31,3,'city=上海','nightly_limit','',600,'CNY/person-night','2026-11-01','A'),
 (32,3,'city=上海','over_limit_approver','',null,null,'2026-11-01','B');
update wiki_statement set value_code='dept_head' where statement_id=32;
insert into wiki_statement(statement_id,revision_id,subject_key,predicate,qualifier,value_num,unit,valid_from,text_excerpt)
values
 (41,4,'city=上海','nightly_limit','',600,'CNY/person-night','2026-11-01','A'),
 (42,4,'city=上海','over_limit_approver','',null,null,'2026-11-01','B2'),
 (43,4,'city=上海','claim_window','',null,null,'2026-11-01','D');
update wiki_statement set value_code='general_manager' where statement_id=42;
update wiki_statement set value_code='d15' where statement_id=43;
insert into wiki_statement(statement_id,revision_id,subject_key,predicate,qualifier,value_num,unit,valid_from,text_excerpt)
values
 (51,5,'city=上海','nightly_limit','',600,'CNY/person-night','2026-11-01','A'),
 (52,5,'city=上海','over_limit_approver','',null,null,'2026-11-01','B2'),
 (53,5,'city=上海','claim_window','',null,null,'2026-11-01','D');
update wiki_statement set value_code='general_manager' where statement_id=52;
update wiki_statement set value_code='d15' where statement_id=53;

select wiki_carry_statements(2);
select wiki_carry_statements(3);
select wiki_carry_statements(4);
select wiki_carry_statements(5);

insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id)
select 300+g,4,g,'u'||g,'z','draft','user',200 from generate_series(1,4) g;

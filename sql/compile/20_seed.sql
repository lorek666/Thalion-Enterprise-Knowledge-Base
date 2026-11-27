\set ON_ERROR_STOP on
insert into space values (1,'运营部');
insert into compile_template(template_id,space_id,name,artifact_kind,created_by)
overriding system value
values (1,1,'差旅主题模板','wiki',9001);

insert into compile_template_rev(template_rev_id,template_id,revision_no,status,rules,prompt_rev,model_rev,
                                 output_contract,required_fields,checksum,change_note,published_by,published_at)
overriding system value
values
 (1,1,1,'published','{"extract":["amount","approver"]}','p1','m1','{"sections":["结论","依据"]}',
  '{}'::jsonb,'c1','初版规则',9002,now()),
 (2,1,2,'published','{"extract":["amount","approver","deadline"]}','p2','m1','{"sections":["结论","依据","时限"]}',
  '{"amount":["unit","valid_from"],"approver":["citation"]}'::jsonb,'c2','金额必须带单位，审批人必须有引用',9002,now());

insert into wiki(wiki_id,space_id,slug,title,status,published_revision_id) values
 (1,1,'shanghai-lodging','上海住宿与审批','published',10),
 (2,1,'approval-summary','审批汇总','published',20);

insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,compile_template_id,compile_template_rev)
values
 (10,1,1,'上海住宿与审批','v10','published',1,'1'),
 (11,1,2,'上海住宿与审批（候选）','v11','draft',1,'2'),
 (12,1,3,'上海住宿与审批（回退重放）','v12','draft',1,'1'),
 (20,2,1,'审批汇总','v20','published',1,'1'),
 (21,2,2,'审批汇总（候选）','v21','draft',1,'2');

insert into wiki_statement(statement_id,revision_id,statement_type,subject_key,predicate,qualifier,value_num,value_code,unit,valid_from,fingerprint) values
 (101,10,'amount','city=上海','nightly_limit','',600,null,'CNY/person-night','2026-11-01','A'),
 (102,10,'approver','city=上海','over_limit_approver','',null,'dept_head',null,'2026-11-01','B'),
 (201,11,'amount','city=上海','nightly_limit','',600,null,null,'2026-11-01','A2'),
 (202,11,'approver','city=上海','over_limit_approver','',null,'dept_head',null,'2026-11-01','B'),
 (203,11,'deadline','city=上海','claim_window','',null,'d30',null,'2026-11-01','C'),
 (301,20,'amount','city=上海','nightly_limit','',600,null,'CNY/person-night','2026-11-01','A'),
 (302,20,'approver','city=上海','over_limit_approver','',null,'dept_head',null,'2026-11-01','B'),
 (401,21,'amount','city=上海','nightly_limit','',600,null,'CNY/person-night','2026-11-01','A'),
 (402,21,'approver','city=上海','over_limit_approver','',null,'dept_head',null,'2026-11-01','B'),
 (500,12,'amount','city=上海','nightly_limit','',600,null,'CNY/person-night','2026-11-01','A'),
 (501,12,'approver','city=上海','over_limit_approver','',null,'dept_head',null,'2026-11-01','B');

insert into wiki_citation(revision_id,statement_id,passage_id,source_version_id) values
 (10,101,1,2),(10,102,2,2),
 (11,201,1,2),(11,203,2,2),
 (20,301,1,2),(20,302,2,2),
 (21,401,1,2),(21,402,2,2),
 (12,500,1,2),(12,501,2,2);

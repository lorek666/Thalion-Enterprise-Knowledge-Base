\set ON_ERROR_STOP on
insert into space values (1,'运营部');
insert into wiki(wiki_id,space_id,slug,status,published_revision_id) values
 (1,1,'shanghai-lodging','published',11),
 (2,1,'lodging-summary','published',20);

insert into wiki_revision(revision_id,wiki_id,version_no,status,published_at,retired_at,withdrawn_at) values
 (10,1,1,'retired','2026-05-01 09:00+08','2026-10-25 09:00+08',null),
 (11,1,2,'published','2026-10-25 09:00+08',null,null),
 (12,1,3,'pending',null,null,null),
 (20,2,1,'published','2026-11-10 09:00+08',null,null);

insert into wiki_statement(statement_id,revision_id,statement_type,subject_key,predicate,qualifier,value_num,unit,valid_from,valid_to) values
 (100,10,'amount','city=上海','nightly_limit','',600,'CNY/person-night','2025-01-01','2026-11-01'),
 (101,11,'amount','city=上海','nightly_limit','',700,'CNY/person-night','2026-11-01','2027-01-01'),
 (102,12,'amount','city=上海','nightly_limit','',800,'CNY/person-night','2027-01-01',null),
 (200,20,'amount','city=上海','nightly_limit','',750,'CNY/person-night','2026-11-12','2026-12-31');

insert into wiki_citation values (100,1,1),(101,2,1),(102,3,1),(200,4,1);

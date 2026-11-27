\set ON_ERROR_STOP on
insert into document_version values
 (1,1,1,'doc-v1'),
 (2,1,2,'doc-v2');

insert into ingest_segment(segment_id,version_id,segment_key,content_hash) values
 (11,1,'intro','h1'),
 (12,1,'lodging','h2'),
 (13,1,'approval','h3'),
 (14,1,'obsolete','h5'),
 (21,2,'intro','h1'),
 (22,2,'lodging','h2b'),
 (23,2,'approval','h3'),
 (24,2,'appendix','h4');

insert into ingest_analysis(analysis_id,content_hash,model_rev,prompt_rev,payload) values
 (101,'h1','m1','pa1','{"summary":"intro"}'),
 (103,'h3','m1','pa1','{"summary":"approval"}');

insert into passage values (1,2),(2,2),(3,2),(4,2),(11,1),(12,1),(13,1),(14,1);
insert into passage_segment values (1,21),(2,22),(3,23),(4,24),(11,11),(12,12),(13,13),(14,14);

insert into wiki values (1,'shanghai-lodging');
insert into wiki_revision values (10,1);
insert into wiki_statement values (100,10),(101,10),(102,10);
insert into wiki_citation values (100,12),(101,13),(102,14);

\set ON_ERROR_STOP on
insert into space values (1,'运营部');
insert into evidence_profile values (1,3,6,100,60000);

-- S1 完整闭环
select evidence_start('req-1',1,date '2026-11-20',9,array['amount','approver']) as s1 \gset
select * from evidence_step_begin(:s1,'search','h:search:1',20) \gset d1_
select evidence_step_finish(:d1_step_id,'ok',array[1,2],20,120);
select evidence_cover(:s1,array['amount']);
select * from evidence_step_begin(:s1,'grep_exact','h:grep:1',20) \gset d2_
select evidence_step_finish(:d2_step_id,'ok',array[3],15,90);
select evidence_cover(:s1,array['approver']);
select status, stop_reason, covered_facets from evidence_session where session_id=:s1;
select * from evidence_step_begin(:s1,'search','h:search:2',10);
select session_id,status,passage_ids,steps_used,tokens_used from v_evidence_bundle where session_id=:s1;

-- S2 步数预算
select evidence_start('req-2',1,date '2026-11-20',9,array['amount']) as s2 \gset
select * from evidence_step_begin(:s2,'search','a',10) \gset b1_
select evidence_step_finish(:b1_step_id,'ok',array[11],10,50);
select * from evidence_step_begin(:s2,'search','b',10) \gset b2_
select evidence_step_finish(:b2_step_id,'ok',array[12],10,50);
select * from evidence_step_begin(:s2,'search','c',10) \gset b3_
select evidence_step_finish(:b3_step_id,'ok',array[13],10,50);
select * from evidence_step_begin(:s2,'search','d',10);
select status, stop_reason from evidence_session where session_id=:s2;

-- S3 token 预算
select evidence_start('req-3',1,date '2026-11-20',9,array['amount']) as s3 \gset
select * from evidence_step_begin(:s3,'search','e',80) \gset c1_
select evidence_step_finish(:c1_step_id,'ok',array[21],80,200);
select * from evidence_step_begin(:s3,'search','f',30);
select status, stop_reason, tokens_used from evidence_session where session_id=:s3;

-- S4 循环
select evidence_start('req-4',1,date '2026-11-20',9,array['amount']) as s4 \gset
select * from evidence_step_begin(:s4,'search','same',10) \gset e1_
select evidence_step_finish(:e1_step_id,'ok',array[31],10,50);
select * from evidence_step_begin(:s4,'search','same',10);

-- S5 拒绝不泄露
select evidence_start('req-5',1,date '2026-11-20',9,array['amount']) as s5 \gset
select * from evidence_step_begin(:s5,'read_section','p:9',10) \gset f1_
select evidence_step_finish(:f1_step_id,'denied','{}'::bigint[],0,30);
do $$
declare sid bigint;
begin
  select max(session_id) into sid from evidence_session where request_id='req-5';
  begin
    insert into evidence_step(session_id,step_no,tool,input_hash,result,passage_ids,policy_rev)
    values (sid, 99, 'read_section','x','denied',array[999],'p');
    raise exception 'denied with passages not blocked';
  exception when check_violation then null;
  end;
end $$;
select session_id,status,passage_ids from v_evidence_bundle where session_id=:s5;

-- S6 截止时间
select evidence_start('req-6',1,date '2026-11-20',9,array['amount']) as s6 \gset
update evidence_session set deadline_at=now()-interval '1 second' where session_id=:s6;
select * from evidence_step_begin(:s6,'search','late',10);
select status, stop_reason from evidence_session where session_id=:s6;

select evidence_start('req-actual-over',1,date '2026-11-20',9,array['amount','approver']) as actual_over \gset
select * from evidence_step_begin(:actual_over,'search','first',10) \gset accepted_
select evidence_step_finish(:accepted_step_id,'ok',array[41],10,50);
select evidence_cover(:actual_over,array['amount']);
select * from evidence_step_begin(:actual_over,'search','over',20) \gset over_
select evidence_step_finish(:over_step_id,'ok',array[42,43,44,45,46,47],91,50);
select evidence_cover(:actual_over,array['approver']);

select evidence_start('req-token-over',1,date '2026-11-20',9,array['amount']) as token_over \gset
select * from evidence_step_begin(:token_over,'search','over',20) \gset token_
select evidence_step_finish(:token_step_id,'ok',array[51],101,50);

select evidence_start('req-exact-budget',1,date '2026-11-20',9,array['amount']) as exact_budget \gset
select * from evidence_step_begin(:exact_budget,'search','exact',20) \gset exact_
select evidence_step_finish(:exact_step_id,'ok',array[61,62,63,64,65,66],100,50);
select evidence_cover(:exact_budget,array['amount']);

select evidence_start('req-duplicate',1,date '2026-11-20',9,array['amount']) as duplicate_step \gset
select * from evidence_step_begin(:duplicate_step,'search','first',10) \gset duplicate_
select evidence_step_finish(:duplicate_step_id,'ok',array[71],80,50);
select evidence_step_finish(:duplicate_step_id,'ok',array[72],1,50);
select * from evidence_step_begin(:duplicate_step,'search','too-expensive',21);

select evidence_start('req-closed-late',1,date '2026-11-20',9,array['amount']) as closed_late \gset
select * from evidence_step_begin(:closed_late,'search','late',20) \gset closed_
select * from evidence_step_begin(:closed_late,'search','over',81);
select evidence_step_finish(:closed_step_id,'ok',array[81],21,50);
select evidence_cover(:closed_late,array['amount']);

select evidence_start('req-deadline-late',1,date '2026-11-20',9,array['amount']) as deadline_late \gset
select * from evidence_step_begin(:deadline_late,'search','late',10) \gset deadline_
update evidence_session set deadline_at=now()-interval '1 second' where session_id=:deadline_late;
select evidence_step_finish(:deadline_step_id,'ok',array[91],11,50);

do $$
declare test_session bigint; test_step bigint;
begin
  test_session := evidence_start('req-in-flight',1,date '2026-11-20',9,array['amount']);
  select b.step_id into strict test_step from evidence_step_begin(test_session,'search','first',20) b;
  perform evidence_cover(test_session,array['amount']);
  perform evidence_step_finish(test_step,'ok',array[101],101,50);
end $$;

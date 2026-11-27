\set ON_ERROR_STOP on

do $$
declare n int; pid bigint[];
begin
  select count(*) into n from evidence_session
  where request_id = 'req-1' and status = 'complete';
  if n <> 1 then raise exception 'req-1 not complete'; end if;

  select v.passage_ids into pid
  from v_evidence_bundle v join evidence_session e using(session_id)
  where e.request_id = 'req-1';
  if pid <> array[1,2,3]::bigint[] then
    raise exception 'req-1 bundle %', pid;
  end if;

  select count(*) into n from evidence_session
  where request_id = 'req-2' and status = 'partial' and stop_reason = 'budget_steps';
  if n <> 1 then raise exception 'req-2 stop reason wrong'; end if;

  select count(*) into n from evidence_session
  where request_id = 'req-3' and status = 'partial' and stop_reason = 'budget_tokens';
  if n <> 1 then raise exception 'req-3 stop reason wrong'; end if;

  select v.passage_ids into pid
  from v_evidence_bundle v join evidence_session e using(session_id)
  where e.request_id = 'req-5';
  if cardinality(pid) <> 0 then raise exception 'denied step leaked passages %', pid; end if;

  select count(*) into n from evidence_session
  where request_id = 'req-6' and status = 'stopped' and stop_reason = 'deadline';
  if n <> 1 then raise exception 'req-6 deadline not enforced'; end if;
end $$;

do $$
begin
  if not exists (
    select 1 from v_evidence_bundle b join evidence_session s using(session_id)
    where s.request_id = 'req-actual-over' and b.status = 'partial'
      and b.stop_reason = 'budget_passages' and b.passages_used = 7 and b.tokens_used = 101
      and b.passage_ids = array[41]::bigint[] and b.covered_facets = array['amount']
  ) then
    raise exception '7 passages and 101 actual tokens must close the session and withhold the over-budget result';
  end if;
  if not exists (
    select 1 from v_evidence_bundle b join evidence_session s using(session_id)
    where s.request_id = 'req-token-over' and b.status = 'partial'
      and b.stop_reason = 'budget_tokens' and b.passages_used = 1 and b.tokens_used = 101
      and b.passage_ids = '{}'::bigint[]
  ) then
    raise exception '101 actual tokens must close the session even when passages are under budget';
  end if;
  if not exists (
    select 1 from v_evidence_bundle b join evidence_session s using(session_id)
    where s.request_id = 'req-exact-budget' and b.status = 'complete'
      and b.passages_used = 6 and b.tokens_used = 100
      and b.passage_ids = array[61,62,63,64,65,66]::bigint[]
  ) then
    raise exception 'settlement at the exact passage and token limits must be accepted';
  end if;
end $$;

do $$
begin
  if not exists (
    select 1 from v_evidence_bundle b join evidence_session s using(session_id)
    where s.request_id = 'req-duplicate' and b.stop_reason = 'budget_tokens'
      and b.steps_used = 1 and b.passages_used = 1 and b.tokens_used = 80
      and b.passage_ids = array[71]::bigint[]
  ) then
    raise exception 'a repeated settlement must not edit the first result or refund its actual cost';
  end if;
  if not exists (
    select 1 from v_evidence_bundle b join evidence_session s using(session_id)
    where s.request_id = 'req-closed-late' and b.status = 'partial'
      and b.stop_reason = 'budget_tokens' and b.passages_used = 1 and b.tokens_used = 21
      and b.passage_ids = '{}'::bigint[] and b.covered_facets = '{}'::text[]
  ) then
    raise exception 'closed session must account for late work without admitting evidence or coverage';
  end if;
  if not exists (
    select 1 from v_evidence_bundle b join evidence_session s using(session_id)
    where s.request_id = 'req-deadline-late' and b.status = 'stopped'
      and b.stop_reason = 'deadline' and b.passages_used = 1 and b.tokens_used = 11
      and b.passage_ids = '{}'::bigint[]
  ) then
    raise exception 'a result arriving after the deadline must only charge actual cost';
  end if;
end $$;

do $$
begin
  if not exists (
    select 1 from v_evidence_bundle b join evidence_session s using(session_id)
    where s.request_id = 'req-in-flight' and b.status = 'partial'
      and b.stop_reason = 'budget_tokens' and b.tokens_used = 101
      and b.passage_ids = '{}'::bigint[] and b.covered_facets = '{}'::text[]
  ) then
    raise exception 'coverage must not complete the session while costs are unsettled';
  end if;
end $$;

do $$
declare test_session bigint; test_step bigint;
begin
  test_session := evidence_start('req-negative-cost',1,date '2026-11-20',9,array['amount']);
  begin
    perform evidence_step_begin(test_session,'search','negative',-1);
    raise exception 'negative estimate can refund the budget';
  exception when invalid_parameter_value then null;
  end;
  select b.step_id into strict test_step from evidence_step_begin(test_session,'search','valid',20) b;
  begin
    perform evidence_step_finish(test_step,'ok',array[111],-1,50);
    raise exception 'negative actual cost can refund the budget';
  exception when invalid_parameter_value then null;
  end;
  perform evidence_step_finish(test_step,'ok',array[112],25,50);
  if not exists (
    select 1 from v_evidence_bundle b where b.session_id = test_session
      and b.steps_used = 1 and b.tokens_used = 25 and b.passage_ids = array[112]::bigint[]
  ) then
    raise exception 'invalid cost input affected the settlement';
  end if;
end $$;

select 'evidence assertions ok' as result;

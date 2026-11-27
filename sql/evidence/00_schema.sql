\set ON_ERROR_STOP on
create table space(space_id bigint primary key, name text not null);

create type evidence_tool as enum ('search','grep_exact','read_section','follow_citation','wiki_page');
create type evidence_step_result as enum ('ok','empty','denied','timeout','budget_exhausted','loop','late');
create type evidence_session_status as enum ('running','complete','partial','stopped');

create table evidence_profile(
  space_id bigint primary key references space(space_id),
  max_steps int not null,
  max_passages int not null,
  max_tokens int not null,
  max_ms int not null
);

create table evidence_session(
  session_id bigint generated always as identity primary key,
  request_id text not null,
  space_id bigint not null references space(space_id),
  business_date date not null,
  gateway_id bigint not null,
  required_facets text[] not null default '{}',
  covered_facets text[] not null default '{}',
  max_steps int not null,
  max_passages int not null,
  max_tokens int not null,
  steps_used int not null default 0,
  passages_used bigint not null default 0,
  tokens_used bigint not null default 0,
  reserved_tokens bigint not null default 0,
  status evidence_session_status not null default 'running',
  stop_reason text,
  started_at timestamptz not null default now(),
  deadline_at timestamptz not null
);

create table evidence_step(
  step_id bigint generated always as identity primary key,
  session_id bigint not null references evidence_session(session_id),
  step_no int not null,
  tool evidence_tool not null,
  input_hash text not null,
  result evidence_step_result,
  passage_ids bigint[] not null default '{}',
  passage_cost int not null default 0 check (passage_cost >= 0),
  token_cost int not null default 0 check (token_cost >= 0),
  latency_ms int not null default 0 check (latency_ms >= 0),
  policy_rev text not null,
  created_at timestamptz not null default now(),
  unique (session_id, step_no),
  check (result is not distinct from 'ok' or cardinality(passage_ids)=0)
);

create or replace function evidence_start(
  p_request text, p_space bigint, p_business date, p_gateway bigint, p_facets text[]
) returns bigint language plpgsql as $$
declare s bigint; p evidence_profile;
begin
  select * into p from evidence_profile where space_id=p_space;
  if not found then raise exception 'no evidence profile for space %', p_space; end if;
  insert into evidence_session(request_id,space_id,business_date,gateway_id,required_facets,
                               max_steps,max_passages,max_tokens,deadline_at)
  values (p_request,p_space,p_business,p_gateway,p_facets,
          p.max_steps,p.max_passages,p.max_tokens,
          clock_timestamp()+make_interval(secs => (p.max_ms/1000.0)::double precision))
  returning session_id into s;
  return s;
end $$;

create or replace function evidence_step_begin(
  p_session bigint, p_tool evidence_tool, p_hash text, p_est_tokens int
) returns table(allowed boolean, step_id bigint, step_no int, reason text)
language plpgsql as $$
declare s evidence_session; n int; sid bigint;
begin
  if p_est_tokens is null or p_est_tokens < 0 then
    raise exception 'invalid token estimate' using errcode = '22023';
  end if;
  select * into s from evidence_session where session_id=p_session for update;
  if not found then raise exception 'session % not found', p_session; end if;

  if s.status <> 'running' then
    return query select false, null::bigint, null::int, 'session_closed'; return;
  end if;
  if clock_timestamp() >= s.deadline_at then
    update evidence_session set status='stopped', stop_reason='deadline' where session_id=p_session;
    return query select false, null::bigint, null::int, 'deadline'; return;
  end if;
  if s.steps_used >= s.max_steps then
    update evidence_session set status='partial', stop_reason='budget_steps' where session_id=p_session;
    return query select false, null::bigint, null::int, 'budget_steps'; return;
  end if;
  if exists (select 1 from evidence_step e
             where e.session_id=p_session and e.tool=p_tool and e.input_hash=p_hash
               and e.step_no > s.steps_used - 2) then
    return query select false, null::bigint, null::int, 'loop'; return;
  end if;
  if s.passages_used >= s.max_passages then
    update evidence_session set status='partial', stop_reason='budget_passages' where session_id=p_session;
    return query select false, null::bigint, null::int, 'budget_passages'; return;
  end if;
  if s.tokens_used + s.reserved_tokens + p_est_tokens > s.max_tokens then
    update evidence_session set status='partial', stop_reason='budget_tokens' where session_id=p_session;
    return query select false, null::bigint, null::int, 'budget_tokens'; return;
  end if;

  n := s.steps_used + 1;
  insert into evidence_step(session_id,step_no,tool,input_hash,token_cost,policy_rev)
  values (p_session,n,p_tool,p_hash,p_est_tokens,'policy-2026-11')
  returning evidence_step.step_id into sid;
  update evidence_session set steps_used=n, reserved_tokens=reserved_tokens+p_est_tokens
  where session_id=p_session;
  return query select true, sid, n, 'ok';
end $$;

create or replace function evidence_step_finish(
  p_step bigint, p_result evidence_step_result, p_passages bigint[],
  p_tokens int, p_latency int
) returns void language plpgsql as $$
declare
  step_session bigint;
  s evidence_session;
  e evidence_step;
  final_result evidence_step_result := p_result;
  actual_passages int := cardinality(p_passages);
begin
  select session_id into step_session from evidence_step where step_id=p_step;
  if not found then raise exception 'step % not found', p_step; end if;
  select * into s from evidence_session where session_id=step_session for update;
  select * into e from evidence_step where step_id=p_step;
  if e.result is not null then return; end if;
  if p_result is null or p_result in ('budget_exhausted','late')
     or p_tokens is null or p_tokens < 0 or p_latency is null or p_latency < 0
     or actual_passages is null or (p_result <> 'ok' and actual_passages <> 0) then
    raise exception 'invalid evidence settlement' using errcode = '22023';
  end if;

  s.tokens_used := s.tokens_used + p_tokens;
  s.passages_used := s.passages_used + actual_passages;
  if s.status <> 'running' then
    final_result := 'late';
  elsif clock_timestamp() >= s.deadline_at then
    final_result := 'timeout';
    s.status := 'stopped';
    s.stop_reason := 'deadline';
  elsif s.passages_used > s.max_passages or s.tokens_used > s.max_tokens then
    final_result := 'budget_exhausted';
    s.status := 'partial';
    s.stop_reason := case when s.passages_used > s.max_passages then 'budget_passages' else 'budget_tokens' end;
  end if;

  update evidence_step
  set result=final_result, passage_ids=case when final_result='ok' then p_passages else '{}'::bigint[] end,
      passage_cost=actual_passages, token_cost=p_tokens, latency_ms=p_latency
  where step_id=p_step;

  if s.status = 'running' and final_result = 'empty'
     and (select count(*) from (select result from evidence_step
                                where session_id=step_session order by step_no desc limit 2) x
          where result='empty') = 2 then
    s.status := 'partial';
    s.stop_reason := 'no_new_evidence';
  end if;
  update evidence_session
  set tokens_used=s.tokens_used, passages_used=s.passages_used,
      reserved_tokens=s.reserved_tokens-e.token_cost, status=s.status, stop_reason=s.stop_reason
  where session_id=step_session;
end $$;

create or replace function evidence_cover(p_session bigint, p_facets text[]) returns void
language plpgsql as $$
declare s evidence_session;
begin
  select * into s from evidence_session where session_id=p_session for update;
  if not found or s.status <> 'running' then return; end if;
  if clock_timestamp() >= s.deadline_at then
    update evidence_session set status='stopped', stop_reason='deadline' where session_id=p_session;
    return;
  end if;
  if exists (select 1 from evidence_step where session_id=p_session and result is null) then
    return;
  end if;
  s.covered_facets := array(select distinct unnest(s.covered_facets || p_facets));
  if s.required_facets <@ s.covered_facets then
    s.status := 'complete';
    s.stop_reason := 'facets_covered';
  end if;
  update evidence_session
  set covered_facets=s.covered_facets, status=s.status, stop_reason=s.stop_reason
  where session_id=p_session;
end $$;

create or replace view v_evidence_bundle as
select s.session_id, s.status, s.required_facets, s.covered_facets, s.stop_reason,
       coalesce((select array_agg(distinct p order by p)
                 from evidence_step e, unnest(e.passage_ids) p
                 where e.session_id = s.session_id and e.result = 'ok'), '{}'::bigint[]) as passage_ids,
       s.steps_used, s.passages_used, s.tokens_used
from evidence_session s;

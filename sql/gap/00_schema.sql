\set ON_ERROR_STOP on
create table space(space_id bigint primary key, name text not null);

create type gap_outcome as enum ('no_evidence','partial_evidence');
create type gap_type as enum
  ('unclassified','no_source','not_ingested','not_retrievable','permission_limited','ambiguous_clause');
create type gap_status as enum ('new','claimed','converted','dismissed');

create table gap_event(
  gap_event_id bigint generated always as identity primary key,
  request_id text not null,
  space_id bigint not null references space(space_id),
  occurred_on date not null,
  outcome gap_outcome not null,
  topic_key text not null,
  intent_key text,
  missing_facet text not null default 'other',
  department_id bigint,
  consequence text not null default 'normal' check (consequence in ('normal','high')),
  representative_question text,
  text_retention_ok boolean not null default false,
  gap_type gap_type not null default 'unclassified',
  nearest_document_id bigint,
  unique (request_id, missing_facet),
  check (representative_question is null or text_retention_ok)
);

create table gap_cluster(
  cluster_id bigint generated always as identity primary key,
  space_id bigint not null references space(space_id),
  week_start date not null,
  topic_key text not null,
  intent_key text not null default '',
  gap_type gap_type not null check (gap_type <> 'permission_limited'),
  first_seen date not null,
  status gap_status not null default 'new',
  owner_id bigint,
  wiki_id bigint,
  decision_note text,
  decided_at timestamptz,
  converted_at timestamptz,
  unique (space_id, week_start, topic_key, intent_key, gap_type)
);

create table gap_probe(
  probe_id bigint generated always as identity primary key,
  cluster_id bigint not null references gap_cluster(cluster_id),
  role_snapshot text not null,
  corpus_watermark bigint not null,
  result gap_type not null,
  evidence jsonb not null default '{}'::jsonb,
  probed_at timestamptz not null default now()
);

create index gap_event_week_idx on gap_event(space_id, occurred_on);
create index gap_event_topic_idx on gap_event(space_id, topic_key, intent_key);

create or replace view v_gap_event_rollup as
select space_id, date_trunc('week',occurred_on::timestamp)::date as week_start,
       topic_key, coalesce(intent_key,'') as intent_key, gap_type,
       count(*)::int as event_count,
       count(distinct department_id)::int as department_count,
       (count(*) filter (where consequence='high'))::int as high_count,
       case when count(distinct department_id) >= 3 then
         min(representative_question) filter (where text_retention_ok and department_id is not null)
       end as sample_question,
       min(nearest_document_id) as nearest_document_id,
       min(occurred_on) as first_event_on, max(occurred_on) as last_seen
from gap_event
where gap_type <> 'permission_limited'
group by space_id, date_trunc('week',occurred_on::timestamp)::date,
         topic_key, coalesce(intent_key,''), gap_type;

create or replace function gap_rollup(p_space bigint, p_week_start date)
returns int language plpgsql as $$
declare n int;
begin
  if extract(isodow from p_week_start) is distinct from 1 then
    raise exception 'week start must be a Monday';
  end if;

  insert into gap_cluster(space_id,week_start,topic_key,intent_key,gap_type,first_seen)
  select space_id,week_start,topic_key,intent_key,gap_type,first_event_on
  from v_gap_event_rollup
  where space_id = p_space and week_start = p_week_start
  on conflict (space_id,week_start,topic_key,intent_key,gap_type) do nothing;
  get diagnostics n = row_count;
  return n;
end $$;

create or replace view v_gap_cluster as
select workflow.cluster_id,workflow.space_id,workflow.week_start,workflow.topic_key,workflow.intent_key,
       workflow.gap_type,workflow.status,workflow.owner_id,workflow.wiki_id,
       current_events.event_count, current_events.department_count,
       current_events.high_count, current_events.sample_question,
       current_events.nearest_document_id, current_events.last_seen
from gap_cluster workflow
join v_gap_event_rollup current_events using (space_id,week_start,topic_key,intent_key,gap_type);

create or replace view v_gap_candidate as
select c.cluster_id,c.space_id,c.week_start,c.topic_key,c.intent_key,c.gap_type,
  c.event_count,c.department_count,c.high_count,c.sample_question,c.nearest_document_id,c.last_seen,
  case when c.high_count >= 3 then 'P1'
       when c.event_count >= 10 or c.department_count >= 3 then 'P2'
       else 'P3' end as priority,
  case c.gap_type
    when 'no_source'         then 'author_new_source'
    when 'not_ingested'      then 'fix_connector'
    when 'not_retrievable'   then 'fix_retrieval'
    when 'ambiguous_clause'  then 'policy_ruling'
    else 'triage' end as next_action
from v_gap_cluster c
where c.status = 'new';

create or replace view v_gap_permission as
select space_id, topic_key, count(*)::int events, count(distinct department_id)::int departments
from gap_event
where gap_type = 'permission_limited'
group by space_id, topic_key;

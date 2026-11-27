\set ON_ERROR_STOP on
set timezone = 'Asia/Shanghai';

create table space(space_id bigint primary key, name text not null);

create table document_version(
  version_id bigint primary key,
  document_id bigint not null,
  version_label text not null,
  status text not null check (status in ('active','retired','withdrawn')),
  valid_from date not null,
  valid_to date
);

create table passage(
  passage_id bigint primary key,
  version_id bigint not null references document_version(version_id),
  page_no int,
  anchor text,
  current_excerpt_revision int not null default 1
);

create type wiki_status as enum ('draft','pending','published','suspended');
create type lint_severity as enum ('blocker','high','normal','low');
create type lint_state as enum ('open','acknowledged','ignored','resolved');

create table wiki(
  wiki_id bigint primary key,
  space_id bigint not null references space(space_id),
  slug text not null,
  title text not null,
  page_type text not null default 'topic' check (page_type in ('topic','index','overview','source')),
  status wiki_status not null default 'draft',
  published_revision_id bigint,
  owner_id bigint not null,
  valid_from date,
  valid_to date,
  unique (space_id, slug)
);

create table wiki_revision(
  revision_id bigint primary key,
  wiki_id bigint not null references wiki(wiki_id),
  version_no int not null,
  title text not null,
  body_md text not null,
  status wiki_status not null,
  edit_source text not null check (edit_source in ('pipeline','agent','user','revert')),
  editor_id bigint,
  approved_by bigint,
  compile_template_rev text,
  model_rev text,
  published_at timestamptz,
  unique (wiki_id, version_no)
);

alter table wiki add constraint wiki_published_revision_fk
  foreign key (published_revision_id) references wiki_revision(revision_id);

create table wiki_link(
  revision_id bigint not null references wiki_revision(revision_id) on delete cascade,
  wiki_id bigint not null references wiki(wiki_id),
  space_id bigint not null references space(space_id),
  line_no int not null,
  target_slug text not null,
  link_kind text not null default 'wikilink' check (link_kind in ('wikilink','anchor')),
  primary key (revision_id, line_no, target_slug)
);

create table wiki_statement(
  statement_id bigint primary key,
  revision_id bigint not null references wiki_revision(revision_id) on delete cascade,
  statement_type text not null check (statement_type in ('amount','deadline','approver','eligibility','other')),
  subject_key text not null,
  predicate text not null,
  qualifier text not null default '',
  value_num numeric(18,4),
  value_code text,
  value_text text,
  unit text,
  valid_from date not null,
  valid_to date,
  superseded_by bigint references wiki_statement(statement_id),
  text_excerpt text not null default ''
);

create table wiki_citation(
  revision_id bigint not null references wiki_revision(revision_id) on delete cascade,
  statement_id bigint references wiki_statement(statement_id) on delete cascade,
  space_id bigint not null references space(space_id),
  passage_id bigint not null references passage(passage_id),
  source_version_id bigint not null references document_version(version_id),
  excerpt_revision int not null,
  cite_order int not null default 0,
  primary key (statement_id, passage_id)
);

create table lint_rule_set(
  space_id bigint not null references space(space_id),
  rule_code text not null,
  enabled boolean not null default true,
  severity lint_severity not null,
  params jsonb not null default '{}'::jsonb,
  revision int not null default 1,
  updated_by bigint,
  updated_at timestamptz not null default now(),
  primary key (space_id, rule_code)
);

create table lint_run(
  run_id bigint primary key,
  space_id bigint,
  rule_set_rev text not null,
  corpus_watermark bigint not null default 0,
  business_date date not null,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  status text not null default 'running' check (status in ('running','succeeded','failed')),
  stats jsonb not null default '{}'::jsonb
);

create table lint_finding(
  finding_id bigint generated always as identity primary key,
  dedupe_key text not null unique,
  rule_code text not null,
  severity lint_severity not null,
  space_id bigint not null references space(space_id),
  wiki_id bigint references wiki(wiki_id),
  revision_id bigint references wiki_revision(revision_id),
  statement_id bigint references wiki_statement(statement_id),
  target_slug text,
  evidence jsonb not null default '{}'::jsonb,
  state lint_state not null default 'open',
  owner_id bigint,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  last_run_id bigint references lint_run(run_id),
  occurrence_count int not null default 1,
  resolved_at timestamptz,
  resolution text
);

create table lint_finding_revision(
  finding_id bigint not null references lint_finding(finding_id) on delete cascade,
  revision_id bigint not null references wiki_revision(revision_id),
  primary key (finding_id, revision_id)
);

create table lint_waiver(
  waiver_id bigint generated always as identity primary key,
  dedupe_key text not null,
  reason text not null,
  waived_by bigint not null,
  waived_at timestamptz not null default now(),
  review_at date not null
);

create index wiki_link_target_idx on wiki_link(space_id, target_slug);
create index wiki_link_wiki_idx on wiki_link(wiki_id);
create index wiki_statement_key_idx on wiki_statement(subject_key, predicate, qualifier);
create index wiki_statement_revision_idx on wiki_statement(revision_id);
create index wiki_citation_version_idx on wiki_citation(source_version_id);
create index wiki_citation_passage_idx on wiki_citation(passage_id);
create index lint_finding_queue_idx on lint_finding(space_id, state, severity, last_seen_at desc);
create index lint_finding_revision_idx on lint_finding_revision(revision_id);

create or replace function lint_emit(
  p_run bigint, p_space bigint, p_key text, p_rule text, p_sev text,
  p_wiki bigint default null, p_rev bigint default null, p_stmt bigint default null,
  p_slug text default null, p_evidence jsonb default '{}'::jsonb, p_owner bigint default null,
  p_related_revisions bigint[] default '{}'
) returns void language sql as $$
  with emitted as (
    insert into lint_finding(dedupe_key,rule_code,severity,space_id,wiki_id,revision_id,
                             statement_id,target_slug,evidence,last_run_id,owner_id)
    values (p_key,p_rule,p_sev::lint_severity,p_space,p_wiki,p_rev,
            p_stmt,p_slug,p_evidence,p_run,p_owner)
    on conflict (dedupe_key) do update
    set last_seen_at = now(),
        last_run_id = excluded.last_run_id,
        occurrence_count = lint_finding.occurrence_count + 1,
        evidence = excluded.evidence,
        owner_id = coalesce(lint_finding.owner_id, excluded.owner_id),
        state = case when lint_finding.state='resolved' then 'open'::lint_state else lint_finding.state end,
        resolved_at = null,
        resolution = null
    returning finding_id
  )
  insert into lint_finding_revision(finding_id,revision_id)
  select emitted.finding_id, related.revision_id
  from emitted
  cross join unnest(array_prepend(p_rev,p_related_revisions)) related(revision_id)
  where related.revision_id is not null
  on conflict do nothing;
$$;

create or replace view v_lint_revision_hold as
select distinct related.revision_id
from lint_finding_revision related
join lint_finding finding using (finding_id)
where finding.state in ('open','acknowledged')
  and finding.severity in ('blocker','high');

create or replace view v_lint_open as
select f.*,
       wv.reason as waiver_reason,
       wv.review_at as waiver_review_at,
       (wv.waiver_id is not null
        and wv.review_at > (now() at time zone 'Asia/Shanghai')::date) as waived
from lint_finding f
left join lint_waiver wv on wv.dedupe_key = f.dedupe_key
where f.state in ('open','acknowledged');

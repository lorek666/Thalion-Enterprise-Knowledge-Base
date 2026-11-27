\set ON_ERROR_STOP on
create table document_version(
  version_id bigint primary key, document_id bigint not null,
  version_no int not null, content_hash text not null,
  superseded_at timestamptz, withdrawn_at timestamptz,
  unique(document_id,version_no));
create table passage(passage_id bigint primary key, version_id bigint not null);
create table wiki(wiki_id bigint primary key, slug text not null, published_revision_id bigint);
create table wiki_revision(
  revision_id bigint primary key, wiki_id bigint not null references wiki(wiki_id),
  input_manifest_complete boolean not null default false,
  unique(wiki_id, revision_id));
alter table wiki add foreign key(wiki_id, published_revision_id)
  references wiki_revision(wiki_id, revision_id);
create table wiki_statement(statement_id bigint primary key, revision_id bigint not null);
create table wiki_citation(statement_id bigint not null, passage_id bigint not null);
create table wiki_revision_input(
  revision_id bigint not null references wiki_revision(revision_id),
  version_id bigint not null references document_version(version_id),
  primary key(revision_id, version_id)
);

create table ingest_segment(
  segment_id bigint primary key,
  version_id bigint not null references document_version(version_id),
  segment_key text not null,
  content_hash text not null,
  unique(version_id, segment_key)
);
create table passage_segment(
  passage_id bigint primary key references passage(passage_id),
  segment_id bigint not null references ingest_segment(segment_id)
);
create table ingest_analysis(
  analysis_id bigint primary key,
  content_hash text not null,
  model_rev text not null,
  prompt_rev text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create table ingest_cache(
  cache_key text primary key,
  kind text not null check (kind in ('analysis','generation')),
  ref_id bigint not null,
  hit_count int not null default 0,
  updated_at timestamptz not null default now()
);
create table source_summary(
  version_id bigint primary key references document_version(version_id),
  wiki_id bigint not null,
  mode text not null check (mode in ('model','stub')),
  created_at timestamptz not null default now()
);

create or replace function ingest_key(p_kind text, p_payload text) returns text
language sql as $$
  select encode(sha256(convert_to(p_kind||'|'||p_payload,'UTF8')),'hex');
$$;

create or replace function ingest_plan(p_version bigint, p_model text, p_prompt text)
returns table(segment_key text, content_hash text, state text, analysis_id bigint, cache_hit boolean)
language sql as $$
  with dv as (select document_id, version_no from document_version where version_id=p_version),
  cur as (select * from ingest_segment where version_id=p_version),
  prev as (
    select s.* from ingest_segment s
    join document_version pv on pv.version_id=s.version_id
    join dv on pv.document_id=dv.document_id and pv.version_no=dv.version_no-1
  )
  select coalesce(cur.segment_key, prev.segment_key), cur.content_hash,
    case when cur.segment_id is null then 'removed'
         when prev.segment_id is null then 'new'
         when prev.content_hash <> cur.content_hash then 'changed'
         else 'unchanged' end,
    analysis.analysis_id,
    (analysis.analysis_id is not null)
  from cur full join prev using (segment_key)
  left join lateral (
    select ia.analysis_id from ingest_analysis ia
    where ia.content_hash=cur.content_hash
      and ia.model_rev=p_model and ia.prompt_rev=p_prompt
    order by ia.analysis_id desc limit 1
  ) analysis on true;
$$;

create or replace function ingest_affected(p_version bigint, p_model text, p_prompt text)
returns table(statement_id bigint, wiki_id bigint, segment_key text)
language sql as $$
  with plan as (
    select * from ingest_plan(p_version,p_model,p_prompt) where state in ('changed','removed')
  )
  select distinct c.statement_id, w.wiki_id, pl.segment_key
  from plan pl
  join document_version current_version on current_version.version_id=p_version
  join document_version previous_version
    on previous_version.document_id=current_version.document_id
   and previous_version.version_no=current_version.version_no-1
  join ingest_segment s on s.version_id=previous_version.version_id and s.segment_key=pl.segment_key
  join passage_segment ps on ps.segment_id=s.segment_id
  join wiki_citation c on c.passage_id=ps.passage_id
  join wiki_statement st on st.statement_id=c.statement_id
  join wiki_revision r on r.revision_id=st.revision_id
  join wiki w on w.wiki_id=r.wiki_id;
$$;

create or replace function ingest_inherit_inputs(p_revision bigint, p_base bigint) returns void
language plpgsql as $$
begin
  if not exists (
    select 1 from wiki_revision
    join wiki_revision_input using(revision_id)
    where revision_id=p_base and input_manifest_complete
  ) then
    raise exception 'base revision has no complete input manifest';
  end if;
  insert into wiki_revision_input(revision_id,version_id)
  select p_revision, version_id from wiki_revision_input where revision_id=p_base
  on conflict do nothing;
end $$;

create view v_ingest_available_wiki as
select page.wiki_id, revision.revision_id
from wiki page
join wiki_revision revision on revision.revision_id=page.published_revision_id
where revision.input_manifest_complete
  and exists (select 1 from wiki_revision_input where revision_id=revision.revision_id)
  and not exists (
    select 1 from wiki_revision_input input
    join document_version source using(version_id)
    where input.revision_id=revision.revision_id
      and (source.superseded_at is not null or source.withdrawn_at is not null)
  );

create or replace function ingest_cache_hit(p_key text) returns bigint
language plpgsql as $$
declare rid bigint;
begin
  update ingest_cache
  set hit_count=hit_count+1, updated_at=now()
  where cache_key=p_key
  returning ref_id into rid;
  return rid;
end $$;

create or replace function ingest_register(p_key text, p_kind text, p_ref bigint) returns void
language sql as $$
  insert into ingest_cache(cache_key,kind,ref_id) values (p_key,p_kind,p_ref)
  on conflict (cache_key) do update
  set ref_id=excluded.ref_id, updated_at=now();
$$;

create or replace function ensure_source_summary(p_version bigint) returns bigint
language plpgsql as $$
declare wid bigint;
begin
  insert into source_summary(version_id,wiki_id,mode)
  values (p_version, 900000+p_version, 'stub')
  on conflict (version_id) do nothing;
  select wiki_id into wid from source_summary where version_id=p_version;
  return wid;
end $$;

\set ON_ERROR_STOP on
create type compile_artifact as enum ('wiki','tree','pageindex','graph','timeline');
create type compile_rev_status as enum ('draft','published','retired');
create type compile_run_status as enum ('running','succeeded','failed','cancelled');
create type compile_output_status as enum ('candidate','accepted','rejected','skipped');

create table compile_template(
  template_id bigint generated always as identity primary key,
  space_id bigint not null references space(space_id),
  name text not null,
  artifact_kind compile_artifact not null default 'wiki',
  created_by bigint not null,
  created_at timestamptz not null default now(),
  unique (space_id, name)
);

create table compile_template_rev(
  template_rev_id bigint generated always as identity primary key,
  template_id bigint not null references compile_template(template_id),
  revision_no int not null,
  status compile_rev_status not null default 'draft',
  rules jsonb not null default '{}'::jsonb,
  prompt_rev text not null,
  model_rev text not null,
  output_contract jsonb not null default '{}'::jsonb,
  required_fields jsonb not null default '{}'::jsonb,
  forbidden_inferences text[] not null default '{}',
  checksum text not null,
  change_note text,
  published_by bigint,
  published_at timestamptz,
  unique (template_id, revision_no),
  unique (template_id, checksum)
);

create function compile_revision_immutable() returns trigger language plpgsql as $$
begin
  if old.status <> 'draft' then
    raise exception 'non-draft template revisions are immutable' using errcode = '55000';
  end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end $$;

create trigger compile_revision_immutable_trg
before update or delete on compile_template_rev
for each row execute function compile_revision_immutable();

create table compile_template_activation(
  activation_id bigint generated always as identity primary key,
  template_rev_id bigint not null references compile_template_rev(template_rev_id),
  activated_by bigint not null,
  reason text not null check (btrim(reason) <> ''),
  activated_at timestamptz not null default clock_timestamp()
);

create view v_compile_template_active as
select distinct on (r.template_id)
       r.template_id, a.activation_id, a.template_rev_id, a.activated_by, a.reason, a.activated_at
from compile_template_activation a join compile_template_rev r using (template_rev_id)
order by r.template_id, a.activation_id desc;

create function compile_activate(p_revision bigint, p_actor bigint, p_reason text)
returns bigint language plpgsql as $$
declare new_activation bigint;
begin
  perform 1
  from compile_template t join compile_template_rev r using (template_id)
  where r.template_rev_id = p_revision and r.status = 'published'
  for update of t;
  if not found then
    raise exception 'template revision % is not published', p_revision using errcode = '55000';
  end if;

  insert into compile_template_activation(template_rev_id, activated_by, reason)
  values (p_revision,p_actor,p_reason) returning activation_id into new_activation;
  return new_activation;
end $$;

create table compile_run(
  run_id bigint generated always as identity primary key,
  space_id bigint not null references space(space_id),
  template_rev_id bigint not null references compile_template_rev(template_rev_id),
  scope_type text not null check (scope_type in ('space','wiki')),
  scope_id bigint,
  corpus_watermark bigint not null,
  status compile_run_status not null default 'running',
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  stats jsonb not null default '{}'::jsonb
);

create table compile_output(
  output_id bigint generated always as identity primary key,
  run_id bigint not null references compile_run(run_id),
  wiki_id bigint not null references wiki(wiki_id),
  base_revision_id bigint references wiki_revision(revision_id),
  candidate_revision_id bigint references wiki_revision(revision_id),
  status compile_output_status not null default 'candidate',
  diff jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (run_id, wiki_id)
);

create or replace function compile_plan(
  p_template_rev bigint,
  p_scope_type text default 'space',
  p_scope_id bigint default null
) returns table(wiki_id bigint, base_revision_id bigint, reason text)
language sql as $$
  select w.wiki_id, w.published_revision_id, 'template_replay'::text
  from wiki w
  join wiki_revision r on r.revision_id = w.published_revision_id
  join compile_template_rev tr on tr.template_rev_id = p_template_rev
  where w.status = 'published'
    and r.compile_template_id = tr.template_id
    and ((p_scope_type = 'space' and w.space_id = p_scope_id)
      or (p_scope_type = 'wiki'  and w.wiki_id  = p_scope_id))
    and not exists (
      select 1 from compile_output o
      join compile_run cr on cr.run_id = o.run_id
      where o.wiki_id = w.wiki_id
        and cr.template_rev_id = p_template_rev
        and o.base_revision_id = w.published_revision_id
        and o.status in ('candidate','accepted'));
$$;

create or replace function compile_diff(
  p_base bigint, p_candidate bigint, p_required jsonb default '{}'::jsonb
) returns jsonb language sql as $$
  with b as (select * from wiki_statement where revision_id = p_base),
       c as (select * from wiki_statement where revision_id = p_candidate),
       citation_sets as (
         select revision_id, statement_id, jsonb_agg(distinct ref order by ref) as citations
         from (
           select revision_id, statement_id, jsonb_build_object(
             'source_version_id', source_version_id, 'passage_id', passage_id,
             'excerpt_revision', excerpt_revision
           ) as ref
           from wiki_citation where revision_id in (p_base,p_candidate)
         ) refs
         group by revision_id, statement_id),
       matched as (
         select b.statement_id as old_id, c.statement_id as new_id
         from b join c
           on b.subject_key = c.subject_key and b.predicate = c.predicate
          and b.qualifier is not distinct from c.qualifier and b.valid_from = c.valid_from),
       added as (
         select statement_id from c
         where fingerprint not in (select fingerprint from b)),
       removed as (
         select statement_id from b
         where fingerprint not in (select fingerprint from c)),
       changed as (
         select c.statement_id, c.subject_key, c.predicate, c.qualifier,
                b.value_num old_num, c.value_num new_num,
                b.value_code old_code, c.value_code new_code,
                b.unit old_unit, c.unit new_unit
         from matched m
         join b on b.statement_id = m.old_id
         join c on c.statement_id = m.new_id
         where b.fingerprint <> c.fingerprint),
       citation_changed as (
         select m.new_id as statement_id, m.old_id as old_statement_id,
                coalesce(old_refs.citations,'[]'::jsonb) as old_citations,
                coalesce(new_refs.citations,'[]'::jsonb) as new_citations
         from matched m
         left join citation_sets old_refs
           on old_refs.revision_id = p_base and old_refs.statement_id = m.old_id
         left join citation_sets new_refs
           on new_refs.revision_id = p_candidate and new_refs.statement_id = m.new_id
         where old_refs.citations is distinct from new_refs.citations),
       missing as (
         select s.statement_id, s.statement_type, f.field
         from c s
         join jsonb_each(p_required) kv on kv.key = s.statement_type
         cross join jsonb_array_elements_text(kv.value) f(field)
         where (f.field = 'unit'       and s.unit is null)
            or (f.field = 'valid_from' and s.valid_from is null)
            or (f.field = 'value'      and s.value_num is null and s.value_code is null)),
       uncited as (
         select s.statement_id from c s
         where not exists (
           select 1 from citation_sets x where x.revision_id = p_candidate and x.statement_id = s.statement_id))
  select jsonb_build_object(
    'added',   (select count(*) from added),
    'removed', (select count(*) from removed),
    'changed', (select count(*) from changed),
    'changed_detail', (select coalesce(jsonb_agg(to_jsonb(changed)),'[]'::jsonb) from changed),
    'citation_changed', (select count(*) from citation_changed),
    'citation_changed_detail', (
      select coalesce(jsonb_agg(to_jsonb(citation_changed) order by statement_id, old_statement_id),'[]'::jsonb)
      from citation_changed),
    'missing_required', (select coalesce(jsonb_agg(to_jsonb(missing)),'[]'::jsonb) from missing),
    'uncited', (select count(*) from uncited),
    'publishable',
      ((select count(*) from missing) = 0 and (select count(*) from uncited) = 0
       and (select count(*) from added) + (select count(*) from removed)
         + (select count(*) from changed) + (select count(*) from citation_changed) > 0));
$$;

create or replace function compile_accept(p_output bigint) returns void
language plpgsql as $$
declare o compile_output;
begin
  select * into o from compile_output where output_id = p_output for update;
  if not found then raise exception 'output % not found', p_output; end if;
  if o.status <> 'candidate' then raise exception 'only candidate can be accepted'; end if;
  if coalesce((o.diff->>'publishable')::boolean, false) is not true then
    raise exception 'candidate has blocking diff: %', o.diff;
  end if;
  update wiki_revision set status = 'pending'
  where revision_id = o.candidate_revision_id and status = 'draft';
  update compile_output set status = 'accepted' where output_id = p_output;
end $$;

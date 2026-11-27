\set ON_ERROR_STOP on
create type wiki_status as enum ('draft','pending','published','suspended');
create table space(space_id bigint primary key, name text not null);
create table wiki(
  wiki_id bigint primary key, space_id bigint references space(space_id),
  slug text not null, title text not null, status wiki_status not null default 'draft',
  published_revision_id bigint, unique(space_id,slug));
create table wiki_revision(
  revision_id bigint primary key, wiki_id bigint references wiki(wiki_id),
  version_no int not null, title text not null, body_md text not null, status wiki_status not null,
  compile_template_id bigint, compile_template_rev text, published_at timestamptz,
  unique(wiki_id,version_no));
create table wiki_statement(
  statement_id bigint primary key, revision_id bigint references wiki_revision(revision_id),
  statement_type text not null default 'amount', subject_key text not null, predicate text not null, qualifier text default '',
  value_num numeric(18,4), value_code text, unit text,
  valid_from date not null, valid_to date, fingerprint text not null);
create table wiki_citation(
  revision_id bigint references wiki_revision(revision_id),
  statement_id bigint references wiki_statement(statement_id),
  passage_id bigint not null, source_version_id bigint not null,
  excerpt_revision int not null default 1);

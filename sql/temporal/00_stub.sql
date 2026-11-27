\set ON_ERROR_STOP on
create table space(space_id bigint primary key, name text not null);
create table wiki(
  wiki_id bigint primary key, space_id bigint references space(space_id),
  slug text not null, status text not null default 'published',
  published_revision_id bigint, unique(space_id,slug));
create table wiki_revision(
  revision_id bigint primary key, wiki_id bigint references wiki(wiki_id),
  version_no int not null, status text not null,
  published_at timestamptz, retired_at timestamptz, withdrawn_at timestamptz,
  unique(wiki_id,version_no));
create table wiki_statement(
  statement_id bigint primary key, revision_id bigint references wiki_revision(revision_id),
  statement_type text default 'amount', subject_key text not null, predicate text not null,
  qualifier text default '', value_num numeric(18,4), value_code text, value_text text,
  unit text, valid_from date not null, valid_to date, superseded_by bigint, text_excerpt text default '');
create table wiki_citation(
  statement_id bigint references wiki_statement(statement_id),
  passage_id bigint, cite_order int default 0);

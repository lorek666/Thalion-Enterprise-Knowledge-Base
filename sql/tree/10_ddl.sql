\set ON_ERROR_STOP on
create table doc_tree_node(
  node_id bigint primary key,
  version_id bigint not null references document_version(version_id),
  parent_id bigint references doc_tree_node(node_id),
  depth int not null,
  order_no int not null,
  node_type text not null check (node_type in ('document','chapter','section','table','figure','appendix')),
  title text not null,
  path text not null,
  page_from int,
  page_to int,
  search_text text not null default '',
  tsv tsvector generated always as (to_tsvector('simple', search_text)) stored,
  unique (version_id, path)
);

create table passage_node(
  passage_id bigint not null references passage(passage_id),
  node_id bigint not null references doc_tree_node(node_id),
  primary key (passage_id, node_id)
);

create index doc_tree_version_idx on doc_tree_node(version_id, node_type);
create index doc_tree_page_idx on doc_tree_node(version_id, page_from, page_to);
create index doc_tree_tsv_idx on doc_tree_node using gin(tsv);

create or replace function tree_route(
  p_version bigint, p_query text, p_limit int default 3, p_page int default null
) returns table(node_id bigint, score real, rank int)
language sql as $$
  with q as (select plainto_tsquery('simple', p_query) tsq),
       cand as (
         select n.node_id, ts_rank_cd(n.tsv, q.tsq, 32) as score, n.depth
         from doc_tree_node n, q
         where n.version_id = p_version
           and n.tsv @@ q.tsq
           and (p_page is null or p_page between n.page_from and n.page_to)
       )
  select c.node_id, c.score,
         row_number() over (order by c.score desc, c.depth asc, c.node_id)::int
  from cand c
  order by c.score desc, c.depth asc, c.node_id
  limit p_limit;
$$;

create or replace function nodes_at_page(p_version bigint, p_page int)
returns table(node_id bigint, depth int, title text)
language sql as $$
  select n.node_id, n.depth, n.title
  from doc_tree_node n
  where n.version_id = p_version
    and n.node_type <> 'document'
    and p_page between n.page_from and n.page_to
  order by n.depth desc, n.order_no;
$$;

create table retrieval_eval_query(
  query_id bigint primary key,
  version_id bigint not null references document_version(version_id),
  query_text text not null,
  query_tokens text not null,
  gold_node_ids bigint[] not null,
  gold_passage_ids bigint[] not null
);

create table retrieval_sample_input(
  query_id bigint primary key references retrieval_eval_query(query_id),
  keyword_ids bigint[] not null,
  vector_ids bigint[] not null
);

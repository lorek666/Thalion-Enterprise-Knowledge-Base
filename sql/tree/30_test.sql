\set ON_ERROR_STOP on
-- T1 文本路由：上海住宿题应命中表格节
select n.node_id, n.title, r.score::numeric(10,6) score, r.rank
from tree_route(1,'上海 住宿 上限',5) r join doc_tree_node n using(node_id);

-- T2 版本隔离
select n.version_id, n.title, r.rank
from tree_route(2,'供应商 准入',5) r join doc_tree_node n using(node_id);

-- T3 页码约束
select n.node_id, n.title, n.page_from, n.page_to
from tree_route(1,'上海 住宿 上限',5,3) r join doc_tree_node n using(node_id);

-- T4 页码回退（该页没有词项命中时）
select * from nodes_at_page(1,3);

create view retrieval_run as
with routed as (
  select q.query_id, route.node_id, route.rank
  from retrieval_eval_query q
  cross join lateral tree_route(q.version_id, q.query_tokens, 3) route
), sample as (
  select s.query_id, input.channel, hits.passage_id, hits.rank
  from retrieval_sample_input s
  cross join lateral (values ('keyword',s.keyword_ids), ('vector',s.vector_ids)) input(channel, ids)
  cross join lateral unnest(input.ids) with ordinality hits(passage_id, rank)
), expanded as (
  select r.query_id, 'tree' as channel, hit.passage_id,
         (r.rank - 1) * 5 + row_number() over (
           partition by r.query_id, r.node_id order by hit.passage_id) as rank
  from routed r
  join retrieval_eval_query q on q.query_id = r.query_id
  cross join lateral (
    select pn.passage_id
    from passage_node pn
    join passage p on p.passage_id = pn.passage_id and p.version_id = q.version_id
    where pn.node_id = r.node_id
    order by pn.passage_id
    limit 5
  ) hit
), inputs as (
  select * from sample
  union all
  select * from expanded
), best as (
  select i.query_id, i.channel, i.passage_id, min(i.rank) as rank
  from inputs i
  join retrieval_eval_query q using (query_id)
  join passage p on p.passage_id = i.passage_id and p.version_id = q.version_id
  group by i.query_id, i.channel, i.passage_id
), scored as (
  select b.query_id, modes.mode, b.passage_id, sum(1.0 / (60 + b.rank)) as score
  from best b
  cross join (values ('two_way'), ('three_way')) modes(mode)
  where modes.mode = 'three_way' or b.channel <> 'tree'
  group by b.query_id, modes.mode, b.passage_id
)
select q.query_id, modes.mode,
       case when modes.mode = 'three_way'
            then array(select r.node_id from routed r where r.query_id = q.query_id order by r.rank)
            else '{}'::bigint[] end as node_ids,
       array(select s.passage_id from scored s where s.query_id = q.query_id and s.mode = modes.mode
             order by s.score desc, s.passage_id limit 5) as passage_ids
from retrieval_eval_query q
cross join (values ('two_way'), ('three_way')) modes(mode);

select r.mode,
  round(avg(cardinality(array(select unnest(r.passage_ids) intersect select unnest(q.gold_passage_ids)))::numeric
      / cardinality(q.gold_passage_ids)),3) as evidence_recall,
  avg((q.gold_passage_ids <@ r.passage_ids)::int) as full_evidence
from retrieval_run r join retrieval_eval_query q using(query_id)
group by r.mode order by r.mode;

select avg((r.node_ids && q.gold_node_ids)::int) as tree_section_hit
from retrieval_run r join retrieval_eval_query q using (query_id)
where r.mode = 'three_way';

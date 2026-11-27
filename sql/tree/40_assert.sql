\set ON_ERROR_STOP on

do $$
begin
  if exists (
    select 1
    from retrieval_eval_query q
    cross join lateral unnest(q.gold_passage_ids) as gold(passage_id)
    left join passage p using (passage_id)
    where p.version_id is distinct from q.version_id
  ) then
    raise exception 'gold passage does not belong to the query version';
  end if;

  if (select gold_passage_ids from retrieval_eval_query where query_id = 2)
       is distinct from array[3]::bigint[] then
    raise exception 'approval question must use passage 3';
  end if;

  if exists (
    select 1
    from retrieval_eval_query q
    cross join lateral unnest(q.gold_node_ids) as gold(node_id)
    left join doc_tree_node t using (node_id)
    where t.version_id is distinct from q.version_id
  ) then
    raise exception 'gold node does not belong to the query version';
  end if;
end $$;

do $$
begin
  if (select node_id from tree_route(1,'上海 住宿 上限') where rank = 1)
       is distinct from 4::bigint then
    raise exception 'expected table node 4 first';
  end if;

  if array(select node_id from tree_route(2,'供应商 准入') order by rank)
       is distinct from array[11]::bigint[]
     or exists(select 1 from tree_route(1,'供应商 准入')) then
    raise exception 'tree route did not isolate the procurement version';
  end if;

  if array(select node_id from tree_route(1,'上海 住宿 上限',3,3) order by rank)
       is distinct from array[4]::bigint[]
     or exists(select 1 from tree_route(1,'上海 住宿 上限',3,4)) then
    raise exception 'route did not enforce the page filter';
  end if;

  if array(select node_id from nodes_at_page(1,3) order by depth desc)
       is distinct from array[4,3]::bigint[] then
    raise exception 'page fallback did not return the table and chapter';
  end if;

  if (select passage_ids from retrieval_run where query_id = 2 and mode = 'two_way')
       is distinct from array[1,4]::bigint[] then
    raise exception 'RRF must count only the best rank per channel and exclude other versions';
  end if;

  if (select node_ids from retrieval_run where query_id = 2 and mode = 'three_way')
       is distinct from array[5]::bigint[] then
    raise exception 'approval question did not route to the approval chapter';
  end if;
end $$;

begin;
update doc_tree_node set search_text = '' where node_id = 5;
do $$
begin
  if (select node_ids from retrieval_run where query_id = 2 and mode = 'three_way')
       is distinct from '{}'::bigint[]
     or (select passage_ids from retrieval_run where query_id = 2 and mode = 'three_way')
       is distinct from (select passage_ids from retrieval_run where query_id = 2 and mode = 'two_way') then
    raise exception 'an empty tree route must fall back to the two-way results';
  end if;
end $$;
rollback;

select 'tree assertions ok' as result;

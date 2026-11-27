\set ON_ERROR_STOP on
create or replace function wiki_resolve(
  p_space bigint, p_subject text, p_predicate text, p_qualifier text, p_business date
) returns table(
  status text, statement_id bigint, revision_id bigint, wiki_id bigint, slug text,
  value_num numeric, value_code text, unit text, valid_from date, valid_to date,
  passage_ids bigint[], statement_type text, value_text text
) language sql as $$
  with recorded as (
    select s.statement_id, s.revision_id, w.wiki_id, w.slug,
           s.statement_type, s.value_num, s.value_code, s.value_text, s.unit,
           s.valid_from, s.valid_to, s.superseded_by, r.status as revision_status,
           w.status as page_status, r.withdrawn_at,
           coalesce((select array_agg(c.passage_id order by c.cite_order)
                     from wiki_citation c where c.statement_id=s.statement_id),'{}'::bigint[]) passage_ids
    from wiki_statement s
    join wiki_revision r on r.revision_id=s.revision_id
    join wiki w on w.wiki_id=r.wiki_id
    where w.space_id=p_space
      and s.subject_key=p_subject and s.predicate=p_predicate and s.qualifier=p_qualifier
      and r.published_at is not null
      and r.status in ('published','retired','suspended')
  ),
  selected as (
    select original.* from recorded original
    where original.valid_from <= p_business
      and (original.valid_to is null or p_business < original.valid_to)
      and not exists (
        select 1 from recorded replacement
        where replacement.statement_id=original.superseded_by
          and replacement.valid_from <= p_business
      )
  ),
  live as (
    select * from selected where withdrawn_at is null
      and revision_status in ('published','retired') and page_status='published'
  ),
  vals as (select distinct statement_type,value_num,value_code,value_text,unit from live)
  select case when (select count(*) from vals)>1 then 'ambiguous' else 'applicable' end,
         live.statement_id, live.revision_id, live.wiki_id, live.slug,
         live.value_num, live.value_code, live.unit, live.valid_from, live.valid_to,
         live.passage_ids, live.statement_type, live.value_text
  from live
  union all
  select case when exists(select 1 from selected where withdrawn_at is not null) then 'withdrawn'
              when exists(select 1 from selected) then 'suspended'
              else 'no_rule' end,
         null::bigint, null::bigint, null::bigint, null::text, null::numeric,
         null::text, null::text, null::date, null::date, '{}'::bigint[], null::text, null::text
  where not exists(select 1 from live);
$$;

create or replace function wiki_asserted_as_of(
  p_space bigint, p_subject text, p_predicate text, p_qualifier text, p_as_of timestamptz
) returns table(
  status text, statement_id bigint, revision_id bigint, wiki_id bigint,
  value_num numeric, value_code text, unit text,
  published_at timestamptz, withdrawn_at timestamptz, statement_type text, value_text text
) language sql as $$
  with cand as (
    select s.statement_id, s.revision_id, w.wiki_id,
           s.statement_type, s.value_num, s.value_code, s.value_text, s.unit,
           r.published_at, r.withdrawn_at
    from wiki_statement s
    join wiki_revision r on r.revision_id=s.revision_id
    join wiki w on w.wiki_id=r.wiki_id
    where w.space_id=p_space
      and s.subject_key=p_subject and s.predicate=p_predicate and s.qualifier=p_qualifier
      and r.published_at <= p_as_of
      and (r.retired_at is null or r.retired_at > p_as_of)
      and (r.withdrawn_at is null or r.withdrawn_at > p_as_of)
      and r.status in ('published','retired','suspended')
  ),
  vals as (select distinct statement_type,value_num,value_code,value_text,unit from cand)
  select case when (select count(*) from vals)>1 then 'ambiguous' else 'asserted' end,
         cand.statement_id, cand.revision_id, cand.wiki_id, cand.value_num, cand.value_code, cand.unit,
         cand.published_at, cand.withdrawn_at, cand.statement_type, cand.value_text
  from cand
  union all
  select 'nothing_recorded'::text, null::bigint, null::bigint, null::bigint,
         null::numeric, null::text, null::text, null::timestamptz, null::timestamptz, null::text, null::text
  where not exists(select 1 from cand);
$$;

\set ON_ERROR_STOP on
set timezone = 'Asia/Shanghai';

insert into lint_run(run_id,space_id,rule_set_rev,corpus_watermark,business_date)
values (:run_id,:space_id,'rs-2026-11-20',1,:'biz_date'::date);

-- L1 链接目标缺失/未发布；同一目标被 >=3 个页面引用升级为缺页
with refs as (
  select l.space_id, l.target_slug,
         count(*)::int refs, count(distinct l.wiki_id)::int pages,
         min(l.wiki_id) wiki_id, min(l.revision_id) revision_id,
         jsonb_agg(distinct l.line_no order by l.line_no) lines
  from wiki_link l
  join wiki_revision r on r.revision_id=l.revision_id and r.status='published'
  where l.space_id=:space_id and l.link_kind='wikilink'
  group by l.space_id,l.target_slug
),
resolved as (
  select r.*, t.status target_status
  from refs r left join wiki t on t.space_id=r.space_id and t.slug=r.target_slug
),
cfg as (
  select coalesce((params->>'min_pages')::int,3) min_pages
  from lint_rule_set where space_id=:space_id and rule_code='PAGE_MISSING'
),
classified as (
  select s.*,
    (case when s.target_status is null and s.pages>=(select min_pages from cfg) then 'PAGE_MISSING'
          when s.target_status is null then 'LINK_BROKEN'
          else 'LINK_UNPUBLISHED' end) rule_code,
    (case when s.target_status is null and s.pages>=(select min_pages from cfg) then 'normal'
          when s.target_status is null then 'high'
          else 'normal' end) severity
  from resolved s
  where s.target_status is distinct from 'published'
)
select lint_emit(p_run=>:run_id, p_space=>:space_id,
  p_key=>encode(sha256(convert_to('LINK|'||c.space_id::text||'|'||c.target_slug,'UTF8')),'hex'),
  p_rule=>c.rule_code, p_sev=>c.severity,
  p_wiki=>c.wiki_id, p_rev=>c.revision_id, p_slug=>c.target_slug,
  p_evidence=>jsonb_build_object('refs',c.refs,'pages',c.pages,'lines',c.lines,
                     'target_state',coalesce(c.target_status::text,'missing')))
from classified c
where exists (select 1 from lint_rule_set rs
              where rs.space_id=:space_id and rs.rule_code=c.rule_code and rs.enabled);

-- L2 孤儿页：已发布、非目录页，无任何已发布页链入
select lint_emit(p_run=>:run_id, p_space=>:space_id,
  p_key=>encode(sha256(convert_to('ORPHAN|'||w.wiki_id::text,'UTF8')),'hex'),
  p_rule=>'PAGE_ORPHAN', p_sev=>'normal',
  p_wiki=>w.wiki_id, p_rev=>w.published_revision_id, p_slug=>w.slug,
  p_evidence=>jsonb_build_object('slug',w.slug,'page_type',w.page_type))
from wiki w
where w.space_id=:space_id and w.status='published'
  and w.page_type not in ('index','overview')
  and exists (select 1 from lint_rule_set rs where rs.space_id=:space_id and rs.rule_code='PAGE_ORPHAN' and rs.enabled)
  and not exists (
    select 1 from wiki_link l
    join wiki_revision r on r.revision_id=l.revision_id and r.status='published'
    where l.space_id=w.space_id and l.target_slug=w.slug and l.wiki_id<>w.wiki_id);

-- L2b 有内容但无出链（默认关闭）
select lint_emit(p_run=>:run_id, p_space=>:space_id,
  p_key=>encode(sha256(convert_to('NOOUT|'||w.wiki_id::text,'UTF8')),'hex'),
  p_rule=>'PAGE_NO_OUTLINK', p_sev=>'low',
  p_wiki=>w.wiki_id, p_rev=>w.published_revision_id, p_slug=>w.slug,
  p_evidence=>jsonb_build_object('slug',w.slug,'statements',n.cnt))
from wiki w
join lateral (select count(*)::int cnt from wiki_statement s
              where s.revision_id=w.published_revision_id) n on true
where w.space_id=:space_id and w.status='published' and w.page_type='topic'
  and exists (select 1 from lint_rule_set rs where rs.space_id=:space_id and rs.rule_code='PAGE_NO_OUTLINK' and rs.enabled)
  and n.cnt >= coalesce((select (params->>'min_statements')::int from lint_rule_set
                         where space_id=:space_id and rule_code='PAGE_NO_OUTLINK'),3)
  and exists (select 1 from wiki_link l where l.space_id=w.space_id and l.target_slug=w.slug and l.wiki_id<>w.wiki_id)
  and not exists (select 1 from wiki_link l where l.revision_id=w.published_revision_id and l.link_kind='wikilink');

-- L3 引用已撤回/已过期原件；撤回优先
with hits as (
  select w.space_id,w.wiki_id,w.published_revision_id,
         v.version_id,v.version_label,v.status,v.valid_to,c.statement_id,
         (case when v.status='withdrawn' then 'CITE_WITHDRAWN' else 'CITE_EXPIRED' end) rule_code
  from wiki_citation c
  join wiki_revision r on r.revision_id=c.revision_id and r.status='published'
  join wiki w on w.published_revision_id=r.revision_id
  join document_version v on v.version_id=c.source_version_id
  where w.space_id=:space_id
    and (w.valid_to is null or w.valid_to > :'biz_date'::date)
    and (v.status='withdrawn' or (v.valid_to is not null and v.valid_to <= :'biz_date'::date))
)
select lint_emit(p_run=>:run_id, p_space=>:space_id,
  p_key=>encode(sha256(convert_to('CITEREF|'||h.wiki_id::text||'|'||h.version_id::text,'UTF8')),'hex'),
  p_rule=>h.rule_code, p_sev=>(case when h.rule_code='CITE_WITHDRAWN' then 'blocker' else 'high' end),
  p_wiki=>h.wiki_id, p_rev=>h.published_revision_id,
  p_evidence=>jsonb_build_object('version_id',h.version_id,'version_label',h.version_label,
                     'version_status',h.status,'valid_to',h.valid_to,
                     'statements',jsonb_agg(distinct h.statement_id)))
from hits h
where exists (select 1 from lint_rule_set rs
              where rs.space_id=:space_id and rs.rule_code=h.rule_code and rs.enabled)
group by h.space_id,h.wiki_id,h.published_revision_id,h.version_id,h.version_label,h.status,h.valid_to,h.rule_code;

-- L3b 引用旧转录修订
select lint_emit(p_run=>:run_id, p_space=>:space_id,
  p_key=>encode(sha256(convert_to('EXSTALE|'||w.wiki_id::text||'|'||c.passage_id::text,'UTF8')),'hex'),
  p_rule=>'CITE_EXCERPT_STALE', p_sev=>'high',
  p_wiki=>w.wiki_id, p_rev=>w.published_revision_id,
  p_evidence=>jsonb_build_object('passage_id',c.passage_id,
                     'cited_excerpt_revision',min(c.excerpt_revision),
                     'current_excerpt_revision',min(p.current_excerpt_revision),
                     'statements',jsonb_agg(distinct c.statement_id)))
from wiki_citation c
join wiki_revision r on r.revision_id=c.revision_id and r.status='published'
join wiki w on w.published_revision_id=r.revision_id
join passage p on p.passage_id=c.passage_id
where w.space_id=:space_id
  and p.current_excerpt_revision<>c.excerpt_revision
  and exists (select 1 from lint_rule_set rs where rs.space_id=:space_id and rs.rule_code='CITE_EXCERPT_STALE' and rs.enabled)
group by w.space_id,w.wiki_id,w.published_revision_id,c.passage_id;

-- L4 当前页结论已过有效期
select lint_emit(p_run=>:run_id, p_space=>:space_id,
  p_key=>encode(sha256(convert_to('STEXP|'||s.statement_id::text,'UTF8')),'hex'),
  p_rule=>'STATEMENT_EXPIRED', p_sev=>'high',
  p_wiki=>w.wiki_id, p_rev=>s.revision_id, p_stmt=>s.statement_id, p_slug=>w.slug,
  p_evidence=>jsonb_build_object('slug',w.slug,'predicate',s.predicate,'valid_to',s.valid_to,
                     'value_num',s.value_num,'value_code',s.value_code,'unit',s.unit))
from wiki_statement s
join wiki_revision r on r.revision_id=s.revision_id and r.status='published'
join wiki w on w.published_revision_id=r.revision_id
where w.space_id=:space_id and w.status='published'
  and (w.valid_to is null or w.valid_to > :'biz_date'::date)
  and s.valid_to is not null and s.valid_to <= :'biz_date'::date
  and exists (select 1 from lint_rule_set rs where rs.space_id=:space_id and rs.rule_code='STATEMENT_EXPIRED' and rs.enabled);

-- L4b 结论已登记替代稿
select lint_emit(p_run=>:run_id, p_space=>:space_id,
  p_key=>encode(sha256(convert_to('STSUP|'||s.statement_id::text,'UTF8')),'hex'),
  p_rule=>'STATEMENT_SUPERSEDED', p_sev=>'normal',
  p_wiki=>w.wiki_id, p_rev=>s.revision_id, p_stmt=>s.statement_id, p_slug=>w.slug,
  p_evidence=>jsonb_build_object('slug',w.slug,'predicate',s.predicate,'superseded_by',s.superseded_by))
from wiki_statement s
join wiki_revision r on r.revision_id=s.revision_id and r.status='published'
join wiki w on w.published_revision_id=r.revision_id
where w.space_id=:space_id and w.status='published'
  and (w.valid_to is null or w.valid_to > :'biz_date'::date)
  and s.superseded_by is not null
  and exists (select 1 from lint_rule_set rs where rs.space_id=:space_id and rs.rule_code='STATEMENT_SUPERSEDED' and rs.enabled);

-- L5 数值冲突/单位不一致：同 subject+predicate+qualifier 且有效期重叠
with live as (
  select s.statement_id,s.revision_id,s.subject_key,s.predicate,s.qualifier,
         s.value_num,s.value_code,s.unit,s.valid_from,s.valid_to,
         w.space_id,w.wiki_id,w.slug
  from wiki_statement s
  join wiki_revision r on r.revision_id=s.revision_id and r.status='published'
  join wiki w on w.published_revision_id=r.revision_id
  where w.space_id=:space_id and w.status='published'
    and (w.valid_to is null or w.valid_to > :'biz_date'::date)
),
pairs as (
  select a.space_id,a.wiki_id a_wiki,b.wiki_id b_wiki,a.slug a_slug,b.slug b_slug,
         a.revision_id a_rev,b.revision_id b_rev,
         a.statement_id a_id,b.statement_id b_id,a.subject_key,a.predicate,a.qualifier,
         a.value_num a_num,b.value_num b_num,a.value_code a_code,b.value_code b_code,
         a.unit a_unit,b.unit b_unit
  from live a
  join live b on a.space_id=b.space_id and a.subject_key=b.subject_key
   and a.predicate=b.predicate and a.qualifier=b.qualifier
   and a.statement_id<b.statement_id
   and daterange(a.valid_from,coalesce(a.valid_to,'infinity'::date),'[)')
    && daterange(b.valid_from,coalesce(b.valid_to,'infinity'::date),'[)')
   and (a.value_num is distinct from b.value_num
        or a.value_code is distinct from b.value_code
        or a.unit is distinct from b.unit)
),
classified as (
  select p.*,
    (case when p.a_unit is distinct from p.b_unit then 'UNIT_MISMATCH' else 'STATEMENT_CONFLICT' end) rule_code
  from pairs p
)
select lint_emit(p_run=>:run_id, p_space=>:space_id,
  p_key=>encode(sha256(convert_to('PAIR|'||p.a_id::text||'|'||p.b_id::text,'UTF8')),'hex'),
  p_rule=>p.rule_code, p_sev=>'blocker',
  p_wiki=>p.a_wiki, p_rev=>p.a_rev, p_stmt=>p.a_id, p_slug=>p.a_slug,
  p_related_revisions=>array[p.b_rev],
  p_evidence=>jsonb_build_object(
    'a',jsonb_build_object('wiki_id',p.a_wiki,'revision_id',p.a_rev,'statement_id',p.a_id,
                           'wiki',p.a_slug,'value',p.a_num,'code',p.a_code,'unit',p.a_unit),
    'b',jsonb_build_object('wiki_id',p.b_wiki,'revision_id',p.b_rev,'statement_id',p.b_id,
                           'wiki',p.b_slug,'value',p.b_num,'code',p.b_code,'unit',p.b_unit),
    'subject',p.subject_key,'predicate',p.predicate,'qualifier',p.qualifier))
from classified p
where exists (select 1 from lint_rule_set rs
              where rs.space_id=:space_id and rs.rule_code=p.rule_code and rs.enabled);

-- 收尾：标记成功，只关闭同日、本轮实际执行且未复现的发现
update lint_run set status='succeeded', finished_at=now() where run_id=:run_id;

update lint_finding f
set state='resolved', resolved_at=now(), resolution='not_reproduced'
where f.space_id=:space_id
  and f.state in ('open','acknowledged')
  and f.last_run_id is distinct from :run_id
  and f.first_seen_at < (select started_at from lint_run where run_id=:run_id)
  and coalesce((select business_date from lint_run where run_id=f.last_run_id), :'biz_date'::date)
      = (select business_date from lint_run where run_id=:run_id)
  and exists (select 1 from lint_rule_set rs
              where rs.space_id=:space_id and rs.rule_code=f.rule_code and rs.enabled);

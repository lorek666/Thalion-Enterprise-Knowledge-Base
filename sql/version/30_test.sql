\set ON_ERROR_STOP on

-- T1 审计：当前发布版里仍由 Agent 写入的陈述
select w.slug, r.version_no, r.edit_source, r.approved_by,
       count(*) filter (where s.last_edit_source='agent') agent_statements
from wiki w
join wiki_revision r on r.revision_id=w.published_revision_id
left join wiki_statement s on s.revision_id=r.revision_id
group by 1,2,3,4 order by 1;

-- T2 正文不可改、不可删
do $$
begin
  begin
    update wiki_revision set body_md='hack' where revision_id=4;
    raise exception 'guard did not block body update';
  exception when others then
    if position('不可修改' in sqlerrm)=0 then raise; end if;
  end;
  begin
    delete from wiki_revision where revision_id=4;
    raise exception 'guard did not block delete';
  exception when others then
    if position('禁止删除' in sqlerrm)=0 then raise; end if;
  end;
end $$;
begin;
update wiki_revision set status='pending' where revision_id=3;
update wiki_revision set status='published', approved_by=100, approved_at=now(),
                         approval_note='确认差旅修订', published_at=now()
where revision_id=3;
do $$
begin
  if not exists (
    select 1 from wiki_revision where revision_id=3 and status='published'
      and approved_by=100 and approval_note='确认差旅修订' and published_at is not null
  ) then
    raise exception 'first publication did not record its approval';
  end if;
end $$;
rollback;
select 'T2 ok' as result;

-- T3 自批与回滚来源约束
do $$
begin
  begin
    insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id,approved_by,approved_at)
    values (90,1,90,'self','x','published','user',7,7,now());
    raise exception 'self approval not blocked';
  exception when check_violation then null;
  end;
  begin
    insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source)
    values (91,1,91,'revert-no-src','x','draft','revert');
    raise exception 'revert without source not blocked';
  exception when check_violation then null;
  end;
end $$;
select 'T3 ok' as result;

-- T4 保留候选：修订 1/4 分别作为陈述来源/回滚基础保留
select * from prune_candidates(1) order by version_no;

-- T4b 人工版本配额：keep_user=2，4 个草稿裁剪最旧 2 个
select count(*) as user_quota_candidates, min(version_no) oldest, max(version_no) newest from prune_candidates(4);

-- T5 保全：整页不裁剪
select count(*) as held_candidates from prune_candidates(2);

-- T6 阻断发现保护具体修订
select count(*) as flagged_page_candidates from prune_candidates(3);
select revision_id, (revision_id in (select revision_id from prune_candidates(3))) candidate
from wiki_revision where wiki_id=3 order by version_no;

-- T7 回滚链
with recursive chain as (
  select r.revision_id, r.rollback_of, r.edit_source, 0 depth
  from wiki_revision r where r.revision_id=6
  union all
  select r.revision_id, r.rollback_of, r.edit_source, c.depth+1
  from wiki_revision r join chain c on r.revision_id=c.rollback_of
)
select * from chain order by depth;

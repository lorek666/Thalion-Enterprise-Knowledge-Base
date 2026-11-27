\set ON_ERROR_STOP on
create type wiki_edit_source as enum ('pipeline','agent','user','revert');

alter table wiki_revision
  add column if not exists edit_source wiki_edit_source not null default 'pipeline',
  add column if not exists editor_id bigint,
  add column if not exists approved_by bigint,
  add column if not exists approved_at timestamptz,
  add column if not exists approval_note text,
  add column if not exists rollback_of bigint references wiki_revision(revision_id),
  add column if not exists body_sha256 text,
  add column if not exists input_watermark bigint not null default 0,
  add column if not exists pruned_at timestamptz;

update wiki_revision
set body_sha256 = encode(sha256(convert_to(body_md,'UTF8')),'hex')
where body_sha256 is null;

alter table wiki_revision alter column body_sha256 set not null;

create or replace function wiki_revision_hash() returns trigger language plpgsql as $$
begin
  new.body_sha256 := encode(sha256(convert_to(new.body_md,'UTF8')),'hex');
  return new;
end $$;

drop trigger if exists wiki_revision_hash_trg on wiki_revision;
create trigger wiki_revision_hash_trg
before insert on wiki_revision
for each row execute function wiki_revision_hash();

alter table wiki_revision
  add constraint wiki_rev_revert_needs_source
    check (edit_source <> 'revert' or rollback_of is not null) not valid,
  add constraint wiki_rev_publish_needs_approval
    check (status <> 'published' or (approved_by is not null and approved_at is not null)) not valid,
  add constraint wiki_rev_no_self_approval
    check (approved_by is null or editor_id is null or approved_by <> editor_id) not valid;

alter table wiki_statement
  add column if not exists fingerprint text,
  add column if not exists origin_revision_id bigint references wiki_revision(revision_id),
  add column if not exists last_edit_source wiki_edit_source,
  add column if not exists last_editor_id bigint;

update wiki_statement s
set fingerprint = encode(sha256(convert_to(jsonb_build_array(
      s.statement_type, s.subject_key, s.predicate, s.qualifier,
      s.value_num, s.value_code, s.value_text, s.unit,
      s.valid_from, s.valid_to)::text,'UTF8')),'hex')
where s.fingerprint is null;

create or replace function wiki_statement_fingerprint() returns trigger language plpgsql as $$
begin
  new.fingerprint := encode(sha256(convert_to(jsonb_build_array(
    new.statement_type, new.subject_key, new.predicate, new.qualifier,
    new.value_num, new.value_code, new.value_text, new.unit,
    new.valid_from, new.valid_to)::text,'UTF8')),'hex');
  return new;
end $$;

drop trigger if exists wiki_statement_fingerprint_trg on wiki_statement;
create trigger wiki_statement_fingerprint_trg
before insert or update of statement_type,subject_key,predicate,qualifier,value_num,value_code,value_text,unit,valid_from,valid_to
on wiki_statement
for each row execute function wiki_statement_fingerprint();

create table if not exists wiki_hold(
  hold_id bigint generated always as identity primary key,
  wiki_id bigint not null references wiki(wiki_id),
  reason text not null,
  authority text not null,
  starts_at date not null default current_date,
  ends_at date,
  review_at date not null,
  released_at timestamptz
);

create table if not exists wiki_revision_archive(
  revision_id bigint primary key references wiki_revision(revision_id),
  body_md text not null,
  archived_at timestamptz not null default now(),
  archive_key text
);

create table wiki_archive_approval(
  revision_id bigint primary key references wiki_revision(revision_id),
  approved_by bigint not null,
  approved_at timestamptz not null default now(),
  approval_note text not null check (btrim(approval_note) <> '')
);

create table if not exists wiki_retention(
  space_id bigint primary key references space(space_id),
  hard_cap int not null default 200,
  keep_user int not null default 50,
  keep_revert int not null default 20
);

create view wiki_revision_archive_protected as
select r.revision_id
from wiki_revision r join wiki w on w.wiki_id = r.wiki_id
where r.status <> 'draft'
   or r.revision_id = w.published_revision_id
   or coalesce(r.approved_at, r.published_at) is not null
   or r.approved_by is not null or r.approval_note is not null
   or exists (
     select 1 from wiki_hold h
     where h.wiki_id = w.wiki_id and h.starts_at <= current_date and h.released_at is null
   )
   or exists (
     select 1 from lint_finding f
     where f.revision_id = r.revision_id
       and f.state in ('open','acknowledged') and f.severity in ('blocker','high')
   )
   or exists (select 1 from wiki_revision child where child.rollback_of = r.revision_id)
   or exists (
     select 1 from wiki_statement s
     where s.origin_revision_id = r.revision_id and s.revision_id is distinct from r.revision_id
   );

create or replace function wiki_revision_guard() returns trigger language plpgsql as $$
begin
  if tg_op <> 'UPDATE' then
    raise exception 'wiki_revision 为只追加表，禁止删除' using errcode = '23514';
  end if;
  if row(new.revision_id, new.wiki_id, new.version_no, new.title, new.edit_source,
         new.editor_id, new.rollback_of, new.body_sha256, new.input_watermark)
     is distinct from
     row(old.revision_id, old.wiki_id, old.version_no, old.title, old.edit_source,
         old.editor_id, old.rollback_of, old.body_sha256, old.input_watermark) then
    raise exception '修订标识和内容不可修改' using errcode = '23514';
  end if;
  if row(new.approved_by, new.approved_at, new.approval_note, new.published_at)
     is distinct from row(old.approved_by, old.approved_at, old.approval_note, old.published_at)
     and (old.status <> 'pending' or new.status <> 'published' or old.approved_by is not null
          or old.approved_at is not null or old.approval_note is not null or old.published_at is not null) then
    raise exception '审批记录只能在首次发布时写入' using errcode = '23514';
  end if;
  if old.pruned_at is not null and new.status is distinct from old.status then
    raise exception '已归档修订的状态不可修改' using errcode = '23514';
  end if;
  if row(new.body_md, new.pruned_at) is distinct from row(old.body_md, old.pruned_at) then
    if old.pruned_at is not null or new.pruned_at is null or new.body_md <> ''
       or new.status is distinct from old.status
       or exists (select 1 from wiki_revision_archive_protected p where p.revision_id = old.revision_id)
       or not exists (
         select 1 from wiki_revision_archive a join wiki_archive_approval approval using (revision_id)
         where a.revision_id = old.revision_id and a.body_md = old.body_md
       ) then
      raise exception '修订正文不可修改，清空前须校验审批、保护状态及完整归档' using errcode = '23514';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists wiki_revision_guard_trg on wiki_revision;
create trigger wiki_revision_guard_trg
before update or delete on wiki_revision
for each row execute function wiki_revision_guard();

create trigger wiki_revision_no_truncate_trg
before truncate on wiki_revision
for each statement execute function wiki_revision_guard();

create function wiki_archive_append_only() returns trigger language plpgsql as $$
begin
  raise exception '归档正文和审批记录只允许追加' using errcode = '23514';
end $$;

create trigger wiki_archive_append_only_trg
before update or delete or truncate on wiki_revision_archive
for each statement execute function wiki_archive_append_only();

create trigger wiki_archive_approval_append_only_trg
before update or delete or truncate on wiki_archive_approval
for each statement execute function wiki_archive_append_only();

create or replace function wiki_carry_statements(p_new_revision bigint) returns int
language plpgsql as $$
declare n int;
begin
  with nr as (
    select r.revision_id, r.wiki_id, r.version_no, r.edit_source, r.editor_id
    from wiki_revision r where r.revision_id = p_new_revision
  ),
  prev as (
    select r.revision_id, r.edit_source, r.editor_id from wiki_revision r
    join nr on nr.wiki_id = r.wiki_id and r.version_no < nr.version_no
    order by r.version_no desc limit 1
  ),
  map as (
    select t.statement_id,
           coalesce(p.origin_revision_id, p.revision_id, t.revision_id) origin_revision_id,
           case when p.fingerprint is not null then coalesce(p.last_edit_source, pr.edit_source) else nr.edit_source end last_edit_source,
           case when p.fingerprint is not null then p.last_editor_id else nr.editor_id end last_editor_id
    from wiki_statement t
    cross join nr
    cross join prev pr
    left join wiki_statement p
      on p.revision_id = pr.revision_id
     and p.fingerprint = t.fingerprint
    where t.revision_id = p_new_revision
  )
  update wiki_statement s
  set origin_revision_id = m.origin_revision_id,
      last_edit_source   = m.last_edit_source,
      last_editor_id     = m.last_editor_id
  from map m
  where m.statement_id = s.statement_id;
  get diagnostics n = row_count;
  return n;
end $$;

create or replace function prune_candidates(p_space bigint)
returns table(wiki_id bigint, revision_id bigint, version_no int, edit_source wiki_edit_source, reason text)
language plpgsql as $$
begin
  return query
  with cfg as (
    select coalesce((select r.hard_cap  from wiki_retention r where r.space_id=p_space),200) cap,
           coalesce((select r.keep_user  from wiki_retention r where r.space_id=p_space),50)  keep_user,
           coalesce((select r.keep_revert from wiki_retention r where r.space_id=p_space),20) keep_revert
  ),
  base as (
    select r.revision_id, r.wiki_id, r.version_no, r.edit_source, r.body_md <> '' as has_body
    from wiki_revision r join wiki w on w.wiki_id = r.wiki_id
    where w.space_id = p_space and r.pruned_at is null
  ),
  totals as (select b.wiki_id, count(*)::int total from base b group by 1),
  cand as (
    select b.*, row_number() over (
             partition by b.wiki_id, b.edit_source order by b.version_no desc) src_rank
    from base b
    where b.has_body and not exists (
      select 1 from wiki_revision_archive_protected p where p.revision_id = b.revision_id
    )
  ),
  eligible as (
    select c.* from cand c cross join cfg
    where c.edit_source in ('pipeline','agent')
       or (c.edit_source = 'user'   and c.src_rank > cfg.keep_user)
       or (c.edit_source = 'revert' and c.src_rank > cfg.keep_revert)
  ),
  ranked as (
    select e.*, row_number() over (
      partition by e.wiki_id
      order by case e.edit_source when 'pipeline' then 0 when 'agent' then 1
                                  when 'user' then 2 else 3 end,
               e.version_no) rn
    from eligible e
  )
  select r.wiki_id, r.revision_id, r.version_no, r.edit_source,
         (case when r.src_rank > 1 and r.edit_source in ('user','revert')
               then 'over_quota' else 'over_cap' end)::text
  from ranked r
  join totals t using (wiki_id)
  cross join cfg
  where t.total > cfg.cap and r.rn <= t.total - cfg.cap
     or r.edit_source in ('user','revert');
end $$;

create function wiki_archive_rehearsal(p_space bigint, p_revision_ids bigint[]) returns int
language plpgsql as $$
declare candidate_ids bigint[];
begin
  lock table wiki, wiki_revision, wiki_hold, lint_finding, wiki_statement, wiki_retention,
             wiki_archive_approval, wiki_revision_archive in share row exclusive mode nowait;

  select array(
    select c.revision_id
    from prune_candidates(p_space) c join wiki_archive_approval a on a.revision_id = c.revision_id
    where c.revision_id = any(p_revision_ids)
  ) into candidate_ids;

  insert into wiki_revision_archive(revision_id,body_md)
  select r.revision_id, r.body_md
  from wiki_revision r where r.revision_id = any(candidate_ids);

  update wiki_revision r
  set body_md = '', pruned_at = now()
  where r.revision_id = any(candidate_ids);

  return cardinality(candidate_ids);
end $$;

revoke execute on function wiki_archive_rehearsal(bigint,bigint[]) from public;

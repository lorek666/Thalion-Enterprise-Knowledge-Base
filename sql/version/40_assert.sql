\set ON_ERROR_STOP on

do $$
begin
  begin
    update wiki_revision
    set title = '被改写', body_md = '', pruned_at = now()
    where revision_id = 105;
    raise exception 'published revision on hold allowed a title rewrite';
  exception when check_violation then null;
  end;
end $$;

do $$
begin
  begin
    update wiki_revision set body_md = '', pruned_at = now() where revision_id = 206;
    raise exception 'revision body was cleared without an archive';
  exception when check_violation then null;
  end;
end $$;

do $$
begin
  begin
    update wiki_revision set approved_by = 999, approval_note = '被改写' where revision_id = 105;
    raise exception 'existing approval record was overwritten';
  exception when check_violation then null;
  end;
end $$;

do $$
begin
  begin
    update wiki_revision set version_no=99, input_watermark=9 where revision_id=3;
    raise exception 'revision identity and provenance were mutable';
  exception when check_violation then null;
  end;
  begin
    update wiki_revision set pruned_at=now() where revision_id=3;
    raise exception 'revision was marked as pruned without an archive';
  exception when check_violation then null;
  end;

  if array(select revision_id from prune_candidates(1) order by revision_id)
       is distinct from array[2,3]::bigint[] then
    raise exception 'candidate selection did not protect the statement origin and rollback base';
  end if;
  if exists(select 1 from prune_candidates(2)) then
    raise exception 'held page produced archive candidates';
  end if;
  if exists(select 1 from prune_candidates(3) where revision_id=201) then
    raise exception 'blocker finding did not protect revision 201';
  end if;
  if array(select revision_id from prune_candidates(4) order by revision_id)
       is distinct from array[301,302]::bigint[] then
    raise exception 'user quota did not select the two oldest eligible drafts';
  end if;
  if exists(select 1 from wiki_revision where pruned_at is not null)
     or exists(select 1 from wiki_revision_archive) then
    raise exception 'listing candidates must be read-only';
  end if;
end $$;

begin;
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,approved_by,approved_at,published_at)
values (207,3,7,'f7','已批准','suspended',100,now(),now());
insert into wiki_archive_approval(revision_id,approved_by,approval_note)
select revision_id, 100, '离线演练' from wiki_revision where revision_id in (1,2,4,5,101,105,201,207);

do $$
begin
  if wiki_archive_rehearsal(1,array[1,2,3,4,5,101]::bigint[]) <> 1 then
    raise exception 'rehearsal must archive only approved, requested and eligible revision 2';
  end if;
  if wiki_archive_rehearsal(1,array[2,3]::bigint[]) <> 0
     or wiki_archive_rehearsal(2,array[101,105]::bigint[]) <> 0
     or wiki_archive_rehearsal(3,array[201,207]::bigint[]) <> 0 then
    raise exception 'rehearsal did not protect retries, holds, findings or past approvals';
  end if;
  if array(select revision_id from wiki_revision where pruned_at is not null order by revision_id)
       is distinct from array[2]::bigint[]
     or array(select revision_id from wiki_revision_archive order by revision_id)
       is distinct from array[2]::bigint[]
     or not exists (
       select 1 from wiki_revision r join wiki_revision_archive a using (revision_id)
       where r.revision_id=2 and r.body_md='' and a.body_md='A|C'
         and r.body_sha256=encode(sha256(convert_to(a.body_md,'UTF8')),'hex')
     ) then
    raise exception 'archived and cleared sets differ, or archive differs from original body';
  end if;

  begin
    update wiki_revision_archive set body_md='损坏' where revision_id=2;
    raise exception 'archive body could be rewritten';
  exception when check_violation then null;
  end;
  begin
    delete from wiki_archive_approval where revision_id=2;
    raise exception 'archive approval could be removed';
  exception when check_violation then null;
  end;
  begin
    update wiki_revision set pruned_at=null where revision_id=2;
    raise exception 'archive timestamp could be reset';
  exception when check_violation then null;
  end;

  insert into wiki_archive_approval(revision_id,approved_by,approval_note) values (3,100,'离线演练');
  insert into wiki_revision_archive(revision_id,body_md) values (3,'错误归档'),(101,'x');
  begin
    update wiki_revision set body_md='', pruned_at=now() where revision_id=3;
    raise exception 'an archive with mismatched body allowed clearing';
  exception when check_violation then null;
  end;
  begin
    update wiki_revision set body_md='', pruned_at=now() where revision_id=101;
    raise exception 'even a matching approved archive must not clear a held revision';
  exception when check_violation then null;
  end;
end $$;
rollback;

select 'version assertions ok' as result;

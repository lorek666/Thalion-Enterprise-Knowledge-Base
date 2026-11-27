\set ON_ERROR_STOP on

begin;
insert into document_version values (30,3,1,'uncited'), (40,4,1,'other');
insert into wiki (wiki_id, slug) values (2,'control'), (3,'incomplete-manifest');
insert into wiki_revision (revision_id, wiki_id, input_manifest_complete) values
  (11,1,false),(20,2,false),(30,3,false);
insert into wiki_statement values (110,11);
insert into wiki_citation values (110,12);
insert into wiki_revision_input values (10,1),(10,30),(20,40),(30,40);
update wiki_revision set input_manifest_complete=true where revision_id in (10,20);
select ingest_inherit_inputs(11,10);
select ingest_inherit_inputs(11,10);
update wiki_revision set input_manifest_complete=true where revision_id=11;
update wiki set published_revision_id=case wiki_id when 1 then 11 when 2 then 20 else 30 end;

do $$
declare wiki_ids bigint[];
begin
  select array_agg(wiki_id order by wiki_id) into wiki_ids from v_ingest_available_wiki;
  if wiki_ids is distinct from array[1,2]::bigint[] then
    raise exception 'must allow both complete manifests but not the incomplete one: %',wiki_ids;
  end if;
end $$;

update document_version set withdrawn_at='2026-11-20 10:00+08' where version_id=30;

do $$
declare wiki_ids bigint[];
begin
  select array_agg(wiki_id order by wiki_id) into wiki_ids from v_ingest_available_wiki;
  if wiki_ids is distinct from array[2]::bigint[] then
    raise exception 'withdrawal of uncited inherited input did not block only the dependent page: %',wiki_ids;
  end if;
end $$;

update document_version set superseded_at='2026-11-20 10:15+08' where version_id=40;

do $$
begin
  if exists (select 1 from v_ingest_available_wiki) then
    raise exception 'ordinary replacement did not block the stale wiki';
  end if;
  if not exists (select 1 from document_version where version_id=40 and withdrawn_at is null) then
    raise exception 'ordinary replacement must not withdraw the historical original';
  end if;
end $$;
rollback;
select 'M7 dependency assertions ok' as result;

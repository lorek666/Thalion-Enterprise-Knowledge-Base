\set ON_ERROR_STOP on

begin;
insert into wiki(wiki_id,space_id,slug,title)
values (900,1,'fingerprint-fixture','fingerprint fixture');
insert into wiki_revision(revision_id,wiki_id,version_no,title,body_md,status,edit_source,editor_id)
values (9001,900,1,'base','base','draft','user',100),
       (9002,900,2,'candidate','candidate','draft','agent',200);
insert into wiki_statement(statement_id,revision_id,statement_type,subject_key,predicate,
                           value_text,valid_from,text_excerpt)
values (9001,9001,'eligibility','travel','approval_condition','须事前书面批准','2026-11-01','原措辞'),
       (9002,9002,'eligibility','travel','approval_condition','可事后口头批准','2026-11-01','新措辞');

update wiki_statement
set origin_revision_id=9001, last_edit_source='user', last_editor_id=100
where statement_id=9001;

do $$
declare previous_fingerprint text;
begin
  if (select fingerprint from wiki_statement where statement_id=9001)
       is not distinct from
     (select fingerprint from wiki_statement where statement_id=9002) then
    raise exception 'different text values must not share a statement fingerprint';
  end if;
  perform wiki_carry_statements(9002);
  if not exists (
    select 1 from wiki_statement
    where statement_id=9002 and origin_revision_id=9002
      and last_edit_source='agent' and last_editor_id=200
  ) then
    raise exception 'changed text inherited the previous author';
  end if;

  update wiki_statement set value_text='须事前书面批准' where statement_id=9002;
  if (select fingerprint from wiki_statement where statement_id=9001)
       is distinct from
     (select fingerprint from wiki_statement where statement_id=9002) then
    raise exception 'equal structured values with different excerpts must share a fingerprint';
  end if;
  perform wiki_carry_statements(9002);
  if not exists (
    select 1 from wiki_statement
    where statement_id=9002 and origin_revision_id=9001
      and last_edit_source='user' and last_editor_id=100
  ) then
    raise exception 'unchanged structured values did not inherit the previous source';
  end if;

  select fingerprint into previous_fingerprint from wiki_statement where statement_id=9002;
  update wiki_statement set statement_type='other' where statement_id=9002;
  if (select fingerprint from wiki_statement where statement_id=9002)
       is not distinct from previous_fingerprint then
    raise exception 'statement type updates must recompute the fingerprint';
  end if;
end $$;

insert into wiki_statement(statement_id,revision_id,statement_type,subject_key,predicate,
                           qualifier,value_text,valid_from)
values (9003,9001,'eligibility','travel|approval','condition','','same','2026-11-01'),
       (9004,9002,'eligibility','travel','approval|condition','','same','2026-11-01');

do $$
begin
  if (select fingerprint from wiki_statement where statement_id=9003)
       is not distinct from
     (select fingerprint from wiki_statement where statement_id=9004) then
    raise exception 'field separators must not create fingerprint collisions';
  end if;
end $$;
rollback;

select 'version fingerprint assertions ok' as result;

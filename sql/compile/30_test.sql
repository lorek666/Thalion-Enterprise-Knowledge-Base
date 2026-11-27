\set ON_ERROR_STOP on
-- T1 重放计划
select count(*) as planned from compile_plan(2,'space',1);

-- T2 缺陷候选：缺单位、缺引用
select jsonb_pretty(compile_diff(10,11,'{"amount":["unit","valid_from"],"approver":["citation"]}'::jsonb)) as diff_bad;

insert into compile_run(run_id,space_id,template_rev_id,scope_type,scope_id,corpus_watermark,status)
overriding system value
values (1,1,2,'space',1,100,'succeeded');
insert into compile_output(output_id,run_id,wiki_id,base_revision_id,candidate_revision_id,status,diff)
overriding system value
values (1,1,1,10,11,'candidate',
        compile_diff(10,11,'{"amount":["unit","valid_from"],"approver":["citation"]}'::jsonb));

-- T3 阻断项不得进入待审
do $$
begin
  begin
    perform compile_accept(1);
    raise exception 'accept should be blocked';
  exception when others then
    if position('blocking diff' in sqlerrm)=0 then raise; end if;
  end;
end $$;
select 'T3 ok' as result;

-- T4 修复后：补单位、补引用
update wiki_statement set unit='CNY/person-night', fingerprint='A' where statement_id=201;
insert into wiki_citation(revision_id,statement_id,passage_id,source_version_id) values (11,202,2,2);
update compile_output set diff=compile_diff(10,11,'{"amount":["unit","valid_from"],"approver":["citation"]}'::jsonb)
where output_id=1;
select jsonb_pretty(diff) as diff_fixed from compile_output where output_id=1;
select compile_accept(1);
select r.revision_id, r.status, w.published_revision_id
from wiki_revision r join wiki w on w.wiki_id=r.wiki_id where r.revision_id in (10,11);

-- T5 零差异：不生成候选
select compile_diff(20,21,'{"amount":["unit","valid_from"],"approver":["citation"]}'::jsonb) as diff_same;

-- T6 模板回退重放：与基线一致时零差异
select compile_diff(10,12,'{}'::jsonb) as diff_revert;

-- T7 相同规则不得重复建修订
do $$
begin
  begin
    insert into compile_template_rev(template_id,revision_no,status,rules,prompt_rev,model_rev,
                                     output_contract,required_fields,checksum)
    values (1,9,'draft','{}','p1','m1','{}','{}','c1');
    raise exception 'duplicate checksum not blocked';
  exception when unique_violation then null;
  end;
end $$;
select 'T7 ok' as result;

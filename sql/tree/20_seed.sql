\set ON_ERROR_STOP on
insert into document_version values (1,'差旅标准 B 版'),(2,'采购制度');
insert into passage values (1,1),(2,1),(3,1),(4,1),(5,2);

insert into doc_tree_node(node_id,version_id,parent_id,depth,order_no,node_type,title,path,page_from,page_to,search_text) values
 (1,1,null,0,1,'document','差旅标准 B 版','差旅标准 B 版',1,8,'差旅 标准 制度'),
 (2,1,1,1,1,'chapter','第一章 总则','差旅标准 B 版/第一章 总则',1,1,'总则 适用 范围 职级'),
 (3,1,1,1,2,'chapter','第二章 住宿标准','差旅标准 B 版/第二章 住宿标准',2,4,'住宿 标准 上限 城市 职级 普通 住宿'),
 (4,1,3,2,1,'table','表2 上海住宿限额','差旅标准 B 版/第二章 住宿标准/表2 上海住宿限额',3,3,'表2 上海 住宿 限额 上限 600 元 人 晚 会议 统一 安排 例外'),
 (5,1,1,1,3,'chapter','第三章 超标审批','差旅标准 B 版/第三章 超标审批',5,6,'超标 审批 事前 部门负责人 书面 批准 流程'),
 (6,1,1,1,4,'appendix','附录 名词解释','差旅标准 B 版/附录 名词解释',7,7,'名词 解释 住宿 标准 定义'),
 (10,2,null,0,1,'document','采购制度','采购制度',1,5,'采购 制度'),
 (11,2,10,1,1,'chapter','第二章 供应商准入','采购制度/第二章 供应商准入',2,3,'供应商 准入 资质 审核 流程');

insert into passage_node values (1,3),(2,4),(3,5),(4,2),(5,11);

insert into retrieval_eval_query values
 (1,1,'上海住宿上限及例外是什么？','上海 住宿 上限',array[4]::bigint[],array[2,3]::bigint[]),
 (2,1,'超标审批谁批准？','超标 审批 批准',array[5]::bigint[],array[3]::bigint[]);

insert into retrieval_sample_input values
 (1,array[2,1]::bigint[],array[1,2,4]::bigint[]),
 (2,array[4,4,4,1,5]::bigint[],array[1]::bigint[]);

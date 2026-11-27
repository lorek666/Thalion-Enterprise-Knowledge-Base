\set ON_ERROR_STOP on
create table document_version(version_id bigint primary key, title text not null);
create table passage(passage_id bigint primary key, version_id bigint not null references document_version(version_id));

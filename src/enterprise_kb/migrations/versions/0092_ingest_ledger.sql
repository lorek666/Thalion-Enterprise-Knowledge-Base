CREATE INDEX source_ingest_batch_source_page
ON thalion.source_ingest_batch (org_id, space_id, source_id, created_at DESC, batch_ref DESC);

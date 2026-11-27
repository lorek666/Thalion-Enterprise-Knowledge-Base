ALTER TABLE thalion.source_sync_page ADD COLUMN connector_cursor text
    CHECK (connector_cursor IS NULL OR octet_length(connector_cursor) BETWEEN 1 AND 4096);

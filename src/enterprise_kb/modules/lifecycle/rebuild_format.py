from psycopg.rows import dict_row

from enterprise_kb.modules.evidence import docx_evidence, markdown, pdf_evidence
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict


REBUILD_SCOPE = "original_and_rebuild"
REBUILD_FIELD = "rebuild_metadata"
REBUILD_FORMAT = "thalion.synthetic-version-rebuild.v1"
REPAIR_REBUILD_FORMAT = "thalion.synthetic-version-rebuild.v2"
PDF_REBUILD_FORMAT = "thalion.synthetic-pdf-version-rebuild.v1"
PDF_REPAIR_REBUILD_FORMAT = "thalion.synthetic-pdf-version-rebuild.v2"
DOCX_REBUILD_FORMAT = "thalion.synthetic-docx-version-rebuild.v1"
DOCX_REPAIR_REBUILD_FORMAT = "thalion.synthetic-docx-version-rebuild.v2"


def rebuild_metadata(connection, org_id, space_id, version_id, configuration, *, repaired=False, media_type="text/markdown"):
    profile = {pdf_evidence.MEDIA_TYPE: pdf_evidence, docx_evidence.MEDIA_TYPE: docx_evidence}.get(media_type, markdown)
    docx_columns = ", contract.docx_amount_columns" if profile is docx_evidence else ""
    with connection.cursor(row_factory=dict_row) as cursor:
        metadata = cursor.execute(f"""
            SELECT source_ref.public_id::text AS source_id, doc_ref.public_id::text AS document_id,
                   source.source_key, contract.object_namespace, doc.source_object_key AS object_key,
                   doc.incarnation, doc.display_name, version.source_version_key AS version_key,
                   version.version_label, version.registration_sequence {docx_columns}
            FROM thalion.document_version AS version
            JOIN thalion.document AS doc USING (org_id, space_id, source_id, document_id)
            JOIN thalion.source AS source USING (org_id, space_id, source_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
                 (source.org_id, source.space_id, source.source_id, source.contract_revision)
            JOIN thalion.object_identity AS source_ref
              ON (source_ref.org_id, source_ref.space_id, source_ref.object_type, source_ref.object_id) =
                 (source.org_id, source.space_id, source.identity_type, source.source_id)
            JOIN thalion.object_identity AS doc_ref
              ON (doc_ref.org_id, doc_ref.space_id, doc_ref.object_type, doc_ref.object_id) =
                 (doc.org_id, doc.space_id, doc.identity_type, doc.document_id)
            JOIN thalion.processing_config_revision AS config ON config.configuration_revision = %s
            WHERE (version.org_id, version.space_id, version.version_id) = (%s, %s, %s)
              AND version.contract_revision = 1 AND contract.revision = 1
              AND (config.configuration_revision = 1 OR %s)
              AND (config.parser_version, config.profile, config.locator_revision) = (%s, %s, %s)
            """, (configuration, org_id, space_id, version_id, repaired or profile is not markdown,
                  profile.PARSER_VERSION, profile.PROFILE, profile.LOCATOR_REVISION)).fetchone()
    if metadata is None:
        raise DispositionConflict("Reconstruction requires the initial source contract and an admitted processing profile.")
    return metadata

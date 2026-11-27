from hashlib import sha256
import json

from enterprise_kb.modules.access.delivery import EvidenceScope
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.lifecycle.transcripts import TRANSCRIPT_FIELD


WIKI_SCOPE = "original_and_wiki"
WIKI_FIELD = "wiki_revision"


def require_current_wiki(connection, org_id, space_id, version, publication, *, lock=False):
    scope = (org_id, space_id, publication)
    if lock:
        connection.execute("SELECT thalion.lock_synthetic_wiki_export(%s, %s, %s)", scope)
    if not connection.execute(
        "SELECT thalion.export_wiki_is_current(%s, %s, %s, %s)", (*scope[:2], version, publication),
    ).fetchone()[0]:
        raise DispositionConflict("The Wiki publication or its complete input scope is no longer available.")


def select_wiki(connection, org_id, space_id, version, revision):
    selected = connection.execute("""
        SELECT publication_ref FROM thalion.available_wiki_publication
        WHERE (org_id, space_id, revision_ref) = (%s, %s, %s)
        """, (org_id, space_id, revision)).fetchone()
    if selected is None:
        raise DispositionConflict("The requested Wiki revision is not currently published in this space.")
    publication, = selected
    require_current_wiki(connection, org_id, space_id, version, publication, lock=True)
    return publication


def archive_wiki(connection, org_id, space_id, target):
    publication = target["wiki_publication_ref"]
    require_current_wiki(connection, org_id, space_id, target["version_id"], publication)
    scope = (org_id, space_id, publication)
    revision, content, digest, manifest, format_revision, input_digest, direct_count, parents, count = connection.execute("""
        SELECT revision.revision_ref, revision.content, revision.content_digest, manifest.manifest_ref,
               manifest.format_revision, revision.input_digest, manifest.direct_count, manifest.parent_refs, seal.dependency_count
        FROM thalion.wiki_publication_event AS publication
        JOIN thalion.wiki_revision AS revision USING (org_id, space_id, revision_ref)
        JOIN thalion.input_manifest AS manifest USING (manifest_ref)
        JOIN thalion.delivery_record AS seal ON seal.check_id = manifest.check_id
        WHERE (publication.org_id, publication.space_id, publication.publication_ref) = (%s, %s, %s)
        """, scope).fetchone()
    parts = connection.execute("""
        SELECT position, source_id, version_ref, passage_ref, excerpt_revision, run_ref, content_digest
        FROM thalion.wiki_archive_input WHERE (org_id, space_id, publication_ref) = (%s, %s, %s)
        ORDER BY position LIMIT 21
        """, scope).fetchall()
    if not 1 <= count <= 20 or len(parts) != count or sha256(content).digest() != digest:
        raise DispositionInventoryUnavailable("The exact Wiki content or sealed input manifest could not be verified.")
    scopes = [EvidenceScope(space_id, target["source_id"], revision, frozenset({WIKI_FIELD}))]
    dependencies = []
    for position, source, version, passage, excerpt_revision, run, excerpt_digest in parts:
        scopes.append(EvidenceScope(space_id, source, passage, frozenset({TRANSCRIPT_FIELD}), excerpt_revision))
        dependencies.append({
            "position": position, "version_id": str(version), "passage_id": str(passage),
            "excerpt_revision": excerpt_revision, "run_id": str(run), "excerpt_sha256": excerpt_digest.hex(),
        })
    metadata = json.dumps({
        "revision_id": str(revision), "publication_id": str(publication), "content_sha256": digest.hex(),
        "manifest_id": str(manifest), "manifest_format_revision": format_revision, "input_sha256": input_digest.hex(),
        "direct_count": direct_count, "parent_manifest_ids": [str(parent) for parent in parents], "inputs": dependencies,
    }, sort_keys=True, separators=(",", ":")).encode()
    return {
        "wiki/dependencies.json": metadata, "wiki/revision.json": content,
        "wiki/content.md": json.loads(content)["markdown"].encode(),
    }, scopes

from hashlib import sha256
import json
from uuid import UUID

from psycopg.rows import dict_row

from enterprise_kb.modules.evidence.docx_evidence import MEDIA_TYPE as DOCX_MEDIA_TYPE
from enterprise_kb.modules.evidence.pdf_evidence import MEDIA_TYPE as PDF_MEDIA_TYPE
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.lifecycle.rebuild_format import rebuild_metadata
from enterprise_kb.modules.lifecycle.transcripts import MAX_TRANSCRIPT_PASSAGES, current_transcript


WIKI_REBUILD_SCOPE = "wiki_rebuild"
WIKI_REBUILD_FORMAT = "thalion.synthetic-wiki-rebuild.v1"
MAX_WIKI_INPUTS = 20
MAX_WIKI_MANIFESTS = 32


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def canonical_ref(value):
    ref = UUID(value)
    if str(ref) != value:
        raise ValueError("Expected a canonical public identifier.")
    return ref


def exact_refs(items):
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_WIKI_INPUTS:
        raise ValueError("Invalid Wiki input count.")
    if any(not isinstance(item, list) or len(item) != 2 or type(item[1]) is not int or item[1] < 1 for item in items):
        raise ValueError("Invalid exact Wiki input.")
    refs = {canonical_ref(ref): revision for ref, revision in items}
    if len(refs) != len(items):
        raise ValueError("Ambiguous Wiki input revisions.")
    return refs


def verify_manifest_graph(root, manifests):
    if not isinstance(manifests, list) or not 1 <= len(manifests) <= MAX_WIKI_MANIFESTS:
        raise ValueError("Invalid Wiki manifest count.")
    by_ref = {}
    for node in manifests:
        if not isinstance(node, dict) or set(node) != {
            "manifest_id", "parent_manifest_ids", "direct_count", "inputs", "direct_sha256", "expanded_sha256",
        }:
            raise ValueError("Invalid Wiki input manifest.")
        ref = canonical_ref(node["manifest_id"])
        inputs = exact_refs(node["inputs"])
        if not isinstance(node["parent_manifest_ids"], list) or len(node["parent_manifest_ids"]) > 8:
            raise ValueError("Invalid Wiki manifest parent scope.")
        parents = tuple(canonical_ref(parent) for parent in node["parent_manifest_ids"])
        direct = node["direct_count"]
        if (
            ref in by_ref or len(set(parents)) != len(parents) or type(direct) is not int
            or not 0 <= direct <= len(inputs) or not (direct or parents)
        ):
            raise ValueError("Ambiguous Wiki manifest links.")
        expanded_bytes = json.dumps(node["inputs"]).encode()
        direct_bytes = json.dumps([node["inputs"][:direct], node["parent_manifest_ids"]]).encode()
        if sha256(expanded_bytes).hexdigest() != node["expanded_sha256"] or sha256(direct_bytes).hexdigest() != node["direct_sha256"]:
            raise ValueError("Wiki input manifest digest mismatch.")
        by_ref[ref] = (parents, direct, inputs)

    visiting, verified = set(), set()

    def follow(ref):
        if ref in visiting or ref not in by_ref:
            raise ValueError("Missing or cyclic Wiki manifest parent.")
        if ref in verified:
            return
        visiting.add(ref)
        parents, direct, inputs = by_ref[ref]
        expanded = dict(list(inputs.items())[:direct])
        for parent in parents:
            follow(parent)
            for part, revision in by_ref[parent][2].items():
                if expanded.setdefault(part, revision) != revision:
                    raise ValueError("Conflicting inherited Wiki input revisions.")
        if tuple(expanded.items()) != tuple(inputs.items()):
            raise ValueError("Expanded Wiki inputs differ from the parent closure.")
        visiting.remove(ref)
        verified.add(ref)

    follow(root)
    if len(verified) != len(by_ref):
        raise ValueError("The Wiki manifest graph contains unrelated entries.")
    return tuple(by_ref), by_ref[root][2]


def _manifest_graph(connection, org_id, space_id, root):
    pending, seen, graph = [root], set(), []
    while pending:
        ref = pending.pop(0)
        if ref in seen:
            continue
        if len(seen) >= MAX_WIKI_MANIFESTS:
            raise DispositionConflict("The Wiki manifest closure exceeds the archive limit.")
        manifest = connection.execute("""
            SELECT parent_refs, direct_count, direct_digest, expanded_digest,
                   count(entry.position), jsonb_agg(jsonb_build_array(entry.passage_ref, entry.excerpt_revision)
                                                    ORDER BY entry.position) AS inputs
            FROM thalion.input_manifest AS manifest
            JOIN thalion.input_manifest_entry AS entry USING (org_id, space_id, manifest_ref)
            WHERE (manifest.org_id, manifest.space_id, manifest.manifest_ref, manifest.format_revision) = (%s, %s, %s, 1)
            GROUP BY manifest.manifest_ref
            """, (org_id, space_id, ref)).fetchone()
        if manifest is None or not 1 <= manifest[4] <= MAX_WIKI_INPUTS:
            raise DispositionInventoryUnavailable("A Wiki ancestor input manifest is unavailable.")
        parents, direct, direct_digest, expanded_digest, _, inputs = manifest
        seen.add(ref)
        pending.extend(parents)
        graph.append({
            "manifest_id": str(ref), "parent_manifest_ids": [str(parent) for parent in parents],
            "direct_count": direct, "direct_sha256": direct_digest.hex(),
            "expanded_sha256": expanded_digest.hex(), "inputs": inputs,
        })
    try:
        verify_manifest_graph(root, graph)
    except ValueError:
        raise DispositionInventoryUnavailable("The recorded Wiki input manifest closure is inconsistent.") from None
    return graph


def wiki_rebuild_material(connection, org_id, space_id, publication):
    topic_key, root = connection.execute("""
        SELECT wiki.topic_key, revision.manifest_ref
        FROM thalion.wiki_publication_event AS wiki
        JOIN thalion.wiki_revision AS revision USING (org_id, space_id, revision_ref)
        WHERE (wiki.org_id, wiki.space_id, wiki.publication_ref) = (%s, %s, %s)
        """, (org_id, space_id, publication)).fetchone()
    graph = _manifest_graph(connection, org_id, space_id, root)
    with connection.cursor(row_factory=dict_row) as cursor:
        versions = cursor.execute("""
            SELECT DISTINCT target.version_id, target.version_ref, target.source_id, target.snapshot,
                            target.storage_key, target.content_digest, target.byte_length, target.media_type,
                            input.run_ref AS transcript_run_ref, run.replaces_run_ref
            FROM thalion.wiki_archive_input AS input
            JOIN thalion.synthetic_export_target AS target USING (org_id, space_id, version_id)
            JOIN thalion.processing_run AS run ON run.run_ref = input.run_ref
            WHERE (input.org_id, input.space_id, input.publication_ref) = (%s, %s, %s) AND NOT target.blocked
            ORDER BY target.version_ref
            """, (org_id, space_id, publication)).fetchall()
    if not 1 <= len(versions) <= MAX_WIKI_INPUTS or len({item["version_ref"] for item in versions}) != len(versions):
        raise DispositionConflict("The Wiki archive requires bounded unique source versions.")
    if any(version["media_type"] not in {"text/markdown", PDF_MEDIA_TYPE, DOCX_MEDIA_TYPE} or version["replaces_run_ref"] is not None
           for version in versions):
        raise DispositionConflict("Wiki rebuild requires every input to have a supported reconstruction format.")
    pin_versions = []
    passage_count = 0
    for version in versions:
        transcript = current_transcript(connection, org_id, space_id, version["version_id"], version["transcript_run_ref"])
        passage_count += transcript[3]
        if passage_count > MAX_TRANSCRIPT_PASSAGES:
            raise DispositionConflict("The complete Wiki transcript scope exceeds the archive limit.")
        version["metadata"] = rebuild_metadata(
            connection, org_id, space_id, version["version_id"], transcript[1], media_type=version["media_type"],
        )
        pin_versions.append((
            str(version["version_ref"]), version["snapshot"], version["content_digest"].hex(),
            version["byte_length"], str(transcript[0]), transcript[2].hex(), version["metadata"],
        ))
    digest = sha256(canonical_json([str(publication), topic_key, graph, pin_versions])).digest()
    return digest, topic_key, graph, versions

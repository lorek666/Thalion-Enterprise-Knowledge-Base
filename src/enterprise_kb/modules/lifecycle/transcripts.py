from hashlib import sha256
import json

from psycopg.rows import dict_row

from enterprise_kb.modules.access.delivery import EvidenceScope
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.sources.registry import _digest


TRANSCRIPT_SCOPE = "original_and_transcript"
TRANSCRIPT_FIELD = "transcription"
REPAIR_HISTORY_FIELD = "repair_history"
MAX_TRANSCRIPT_PASSAGES = 128
MAX_REPAIR_RUNS = 16
MAX_REPAIR_LOCATIONS = 256


def current_transcript(connection, org_id, space_id, version, expected=None):
    run = connection.execute(
        "SELECT * FROM thalion.current_export_transcript(%s, %s, %s)", (org_id, space_id, version),
    ).fetchone()
    if run is None or (expected is not None and run[0] != expected):
        raise DispositionConflict("The archive requires the same current approved bounded transcript.")
    return run


def _locations(connection, org_id, space_id, version_id, run, limit):
    return connection.execute("""
        SELECT identity.public_id, excerpt.excerpt_revision, passage.locator_revision, passage.heading_path,
               passage.paragraph, passage.kind, passage.byte_start, passage.byte_end, excerpt.content_digest
        FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (org_id, space_id, version_id, passage_id)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id)
        WHERE (excerpt.org_id, excerpt.space_id, excerpt.version_id, excerpt.run_ref) = (%s, %s, %s, %s)
        ORDER BY passage.byte_start, passage.byte_end, identity.public_id LIMIT %s
        """, (org_id, space_id, version_id, run, limit)).fetchall()


def _manifest_matches(target, configuration, manifest_digest, count, parts):
    return len(parts) == count and manifest_digest == _digest(
        "markdown_manifest.v1", str(target["version_ref"]), target["content_digest"].hex(), configuration,
        "pending_review", None, [(path, paragraph, kind, start, end, digest.hex())
                                 for _, _, _, path, paragraph, kind, start, end, digest in parts],
    )


def transcript_scopes(connection, org_id, space_id, target):
    version = target["version_id"]
    run, _, _, count = current_transcript(connection, org_id, space_id, version, target["transcript_run_ref"])
    parts = _locations(connection, org_id, space_id, version, run, MAX_TRANSCRIPT_PASSAGES + 1)
    if len(parts) != count or len({part[0] for part in parts}) != count:
        raise DispositionInventoryUnavailable("The current transcript scope is incomplete.")
    return tuple(
        EvidenceScope(space_id, target["source_id"], ref, frozenset({TRANSCRIPT_FIELD}), revision)
        for ref, revision, *_ in parts
    )


def _exact_locations(parts, payload):
    last_end = 0
    for ref, revision, locator, path, paragraph, kind, start, end, digest in parts:
        if not last_end <= start < end:
            raise DispositionInventoryUnavailable("The registered transcript has an invalid location.")
        if payload is not None and (end > len(payload) or sha256(payload[start:end]).digest() != digest):
            raise DispositionInventoryUnavailable("The registered transcript does not match the exact original.")
        yield {
            "passage_id": str(ref), "excerpt_revision": revision, "locator_revision": locator,
            "heading_path": path, "paragraph": paragraph, "kind": kind, "byte_start": start, "byte_end": end,
            "sha256": digest.hex(),
        }
        last_end = end


def archive_transcription(connection, org_id, space_id, target, payload):
    run, configuration, manifest_digest, count = current_transcript(
        connection, org_id, space_id, target["version_id"], target["transcript_run_ref"],
    )
    parts = _locations(connection, org_id, space_id, target["version_id"], run, MAX_TRANSCRIPT_PASSAGES + 1)
    if not _manifest_matches(target, configuration, manifest_digest, count, parts):
        raise DispositionInventoryUnavailable("The approved transcript manifest is incomplete or inconsistent.")
    members = {}
    locations = []
    scopes = []
    for location, (ref, revision, *_) in zip(_exact_locations(parts, payload), parts, strict=True):
        member = f"transcript/{ref}.md"
        members[member] = payload[location["byte_start"]:location["byte_end"]]
        locations.append(location | {"member": member})
        scopes.append(EvidenceScope(space_id, target["source_id"], ref, frozenset({TRANSCRIPT_FIELD}), revision))
    members["transcription.json"] = json.dumps({
        "run_id": str(run), "manifest_sha256": manifest_digest.hex(), "configuration_revision": configuration,
        "passages": locations,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return members, scopes


def _repair_run(connection, scope, ref):
    with connection.cursor(row_factory=dict_row) as cursor:
        run = cursor.execute("""
            SELECT run_ref, configuration_revision, manifest_digest, passage_count, outcome, input_digest,
                   replaces_run_ref, rollback_run_ref, repair_basis_ref, contract_revision,
                   config.parser_version, config.profile, config.locator_revision
            FROM thalion.processing_run
            JOIN thalion.processing_config_revision AS config USING (configuration_revision)
            WHERE (org_id, space_id, version_id, run_ref) = (%s, %s, %s, %s)
        """, (*scope, ref)).fetchone()
    if run is None:
        raise DispositionInventoryUnavailable("A repair history run is missing from its version.")
    return run


def _repair_decisions(connection, scope, run):
    rows = connection.execute("""
        SELECT decision.outcome, decision.decision_ref, decision.basis_ref, preview.preview_ref,
               preview.difference_digest
        FROM thalion.quality_decision AS decision
        LEFT JOIN thalion.repair_review_preview AS preview ON preview.preview_ref = decision.repair_preview_ref
        WHERE (decision.org_id, decision.space_id, decision.version_id, decision.run_ref) = (%s, %s, %s, %s)
        ORDER BY decision.outcome
    """, (*scope, run["run_ref"])).fetchall()
    return [
        {"outcome": outcome, "decision_id": str(ref), "basis_id": str(basis),
         "preview_id": str(preview) if preview else None, "difference_sha256": digest.hex() if digest else None}
        for outcome, ref, basis, preview, digest in rows
    ]


def repair_history(connection, org_id, space_id, target, run_ref, *, payload=None):
    scope = (org_id, space_id, target["version_id"])
    current = _repair_run(connection, scope, run_ref)
    if current["replaces_run_ref"] is None:
        return None, ()
    pending = [current]
    collected = {}
    locations_left = MAX_REPAIR_LOCATIONS
    protected = {(target["version_ref"], None)}
    while pending:
        run = pending.pop()
        ref = run["run_ref"]
        if ref in collected:
            continue
        if (
            len(collected) == MAX_REPAIR_RUNS or not 1 <= run["passage_count"] <= locations_left
            or run["outcome"] != "pending_review" or run["input_digest"] != target["content_digest"]
        ):
            raise DispositionConflict("The complete repair history exceeds its scope or size limit.")
        configuration = run["configuration_revision"]
        pieces = _locations(connection, *scope, ref, run["passage_count"] + 1)
        if not _manifest_matches(target, configuration, run["manifest_digest"], run["passage_count"], pieces):
            raise DispositionInventoryUnavailable("A repair history manifest does not match its exact revisions.")
        locations_left -= len(pieces)
        protected.update((part[0], part[1]) for part in pieces)
        links = (run["replaces_run_ref"], run["rollback_run_ref"])
        collected[ref] = {
            "run_id": str(ref), "configuration_revision": configuration,
            "contract_revision": run["contract_revision"],
            "parser": {"version": run["parser_version"], "profile": run["profile"],
                       "locator_revision": run["locator_revision"]},
            "manifest_sha256": run["manifest_digest"].hex(),
            "replaces_run_id": str(links[0]) if links[0] else None,
            "rollback_run_id": str(links[1]) if links[1] else None,
            "repair_basis_id": str(run["repair_basis_ref"]) if run["repair_basis_ref"] else None,
            "decisions": _repair_decisions(connection, scope, run),
            "passages": list(_exact_locations(pieces, payload)),
        }
        for prior in (link for link in links if link is not None):
            ancestor = _repair_run(connection, scope, prior)
            if ancestor["configuration_revision"] >= configuration:
                raise DispositionInventoryUnavailable("A repair history edge is not chronologically valid.")
            pending.append(ancestor)
    material = json.dumps({
        "run_id": str(run_ref), "runs": sorted(collected.values(), key=lambda run: run["configuration_revision"]),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    scopes = tuple(
        EvidenceScope(space_id, target["source_id"], ref, frozenset({REPAIR_HISTORY_FIELD}), revision)
        for ref, revision in sorted(protected, key=lambda item: (item[0], item[1] or 0))
    )
    return material, scopes

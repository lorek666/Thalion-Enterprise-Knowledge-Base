import json
from uuid import UUID

from enterprise_kb.modules.access.delivery import EvidenceScope
from enterprise_kb.modules.evidence import csv_evidence, docx_evidence, docx_review, processing
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.lifecycle.transcripts import (
    MAX_REPAIR_LOCATIONS, MAX_REPAIR_RUNS, REPAIR_HISTORY_FIELD, TRANSCRIPT_FIELD, _repair_run, current_transcript,
)
from enterprise_kb.modules.sources.originals import OriginalIntegrityError


DOCX_TRANSCRIPT_FORMAT = "thalion.synthetic-docx-transcript-archive.v1"
DOCX_REPAIR_TRANSCRIPT_FORMAT = "thalion.synthetic-docx-transcript-archive.v2"


def _locations(connection, org_id, space_id, target):
    run, configuration, digest, count = current_transcript(
        connection, org_id, space_id, target["version_id"], target["transcript_run_ref"],
    )
    try:
        rows = docx_review.batch_locations(connection, org_id, space_id, target["version_id"], run, count)
    except OriginalIntegrityError:
        raise DispositionInventoryUnavailable("The DOCX transcript has incomplete registered locations.") from None
    return run, configuration, digest, rows


def _scopes(space_id, target, rows):
    return tuple(
        EvidenceScope(space_id, target["source_id"], part[0], frozenset({TRANSCRIPT_FIELD}), part[5])
        for part in rows
    )


def docx_transcript_scopes(connection, org_id, space_id, target):
    *_, rows = _locations(connection, org_id, space_id, target)
    return _scopes(space_id, target, rows)


def _amount_columns(connection, run):
    columns, = connection.execute("""
        SELECT contract.docx_amount_columns
        FROM thalion.processing_run AS run
        JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (run.org_id, run.space_id, version.source_id, run.contract_revision)
        WHERE run.run_ref = %s
    """, (run,)).fetchone()
    return tuple(columns) if columns is not None else None


def _wrap_repair_manifest(manifest, run):
    if run["replaces_run_ref"] is None:
        return manifest
    return processing.docx_repair_manifest(
        manifest, run["replaces_run_ref"], run["rollback_run_ref"], run["repair_basis_ref"],
    )


def archive_docx_transcription(connection, org_id, space_id, target, payload):
    run, configuration, manifest, rows = _locations(connection, org_id, space_id, target)
    record = _repair_run(connection, (org_id, space_id, target["version_id"]), run)
    columns = _amount_columns(connection, run)
    candidate = docx_evidence.parse_docx(payload, amount_columns=columns)
    exact = processing.docx_processing_manifest(
        target["version_ref"], target["content_digest"], configuration, columns,
        candidate, processing.docx_candidate_cells(candidate),
    )
    if _wrap_repair_manifest(exact, record) != manifest:
        raise DispositionInventoryUnavailable("The DOCX transcript does not match the approved manifest.")
    paragraphs, tables = docx_review.resolve_batch(candidate, rows)
    members = {}
    digests = {str(part[0]): part[6].hex() for part in rows}
    parts = paragraphs + [cell for table in tables for row in table["rows"] for cell in row["cells"]]
    for part in parts:
        ref = part["passage_id"]
        name = f"transcript/{ref}.txt"
        members[name] = part.pop("excerpt").encode()
        part.update(member=name, sha256=digests[ref])
    members["transcription.json"] = json.dumps({
        "run_id": str(run), "configuration_revision": configuration, "manifest_sha256": manifest.hex(),
        "paragraphs": paragraphs, "tables": tables,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return members, _scopes(space_id, target, rows)


def _verify_historical_manifest(target, run, rows, columns):
    paragraphs = []
    cells = []
    unit_roles = {}
    for _, _, path, paragraph, ordinal, _, digest, table, row, column, header, reason, role in rows:
        if table is None:
            paragraphs.append((ordinal, path, paragraph, digest.hex()))
            continue
        cells.append((table, row, column, path, digest, header))
        roles = unit_roles.setdefault((table, row, reason), {})
        if role is not None:
            roles[role] = column
    units = [
        (table, row, tuple(roles[role] for role in csv_evidence.AMOUNT_ROLES if role in roles), reason)
        for (table, row, reason), roles in unit_roles.items()
    ]
    exact = processing.docx_manifest_from_locations(
        target["version_ref"], target["content_digest"], run["configuration_revision"], columns,
        "pending_review", None, paragraphs, cells, units,
    )
    if _wrap_repair_manifest(exact, run) != run["manifest_digest"]:
        raise DispositionInventoryUnavailable("A DOCX repair history manifest does not match its registered evidence.")


def _quality_decisions(connection, scope, run, *, tables):
    rows = connection.execute("""
        SELECT decision.outcome, decision.decision_ref, decision.basis_ref,
               docx.request_id, docx.batch_digest, text.preview_ref, text.difference_digest
        FROM thalion.quality_decision AS decision
        LEFT JOIN thalion.docx_quality_preview AS docx
          ON (docx.org_id, docx.space_id, docx.version_id, docx.run_ref, docx.request_id) =
             (decision.org_id, decision.space_id, decision.version_id, decision.run_ref, decision.docx_preview_request)
        LEFT JOIN thalion.repair_review_preview AS text ON text.preview_ref = decision.repair_preview_ref
        WHERE (decision.org_id, decision.space_id, decision.version_id, decision.run_ref) = (%s, %s, %s, %s)
        ORDER BY decision.outcome
    """, (*scope, run["run_ref"])).fetchall()
    decisions = []
    for outcome, ref, basis, batch, batch_digest, text, text_digest in rows:
        if outcome == "approved" and (
            (tables and batch is None) or (not tables and run["replaces_run_ref"] is not None and text is None)
        ):
            raise DispositionInventoryUnavailable("A DOCX repair history approval is missing its exact receipt.")
        entry = {"outcome": outcome, "decision_id": str(ref), "basis_id": str(basis)}
        if batch is not None:
            entry.update(preview_id=str(batch), batch_sha256=batch_digest.hex())
        if text is not None:
            entry.update(preview_id=str(text), difference_sha256=text_digest.hex())
        decisions.append(entry)
    return decisions


def docx_repair_history(connection, org_id, space_id, target, run_ref):
    scope = (org_id, space_id, target["version_id"])
    current = _repair_run(connection, scope, run_ref)
    if current["replaces_run_ref"] is None:
        return None, ()
    pending = [current]
    collected = {}
    locations_left = MAX_REPAIR_LOCATIONS
    protected = {(target["version_ref"], None)}
    config_keys = ("contract_revision", "parser_version", "profile", "locator_revision")
    columns = _amount_columns(connection, run_ref)
    while pending:
        run = pending.pop()
        ref = run["run_ref"]
        if ref in collected:
            continue
        count = run["passage_count"]
        if len(collected) == MAX_REPAIR_RUNS or not 1 <= count <= locations_left:
            raise DispositionConflict("The DOCX repair history exceeds its bounded archive scope.")
        if (
            run["outcome"] != "pending_review" or run["input_digest"] != target["content_digest"]
            or any(run[key] != current[key] for key in config_keys)
        ):
            raise DispositionInventoryUnavailable("The DOCX history does not match the archived source contract.")
        try:
            rows = docx_review.batch_locations(connection, *scope, ref, count)
        except OriginalIntegrityError:
            raise DispositionInventoryUnavailable("A DOCX repair history batch has incomplete locations.") from None
        _verify_historical_manifest(target, run, rows, columns)
        locations_left -= count
        protected.update((part[0], part[5]) for part in rows)
        replaced, baseline = run["replaces_run_ref"], run["rollback_run_ref"]
        configuration = run["configuration_revision"]
        decisions = _quality_decisions(connection, scope, run, tables=any(part[7] is not None for part in rows))
        collected[ref] = {
            "run_id": str(ref), "configuration_revision": configuration, "contract_revision": run["contract_revision"],
            "parser": {"version": run["parser_version"], "profile": run["profile"], "locator_revision": run["locator_revision"]},
            "manifest_sha256": run["manifest_digest"].hex(),
            "replaces_run_id": str(replaced) if replaced else None,
            "rollback_run_id": str(baseline) if baseline else None,
            "repair_basis_id": str(run["repair_basis_ref"]) if run["repair_basis_ref"] else None,
            "decisions": decisions,
            "locations": [{"passage_id": str(part[0]), **docx_review.describe_location(part)} for part in rows],
        }
        for prior in (replaced, baseline):
            if prior is not None:
                ancestor = _repair_run(connection, scope, prior)
                if ancestor["configuration_revision"] >= configuration:
                    raise DispositionInventoryUnavailable("The DOCX repair history is not chronological.")
                pending.append(ancestor)
    for run in collected.values():
        replaced, baseline = run["replaces_run_id"], run["rollback_run_id"]
        outcomes = {entry["outcome"] for entry in run["decisions"]}
        if run["run_id"] == str(run_ref) and outcomes != {"approved"}:
            raise DispositionConflict("The current DOCX repair is not approved.")
        for prior, required in ((replaced, "quarantined"), (baseline, "approved")):
            if prior is not None and required not in {entry["outcome"] for entry in collected[UUID(prior)]["decisions"]}:
                raise DispositionInventoryUnavailable("The DOCX repair history is missing a required quality decision.")
    material = json.dumps({
        "run_id": str(run_ref), "runs": sorted(collected.values(), key=lambda run: run["configuration_revision"]),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return material, tuple(
        EvidenceScope(space_id, target["source_id"], ref, frozenset({REPAIR_HISTORY_FIELD}), revision)
        for ref, revision in sorted(protected, key=lambda item: (item[0], item[1] or 0))
    )

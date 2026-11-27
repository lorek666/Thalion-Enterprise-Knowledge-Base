from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import psycopg
import pytest

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable, DeliveryCheck, DeliveryContext, EvidenceScope
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.transport.local import LocalProfile

from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, private_json
from test_runtime import runtime_db
from test_source_revocations import independent_authority, revocation_authority
from test_travel_search import corpus


GRANTS = "model-source-grants.json"


def model_probe(fixture):
    _, db, (token, _), credentials, _, first, _ = fixture
    connection, tenant, *_ = db
    source_id, = connection.execute("SELECT source_id FROM thalion.source").fetchone()
    scope = EvidenceScope(tenant.space_id, source_id, first.passage_ref, frozenset({"excerpt", "title"}), first.revision)
    credential = credentials[token]
    context = DeliveryContext(
        uuid4(), tenant.org_id, tenant.actor_id, credential.client_id,
        "send_model_evidence", "model_answer", "synthetic-gateway", datetime.now(UTC) + timedelta(seconds=5),
    )
    probe = DeliveryCheck(uuid4(), context, sha256(b"Synthetic test excerpt").hexdigest(), frozenset({scope}))
    return credential, scope, probe


def grant_for(credential, scope, **changes):
    return {"employee_ref": str(credential.employee_ref), "purpose": "model_answer", "passage_id": str(scope.object_id),
            "revision": scope.revision, "fields": ["excerpt"], **changes}


def test_employee_read_authority_does_not_issue_model_proofs(evidence_transport, revocation_authority):
    _, _, profile = revocation_authority
    credential, scope, probe = model_probe(evidence_transport)
    employee_context = replace(probe.context, operation="read_passage", purpose="employee_evidence", destination="employee")
    ordinary = profile.check_source(credential, replace(probe, context=employee_context))
    assert ordinary.permitted_fields[scope] == scope.fields
    for context in (probe.context, replace(probe.context, destination="unconfigured-gateway")):
        with pytest.raises(AuthorizationUnavailable):
            profile.check_source(credential, replace(probe, context=context))


def test_model_source_requires_current_permission_for_the_exact_use_revision_and_fields(evidence_transport, revocation_authority):
    _, _, profile = revocation_authority
    credential, scope, probe = model_probe(evidence_transport)
    assert profile.check_model_source(credential, probe).permitted_fields[scope] == frozenset()
    grants = profile.root / GRANTS
    private_json(grants, [grant_for(credential, scope)])
    allowed = profile.check_model_source(credential, probe)
    assert allowed.check_id == probe.check_id and allowed.subject_ids == {probe.context.principal_id}
    assert allowed.permitted_fields[scope] == {"excerpt"}
    assert allowed.valid_until > allowed.checked_at
    other_use = replace(probe, context=replace(probe.context, purpose="wiki_compilation"))
    assert profile.check_model_source(credential, other_use).permitted_fields[scope] == frozenset()
    for other_scope in (replace(scope, revision=scope.revision + 1), replace(scope, revision=None)):
        changed = replace(probe, scopes=frozenset({other_scope}))
        assert profile.check_model_source(credential, changed).permitted_fields[other_scope] == frozenset()
    for context in (replace(probe.context, destination="employee"), replace(probe.context, client_id="other-client")):
        with pytest.raises(AuthorizationUnavailable):
            profile.check_model_source(credential, replace(probe, context=context))
    with pytest.raises(AuthorizationUnavailable):
        LocalProfile(profile.root).check_model_source(credential, probe)
    private_json(profile.root / "source-grants.json", {})
    assert profile.check_model_source(credential, probe).permitted_fields[scope] == frozenset()
    assert grants.exists()


def test_model_source_rechecks_independent_revocation_without_changing_local_rules(evidence_transport, revocation_authority):
    authority, source, profile = revocation_authority
    credential, scope, probe = model_probe(evidence_transport)
    grants = profile.root / GRANTS
    private_json(grants, [grant_for(credential, scope)])
    assert profile.check_model_source(credential, probe).permitted_fields[scope] == {"excerpt"}
    private_json(grants, [])
    assert profile.check_model_source(credential, probe).permitted_fields[scope] == frozenset()
    read = replace(probe.context, operation="read_passage", purpose="employee_evidence", destination="employee")
    assert profile.check_source(credential, replace(probe, context=read)).permitted_fields[scope] == scope.fields
    private_json(grants, [grant_for(credential, scope)])
    source_revocations.revoke(
        authority, source.authority_ref, credential.space_ref, credential.employee_ref, scope.object_id,
        "archive", basis_ref=uuid4(),
    )
    assert profile.check_model_source(credential, probe).permitted_fields[scope] == {"excerpt"}
    source_revocations.revoke(
        authority, source.authority_ref, credential.space_ref, credential.employee_ref, scope.object_id,
        "evidence", basis_ref=uuid4(),
    )
    assert profile.check_model_source(credential, probe).permitted_fields[scope] == frozenset()

    def disconnected():
        raise psycopg.OperationalError("Synthetic source authority outage.")

    unavailable = LocalProfile(profile.root, revocations=replace(source, connect=disconnected))
    with pytest.raises(AuthorizationUnavailable):
        unavailable.check_model_source(credential, probe)


def test_malformed_or_nonprivate_model_grants_never_fall_back_to_employee_authority(evidence_transport, revocation_authority):
    _, _, profile = revocation_authority
    credential, scope, probe = model_probe(evidence_transport)
    file = profile.root / GRANTS
    rule = grant_for(credential, scope)
    for bad_grants in ([rule, rule], [rule | {"revision": True}], [rule | {"fields": ["original_page"]}],
                       [rule | {"purpose": "employee_evidence"}], [rule | {"destination": "real-gateway"}]):
        private_json(file, bad_grants)
        with pytest.raises(AuthorizationUnavailable):
            profile.check_model_source(credential, probe)
        with pytest.raises(AuthorizationUnavailable):
            LocalProfile(profile.root)
    private_json(file, [rule])
    file.chmod(0o644)
    with pytest.raises(AuthorizationUnavailable):
        profile.check_model_source(credential, probe)

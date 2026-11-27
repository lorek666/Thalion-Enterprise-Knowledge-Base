from hashlib import sha256
import json
from uuid import uuid4

import httpx2
import pytest

from enterprise_kb.modules.sources.originals import ObjectStorageOriginalStore
from enterprise_kb.ports.adapters import HttpObjectStorageAdapter, build_production_port_registry
from enterprise_kb.ports.contracts import ObjectStorageUnavailable
from enterprise_kb.runtime.config import ConfigValidationError, ObjectStorageEndpointConfig, load_production_config_from_env


CREDENTIAL_REF = "env:THALION_TEST_S3_CRED"
ACCESS_KEY = "test-storage-access-id"
SECRET_KEY = "test-storage-secret"
PAYLOAD = b"Approved original bytes"
DIGEST = sha256(PAYLOAD).digest()


@pytest.fixture(autouse=True)
def s3_credential(monkeypatch):
    monkeypatch.setenv("THALION_TEST_S3_CRED", json.dumps({
        "access_key_id": ACCESS_KEY, "secret_access_key": SECRET_KEY,
    }))


def _adapter(config, handler):
    from enterprise_kb.ports.s3 import S3CompatibleObjectStorageAdapter

    return S3CompatibleObjectStorageAdapter(config, transport=httpx2.MockTransport(handler))


@pytest.mark.parametrize(("provider", "endpoint", "bucket", "region", "style", "host", "prefix", "guard"), [
    (None, "https://storage.example:9443", "originals", "us-east-1", "path",
     "storage.example:9443", "/originals", "if-none-match"),
    ("aliyun_oss", "https://s3.oss-cn-hangzhou.aliyuncs.com", "originals", "cn-hangzhou", None,
     "originals.s3.oss-cn-hangzhou.aliyuncs.com", "", "x-oss-forbid-overwrite"),
    ("aliyun_oss", "https://oss.example.com", "originals", "cn-hangzhou", "bucket",
     "oss.example.com", "", "x-oss-forbid-overwrite"),
    ("tencent_cos", "https://cos.ap-guangzhou.myqcloud.com", "originals-1250000000", "ap-guangzhou", None,
     "originals-1250000000.cos.ap-guangzhou.myqcloud.com", "", "x-cos-forbid-overwrite"),
])
def test_s3_signed_roundtrip_and_immutable_writes(provider, endpoint, bucket, region, style, host, prefix, guard):
    key = DIGEST.hex()
    contents = {}
    requests = []

    def handle(request):
        requests.append(request.method)
        assert request.headers["host"] == host
        authorization = request.headers["authorization"]
        assert authorization.startswith(f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/")
        assert f"/{region}/s3/aws4_request" in authorization
        assert SECRET_KEY not in authorization
        assert request.headers["x-amz-content-sha256"] == sha256(request.content).hexdigest()
        if request.url.query:
            assert request.method == "GET" and request.url.query == b"versioning"
            assert request.url.path == f"{prefix}/"
            return httpx2.Response(200, content=b'<VersioningConfiguration xmlns="urn:test"/>')
        assert request.url.path == f"{prefix}/{key}"
        if request.method == "PUT":
            assert request.headers[guard] == ("*" if provider is None else "true")
            assert guard in authorization.partition("SignedHeaders=")[2].partition(",")[0].split(";")
            assert int(request.headers["content-length"]) == len(request.content)
            assert "transfer-encoding" not in request.headers
            if key in contents:
                if provider is None:
                    return httpx2.Response(412)
                return httpx2.Response(409, content=b"<Error><Code>FileAlreadyExists</Code></Error>")
            contents[key] = request.content
            return httpx2.Response(200)
        assert request.method == "GET"
        return httpx2.Response(200, content=contents[key])

    port = _adapter(ObjectStorageEndpointConfig(
        endpoint, bucket, CREDENTIAL_REF, protocol="s3", region=region, s3_provider=provider, addressing_style=style,
    ), handle)
    store = ObjectStorageOriginalStore(port)
    asset = store.stage(key, DIGEST, PAYLOAD)
    assert requests == (["GET"] if provider else []) + ["PUT", "GET"]
    assert store.stage(key, DIGEST, PAYLOAD) == asset
    assert store.read(asset) == PAYLOAD
    with pytest.raises(ObjectStorageUnavailable, match="verification"):
        port.write_immutable(key, bytes(len(PAYLOAD)))
    assert contents[key] == PAYLOAD


@pytest.mark.parametrize(("put_status", "read_body", "error"), [
    (200, bytes(len(PAYLOAD)), "SHA-256"),
    (409, PAYLOAD, "HTTP 409"),
    (403, PAYLOAD, "HTTP 403"),
])
def test_s3_requires_a_verified_write_or_an_explicit_already_exists_response(put_status, read_body, error):
    requests = []

    def handle(request):
        requests.append(request.method)
        if request.method == "PUT":
            return httpx2.Response(put_status)
        return httpx2.Response(200, content=read_body)

    port = _adapter(ObjectStorageEndpointConfig(
        "https://storage.example", "originals", CREDENTIAL_REF, protocol="s3", region="us-east-1",
    ), handle)
    with pytest.raises(ObjectStorageUnavailable, match=error):
        port.write_immutable("original", PAYLOAD)
    assert requests == (["PUT", "GET"] if put_status == 200 else ["PUT"])


@pytest.mark.parametrize(("status", "response"), [
    (403, b"<Error/>"),
    (200, b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
    (200, b"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"),
    (200, b"<ListBucketResult/>"),
    (200, b"not XML"),
])
def test_cloud_s3_write_stops_when_bucket_versioning_cannot_be_proven_off(status, response):
    def handle(request):
        assert request.method == "GET" and request.url.query == b"versioning"
        return httpx2.Response(status, content=response)

    port = _adapter(ObjectStorageEndpointConfig(
        "https://s3.oss-cn-hangzhou.aliyuncs.com", "originals", CREDENTIAL_REF,
        protocol="s3", s3_provider="aliyun_oss", region="cn-hangzhou",
    ), handle)
    with pytest.raises(ObjectStorageUnavailable, match="versioning"):
        port.write_immutable("original", PAYLOAD)


@pytest.mark.parametrize(("status", "body", "error"), [
    (302, PAYLOAD, "HTTP 302"),
    (200, PAYLOAD + b"!", "length"),
    (200, b"short", "length"),
    (200, bytes(len(PAYLOAD)), "SHA-256"),
])
def test_s3_verified_read_fails_closed(status, body, error):
    def handle(request):
        assert request.url.host == "originals.storage.example"
        return httpx2.Response(status, content=body, headers={"Location": "https://another.example/object"})

    port = _adapter(ObjectStorageEndpointConfig(
        "https://storage.example", "originals", CREDENTIAL_REF, protocol="s3", region="us-east-1",
    ), handle)
    with pytest.raises(ObjectStorageUnavailable, match=error):
        port.read_verified("original", DIGEST, len(PAYLOAD))


def test_s3_rejects_bad_credentials_and_ambiguous_keys_before_network(monkeypatch):
    def handle(_request):
        pytest.fail("unexpected network request")

    port = _adapter(ObjectStorageEndpointConfig(
        "https://storage.example", "originals", CREDENTIAL_REF, protocol="s3", region="us-east-1",
    ), handle)
    for key in ("prefix/../original", "prefix/./original", "prefix//original", "prefix/original/"):
        with pytest.raises(ObjectStorageUnavailable, match="key"):
            port.read_verified(key, DIGEST, len(PAYLOAD))
    monkeypatch.setenv("THALION_TEST_S3_CRED", "fake-bearer-value")
    with pytest.raises(ObjectStorageUnavailable, match="credential") as caught:
        port.write_immutable("original", PAYLOAD)
    assert "fake-bearer-value" not in str(caught.value)


def test_s3_env_selects_port_without_changing_default_protocol():
    from enterprise_kb.ports.s3 import S3CompatibleObjectStorageAdapter

    env = {
        "THALION_BUSINESS_TIMEZONE": "Asia/Shanghai",
        "THALION_DATABASE_URL_REF": "env:THALION_DB_URL",
        "THALION_ALLOWED_HOSTS": "kb.example.com",
        "THALION_OIDC_ISSUER": "https://idp.example.com",
        "THALION_OIDC_AUDIENCE": "thalion",
        "THALION_OIDC_JWKS_URL": "https://idp.example.com/jwks",
        "THALION_SOURCE_AUTHORITY_ENDPOINT": "https://authority.example.com",
        "THALION_SOURCE_AUTHORITY_CREDENTIAL_REF": "env:AUTHORITY_SECRET",
        "THALION_SECURITY_AUDIT_ENDPOINT": "https://audit.example.com",
        "THALION_SECURITY_AUDIT_CREDENTIAL_REF": "env:AUDIT_SECRET",
        "THALION_OBJECT_STORAGE_ENDPOINT": "https://cos.ap-guangzhou.myqcloud.com",
        "THALION_OBJECT_STORAGE_BUCKET": "originals-1250000000",
        "THALION_OBJECT_STORAGE_CREDENTIAL_REF": CREDENTIAL_REF,
    }
    refs = {"source_authority_ref": uuid4(), "security_log_ref": uuid4()}
    registry = build_production_port_registry(load_production_config_from_env(env), **refs)
    assert isinstance(registry.object_storage, HttpObjectStorageAdapter)
    env.update(
        THALION_OBJECT_STORAGE_PROTOCOL="s3", THALION_OBJECT_STORAGE_S3_PROVIDER="tencent_cos",
        THALION_OBJECT_STORAGE_REGION="ap-guangzhou",
    )
    registry = build_production_port_registry(load_production_config_from_env(env), **refs)
    assert isinstance(registry.object_storage, S3CompatibleObjectStorageAdapter)
    assert registry.object_storage.storage_kind == "https_object_store"
    assert registry.object_storage.admission == "production_approved"


@pytest.mark.parametrize(("overrides", "error"), [
    ({"protocol": "unknown"}, "protocol"),
    ({"protocol": "thalion"}, "S3"),
    ({"region": None}, "region"),
    ({"s3_provider": "unknown"}, "provider"),
    ({"s3_provider": "aliyun_oss", "addressing_style": "path"}, "addressing_style"),
    ({"s3_provider": "tencent_cos"}, "APPID"),
    ({"bucket": "other.example/escape"}, "bucket"),
    ({"endpoint": "https://object.example/bucket"}, "endpoint"),
    ({"endpoint": "https://object.example?token=value"}, "endpoint"),
])
def test_s3_config_fails_closed_for_ambiguous_or_mistyped_options(overrides, error):
    valid = {
        "endpoint": "https://object.example", "bucket": "originals", "credential_ref": CREDENTIAL_REF,
        "protocol": "s3", "region": "us-east-1",
    }
    with pytest.raises(ConfigValidationError, match=error):
        ObjectStorageEndpointConfig(**(valid | overrides))

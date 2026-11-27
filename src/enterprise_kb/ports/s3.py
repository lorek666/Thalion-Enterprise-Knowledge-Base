from hashlib import sha256
import re
from xml.etree import ElementTree

from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
import httpx2

from enterprise_kb.runtime.config import ObjectStorageEndpointConfig

from .adapters import SecretResolver, _BaseHttpAdapter, _parse_json_strict, _validate_storage_key, resolve_secret_ref
from .contracts import AdmissionMode, ObjectStorageUnavailable, PortUnavailable


OVERWRITE_HEADERS = {
    "aliyun_oss": {"x-oss-forbid-overwrite": "true"},
    "tencent_cos": {"x-cos-forbid-overwrite": "true"},
}
ACCESS_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,256}")
MAX_S3_XML_BYTES = 16 * 1024


def _bounded_bytes(response: httpx2.Response, limit: int) -> bytes:
    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
        raise ObjectStorageUnavailable("Unexpected content encoding from S3 object storage.")
    payload = bytearray()
    for chunk in response.iter_bytes():
        if len(payload) + len(chunk) > limit:
            raise ObjectStorageUnavailable("S3 response exceeds the expected byte length.")
        payload.extend(chunk)
    return bytes(payload)


def _s3_xml(response: httpx2.Response) -> ElementTree.Element:
    body = _bounded_bytes(response, MAX_S3_XML_BYTES).decode("utf-8")
    if "<!" in body:
        raise ValueError("Unexpected declaration in S3 XML.")
    return ElementTree.fromstring(body)


class S3CompatibleObjectStorageAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"
    storage_kind = "https_object_store"

    def __init__(
        self,
        config: ObjectStorageEndpointConfig,
        *,
        timeout_seconds: float = 10.0,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        if config.protocol != "s3" or config.region is None:
            raise ValueError("S3 object storage requires protocol=s3 and a region.")
        super().__init__(
            config.endpoint, config.credential_ref,
            timeout_seconds=timeout_seconds, transport=transport, secret_resolver=secret_resolver,
        )
        endpoint = httpx2.URL(self._endpoint)
        style = config.addressing_style or "virtual"
        if style == "virtual":
            endpoint = endpoint.copy_with(host=f"{config.bucket}.{endpoint.host}")
        elif style == "path":
            endpoint = endpoint.copy_with(path=f"/{config.bucket}")
        self._bucket_url = str(endpoint).rstrip("/")
        self._region = config.region
        self._provider = config.s3_provider

    def _signer(self) -> S3SigV4Auth:
        try:
            raw = resolve_secret_ref(self._credential_ref, external_resolver=self._secret_resolver)
            credential = _parse_json_strict(raw.encode("utf-8"))
            if not isinstance(credential, dict) or credential.keys() != {"access_key_id", "secret_access_key"}:
                raise ValueError("Invalid S3 credential structure.")
            access_key, secret_key = credential["access_key_id"], credential["secret_access_key"]
            if (
                not isinstance(access_key, str) or not ACCESS_KEY_PATTERN.fullmatch(access_key)
                or not isinstance(secret_key, str) or not 1 <= len(secret_key) <= 256
                or not all(33 <= ord(char) <= 126 for char in secret_key)
            ):
                raise ValueError("Invalid S3 credential values.")
        except (PortUnavailable, ValueError):
            raise ObjectStorageUnavailable("S3 credential could not be resolved or is malformed.") from None
        return S3SigV4Auth(Credentials(access_key, secret_key), "s3", self._region)

    def _object_url(self, storage_key: str) -> str:
        key = _validate_storage_key(storage_key)
        if any(segment in {"", "."} for segment in key.split("/")):
            raise ObjectStorageUnavailable("Invalid S3 object key segment.")
        return f"{self._bucket_url}/{key}"

    @staticmethod
    def _request(client, signer, method, url, *, payload=None, headers=None):
        request = AWSRequest(method=method, url=url, data=payload, headers=headers)
        signer.add_auth(request)
        return client.stream(method, url, content=payload, headers=dict(request.headers.items()) | {
            "Accept-Encoding": "identity",
        })

    def _require_unversioned_bucket(self, client: httpx2.Client, signer: S3SigV4Auth) -> None:
        try:
            with self._request(client, signer, "GET", f"{self._bucket_url}/?versioning") as response:
                if response.status_code != 200:
                    raise ObjectStorageUnavailable(f"S3 bucket versioning check returned HTTP {response.status_code}.")
                root = _s3_xml(response)
        except (ValueError, ElementTree.ParseError):
            raise ObjectStorageUnavailable("Malformed S3 bucket versioning response.") from None
        if root.tag.rsplit("}", 1)[-1] != "VersioningConfiguration" or len(root) or (root.text or "").strip():
            raise ObjectStorageUnavailable("S3 bucket versioning must never have been enabled for this provider.")

    def _read(self, client, signer, url, expected_digest: bytes, expected_length: int) -> bytes:
        with self._request(client, signer, "GET", url) as response:
            if response.status_code != 200:
                raise ObjectStorageUnavailable(f"S3 object read returned HTTP {response.status_code}.")
            payload = _bounded_bytes(response, expected_length)
        if len(payload) != expected_length or sha256(payload).digest() != expected_digest:
            raise ObjectStorageUnavailable("S3 object failed length or SHA-256 verification.")
        return payload

    def read_verified(self, storage_key: str, expected_digest: bytes, expected_length: int) -> bytes:
        if not isinstance(expected_digest, bytes) or len(expected_digest) != 32 or type(expected_length) is not int or expected_length < 0:
            raise ObjectStorageUnavailable("Invalid expected digest or byte length.")
        url = self._object_url(storage_key)
        signer = self._signer()
        try:
            with self._client() as client:
                return self._read(client, signer, url, expected_digest, expected_length)
        except httpx2.HTTPError:
            raise ObjectStorageUnavailable("Failed to read verified S3 object bytes.") from None

    def write_immutable(self, storage_key: str, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or not payload:
            raise ObjectStorageUnavailable("S3 storage requires a non-empty byte payload.")
        url = self._object_url(storage_key)
        digest = sha256(payload).digest()
        signer = self._signer()
        guard = OVERWRITE_HEADERS.get(self._provider, {"If-None-Match": "*"})
        headers = {"Content-Type": "application/octet-stream", "Content-Length": str(len(payload))} | guard
        try:
            with self._client() as client:
                if self._provider is not None:
                    self._require_unversioned_bucket(client, signer)
                with self._request(client, signer, "PUT", url, payload=payload, headers=headers) as response:
                    status = response.status_code
                    existing = status == 412 and self._provider is None
                    if status == 409 and self._provider is not None:
                        error_xml = _s3_xml(response)
                        existing = (
                            error_xml.tag.rsplit("}", 1)[-1] == "Error"
                            and error_xml.findtext("{*}Code") == "FileAlreadyExists"
                        )
                    if status not in {200, 201} and not existing:
                        raise ObjectStorageUnavailable(f"Immutable S3 object write refused with HTTP {status}.")
                self._read(client, signer, url, digest, len(payload))
        except (httpx2.HTTPError, ValueError, ElementTree.ParseError):
            raise ObjectStorageUnavailable("Failed to write and verify immutable S3 object.") from None
        return digest

import argparse
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import signal
import sys
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg import Connection, Error
from sqlalchemy.exc import ArgumentError

from enterprise_kb import runtime_alerts
from enterprise_kb.database import local_connection_factory, production_connection_factory, require_current_schema
from enterprise_kb.modules.evidence.pdf_evidence import Tesseract
from enterprise_kb.modules.evidence.processing import (
    ProcessingDependencyUnavailable,
    ProcessingNotAdmitted,
    process_evidence_job,
)
from enterprise_kb.modules.retrieval import lexical, vector
from enterprise_kb.modules.sources import connector_sync
from enterprise_kb.modules.sources.originals import (
    ObjectStorageOriginalStore,
    OriginalIntegrityError,
    SyntheticOriginalStore,
)
from enterprise_kb.modules.sources.registry import (
    PRODUCTION_ADMISSION,
    SYNTHETIC_ADMISSION,
    store_admission,
)
from enterprise_kb.modules.sources.source_revocations import SourceRevocationAuthority
from enterprise_kb.ports.adapters import (
    build_production_port_registry,
    embedding_options_from_env,
    model_gateway_options_from_env,
    resolve_secret_ref,
)
from enterprise_kb.ports.contracts import (
    EmbeddingProviderPort,
    PortRegistry,
    PortUnavailable,
    ProductionIsolationError,
    SecurityAuditLogPort,
    SourceConnectorPort,
)
from enterprise_kb.ports.source_connectors import connector_for_source
from enterprise_kb.runtime.audit_sink import (
    SecurityAuditDispatcher,
    SecurityAuditEvent,
    metadata_digest,
)
from enterprise_kb.runtime.config import ConfigValidationError, load_production_config_from_env
from enterprise_kb.runtime.jobs import ExternalCallPending, LeaseLost, claim_job, retry_job
from enterprise_kb.transport.evidence import parse_ref


@dataclass(frozen=True)
class WorkerConfig:
    connect: Callable[[], Connection]
    store: SyntheticOriginalStore | ObjectStorageOriginalStore
    connector: SourceConnectorPort | None = None
    source_refs: tuple[UUID, ...] = ()
    revocation_authority: SourceRevocationAuthority | None = None
    embedding_provider: EmbeddingProviderPort | None = None
    pdf_ocr: Tesseract | None = None
    security_audit_log: SecurityAuditLogPort | None = None
    strict_audit_sink: bool = False
    reconcile_on_sync: bool = False
    max_sync_pages_per_source: int = 20
    max_parse_jobs_per_cycle: int = 20
    max_index_versions_per_cycle: int = 20
    enable_sync: bool = True
    enable_parse: bool = True
    enable_index: bool = True
    enable_alerts: bool = True
    interval_seconds: float = 15.0
    alert_webhook: runtime_alerts.AlertWebhook | None = None

    @classmethod
    def from_port_registry(
        cls,
        connect: Callable[[], Connection],
        registry: PortRegistry,
        *,
        store: SyntheticOriginalStore | ObjectStorageOriginalStore | None = None,
        source_refs: tuple[UUID, ...] = (),
        revocation_authority: SourceRevocationAuthority | None = None,
        pdf_ocr: Tesseract | None = None,
        reconcile_on_sync: bool = False,
        max_sync_pages_per_source: int = 20,
        max_parse_jobs_per_cycle: int = 20,
        max_index_versions_per_cycle: int = 20,
        enable_sync: bool = True,
        enable_parse: bool = True,
        enable_index: bool = True,
        enable_alerts: bool = True,
        interval_seconds: float = 15.0,
        alert_webhook: runtime_alerts.AlertWebhook | None = None,
    ) -> "WorkerConfig":
        registry.validate()
        if store is None:
            if registry.object_storage is None:
                raise ValueError("PortRegistry requires an object_storage port when store is omitted.")
            resolved_store: SyntheticOriginalStore | ObjectStorageOriginalStore = ObjectStorageOriginalStore(
                registry.object_storage
            )
        else:
            resolved_store = store

        try:
            resolved_admission = store_admission(resolved_store)
        except ValueError as exc:
            raise ProductionIsolationError(str(exc)) from None

        if registry.mode == "production":
            if resolved_admission != PRODUCTION_ADMISSION:
                raise ProductionIsolationError("Production worker requires a production_approved original store.")
        else:
            if resolved_admission != SYNTHETIC_ADMISSION:
                raise ProductionIsolationError("synthetic_local worker requires a synthetic_only original store.")

        return cls(
            connect=connect,
            store=resolved_store,
            connector=registry.source_connector,
            source_refs=source_refs,
            revocation_authority=revocation_authority,
            embedding_provider=registry.embedding_provider,
            pdf_ocr=pdf_ocr,
            security_audit_log=registry.security_audit_log,
            strict_audit_sink=(registry.mode == "production"),
            reconcile_on_sync=reconcile_on_sync,
            max_sync_pages_per_source=max_sync_pages_per_source,
            max_parse_jobs_per_cycle=max_parse_jobs_per_cycle,
            max_index_versions_per_cycle=max_index_versions_per_cycle,
            enable_sync=enable_sync,
            enable_parse=enable_parse,
            enable_index=enable_index,
            enable_alerts=enable_alerts,
            interval_seconds=interval_seconds,
            alert_webhook=alert_webhook,
        )


@dataclass(frozen=True)
class WorkerCycleReport:
    started_at: str
    finished_at: str
    synced_sources: tuple[dict[str, Any], ...] = ()
    parsed_jobs: tuple[dict[str, Any], ...] = ()
    lexical_indexed: tuple[dict[str, Any], ...] = ()
    vector_indexed: tuple[dict[str, Any], ...] = ()
    alerts: tuple[dict[str, Any], ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "synced_sources": list(self.synced_sources),
            "parsed_jobs": list(self.parsed_jobs),
            "lexical_indexed": list(self.lexical_indexed),
            "vector_indexed": list(self.vector_indexed),
            "alerts": list(self.alerts),
            "errors": list(self.errors),
        }


def _discover_sources(connection: Connection, *, admission: str) -> tuple[UUID, ...]:
    with connection.transaction():
        rows = connection.execute(
            """
            SELECT id.public_id
            FROM thalion.source AS src
            JOIN thalion.object_identity AS id
              ON (id.org_id, id.space_id, id.object_type, id.object_id)
               = (src.org_id, src.space_id, src.identity_type, src.source_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
               = (src.org_id, src.space_id, src.source_id, src.contract_revision)
            JOIN thalion.principal AS collector
              ON (collector.org_id, collector.principal_id) = (contract.org_id, contract.collector_id)
            WHERE collector.principal_type = 'service' AND NOT collector.disabled
              AND src.lifecycle = 'active'
              AND contract.admission = %s
            ORDER BY src.org_id, src.space_id, src.source_id
            """,
            (admission,),
        ).fetchall()
    return tuple(row[0] for row in rows)


def _discover_claimable_parse_jobs(
    connection: Connection,
    limit: int,
    *,
    admission: str,
) -> list[tuple[int, UUID, UUID, int]]:
    with connection.transaction():
        rows = connection.execute(
            """
            SELECT job.org_id, job.job_id, job.target_ref, contract.processor_id
            FROM thalion.job AS job
            JOIN thalion.object_identity AS ver_id
              ON (ver_id.org_id, ver_id.space_id, ver_id.object_type, ver_id.public_id)
               = (job.org_id, job.space_id, 'document_version', job.target_ref)
            JOIN thalion.document_version AS version
              ON (version.org_id, version.space_id, version.version_id)
               = (ver_id.org_id, ver_id.space_id, ver_id.object_id)
            JOIN thalion.source AS src
              ON (src.org_id, src.space_id, src.source_id)
               = (version.org_id, version.space_id, version.source_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
               = (src.org_id, src.space_id, src.source_id, src.contract_revision)
            JOIN thalion.principal AS processor
              ON (processor.org_id, processor.principal_id) = (contract.org_id, contract.processor_id)
            LEFT JOIN thalion.job_attempt AS attempt
              ON attempt.org_id = job.org_id AND attempt.job_id = job.job_id
             AND attempt.generation = job.generation AND attempt.outcome = 'running'
            WHERE job.stage = 'parse'
              AND job.result_ref IS NULL
              AND processor.principal_type = 'service'
              AND NOT processor.disabled
              AND src.lifecycle = 'active'
              AND contract.admission = %s
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.external_call_budget AS budget
                  WHERE (budget.org_id, budget.job_id) = (job.org_id, job.job_id)
              )
              AND (
                  (job.state = 'queued' AND (job.generation = 0 OR job.available_at <= clock_timestamp()))
                  OR (job.state = 'running' AND attempt.lease_expires_at <= clock_timestamp())
              )
            ORDER BY job.available_at, job.job_id
            LIMIT %s
            """,
            (admission, limit),
        ).fetchall()
    return [(int(r[0]), r[1], r[2], int(r[3])) for r in rows]


def _discover_unindexed_runs(
    connection: Connection,
    *,
    kind: str,
    model_id: str | None,
    limit: int,
    admission: str,
) -> list[tuple[UUID, UUID, UUID]]:
    with connection.transaction():
        if kind == "lexical":
            index_filter = """
                NOT EXISTS (
                    SELECT 1 FROM thalion.synthetic_lexical_index AS idx
                    WHERE idx.run_ref = latest.run_ref AND idx.profile = %s
                )
            """
            params = (admission, lexical.PROFILE, limit)
        else:
            index_filter = """
                NOT EXISTS (
                    SELECT 1 FROM thalion.synthetic_vector_index AS idx
                    WHERE idx.run_ref = latest.run_ref AND idx.model_id = %s
                )
            """
            params = (admission, model_id, limit)

        rows = connection.execute(
            f"""
            WITH latest_runs AS (
                SELECT DISTINCT ON (org_id, space_id, version_id)
                       org_id, space_id, version_id, run_ref, passage_count
                FROM thalion.processing_run
                ORDER BY org_id, space_id, version_id, configuration_revision DESC
            )
            SELECT space_obj.public_id, ver_obj.public_id, latest.run_ref
            FROM latest_runs AS latest
            JOIN thalion.document_version AS version
              ON (version.org_id, version.space_id, version.version_id)
               = (latest.org_id, latest.space_id, latest.version_id)
            JOIN thalion.source AS src
              ON (src.org_id, src.space_id, src.source_id)
               = (version.org_id, version.space_id, version.source_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
               = (src.org_id, src.space_id, src.source_id, src.contract_revision)
            JOIN thalion.object_identity AS space_obj
              ON (space_obj.org_id, space_obj.space_id, space_obj.object_type, space_obj.object_id)
               = (latest.org_id, latest.space_id, 'space', latest.space_id)
            JOIN thalion.object_identity AS ver_obj
              ON (ver_obj.org_id, ver_obj.space_id, ver_obj.object_type, ver_obj.object_id)
               = (latest.org_id, latest.space_id, 'document_version', latest.version_id)
            WHERE latest.passage_count > 0
              AND src.lifecycle = 'active'
              AND contract.admission = %s
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.current_version_hold AS hold
                  WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
                      = (version.org_id, version.space_id, version.version_id, 'establish')
              )
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.rule_use_stop AS stop
                  WHERE stop.version_id = version.version_id
              )
              AND NOT thalion.document_source_deleted(
                  version.org_id, version.space_id, version.source_id, version.document_id
              )
              AND {index_filter}
            ORDER BY latest.org_id, latest.space_id, latest.version_id
            LIMIT %s
            """,
            params,
        ).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def _discover_spaces(connection: Connection, *, admission: str) -> tuple[tuple[int, UUID], ...]:
    with connection.transaction():
        rows = connection.execute(
            """
            SELECT identity.org_id, identity.public_id
            FROM thalion.object_identity AS identity
            JOIN thalion.space AS space
              ON (identity.org_id, identity.object_type, identity.object_id) = (space.org_id, 'space', space.space_id)
            JOIN thalion.principal AS owner
              ON (owner.org_id, owner.principal_id) = (space.org_id, space.owner_principal_id)
            WHERE thalion.issuer_matches_admission(owner.authority_issuer, %s)
            ORDER BY identity.org_id, identity.object_id
            """, (admission,),
        ).fetchall()
    return tuple((int(r[0]), r[1]) for r in rows)


def run_worker_cycle(config: WorkerConfig) -> WorkerCycleReport:
    """Execute one deterministic background cycle: sync -> parse/OCR -> index -> alerts."""
    started_at = datetime.now(UTC).isoformat()
    synced_sources: list[dict[str, Any]] = []
    parsed_jobs: list[dict[str, Any]] = []
    lexical_indexed: list[dict[str, Any]] = []
    vector_indexed: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    errors: list[str] = []
    admission = store_admission(config.store)
    audit_dispatcher = SecurityAuditDispatcher(config.security_audit_log, strict=config.strict_audit_sink)

    # Phase 1: Source sync
    if config.enable_sync and config.connector is not None:
        try:
            with config.connect() as conn:
                source_refs = config.source_refs or _discover_sources(conn, admission=admission)
            for source_ref in source_refs:
                source_connector = connector_for_source(config.connector, source_ref)
                if source_connector is None:
                    if source_ref in config.source_refs:
                        errors.append(f"sync[{source_ref}]: no connector configured")
                    continue
                try:
                    with config.connect() as conn:
                        report = connector_sync.sync_source_from_connector(
                            conn,
                            source_ref,
                            source_connector,
                            config.store,
                            revocation_authority=config.revocation_authority,
                            reconcile=config.reconcile_on_sync,
                            max_pages=config.max_sync_pages_per_source,
                            audit_dispatcher=audit_dispatcher,
                        )
                        synced_sources.append(report.to_dict())
                        if report.error:
                            errors.append(f"sync[{source_ref}]: {report.error}")
                except Exception as exc:
                    errors.append(f"sync[{source_ref}]: {exc}")
                    synced_sources.append({"source_id": str(source_ref), "status": "error", "error": str(exc)})
        except Exception as exc:
            errors.append(f"sync_discovery: {exc}")

    # Phase 2: Parse / OCR queued jobs
    if config.enable_parse:
        try:
            with config.connect() as conn:
                candidates = _discover_claimable_parse_jobs(
                    conn, config.max_parse_jobs_per_cycle, admission=admission
                )
            for org_id, job_id, version_ref, processor_id in candidates:
                try:
                    with config.connect() as conn:
                        lease = claim_job(
                            conn, org_id, "parse", processor_id, timedelta(minutes=2), job_id=job_id
                        )
                        if lease is None:
                            continue
                        try:
                            result = process_evidence_job(conn, lease, config.store, pdf_ocr=config.pdf_ocr)
                            parsed_jobs.append({
                                "job_id": str(job_id),
                                "version_id": str(version_ref),
                                "outcome": result.outcome,
                                "run_id": str(result.run_ref),
                            })
                        except (
                            OriginalIntegrityError,
                            ProcessingDependencyUnavailable,
                            ProcessingNotAdmitted,
                        ) as exc:
                            try:
                                retry_job(conn, lease, delay=timedelta(seconds=30))
                            except (Error, LeaseLost, ExternalCallPending):
                                pass
                            errors.append(f"parse[{version_ref}]: {exc}")
                            parsed_jobs.append({
                                "job_id": str(job_id),
                                "version_id": str(version_ref),
                                "outcome": "retry_scheduled",
                                "error": str(exc),
                            })
                except (LeaseLost, ExternalCallPending, Error, ValueError) as exc:
                    errors.append(f"parse_claim[{job_id}]: {exc}")
        except Exception as exc:
            errors.append(f"parse_discovery: {exc}")

    # Phase 3: Lexical & Vector indexing
    if config.enable_index:
        try:
            with config.connect() as conn:
                lex_targets = _discover_unindexed_runs(
                    conn,
                    kind="lexical",
                    model_id=None,
                    limit=config.max_index_versions_per_cycle,
                    admission=admission,
                )
            for space_ref, version_ref, run_ref in lex_targets:
                try:
                    with config.connect() as conn:
                        index_ref = lexical.build_index(conn, config.store, space_ref, version_ref, run_ref)
                    lexical_indexed.append({
                        "space_id": str(space_ref),
                        "version_id": str(version_ref),
                        "run_id": str(run_ref),
                        "index_id": str(index_ref),
                        "status": "indexed",
                    })
                except lexical.LexicalIndexUnavailable:
                    lexical_indexed.append({
                        "space_id": str(space_ref),
                        "version_id": str(version_ref),
                        "run_id": str(run_ref),
                        "status": "skipped_not_ready",
                    })
                except (OriginalIntegrityError, Error, ValueError) as exc:
                    errors.append(f"lexical[{version_ref}]: {exc}")
        except Exception as exc:
            errors.append(f"lexical_discovery: {exc}")

        if config.embedding_provider is not None:
            try:
                with config.connect() as conn:
                    vec_targets = _discover_unindexed_runs(
                        conn,
                        kind="vector",
                        model_id=config.embedding_provider.model_id,
                        limit=config.max_index_versions_per_cycle,
                        admission=admission,
                    )
                for space_ref, version_ref, run_ref in vec_targets:
                    try:
                        with config.connect() as conn:
                            index_ref = vector.build_vector_index(
                                conn, config.store, space_ref, version_ref, run_ref, config.embedding_provider
                            )
                        vector_indexed.append({
                            "space_id": str(space_ref),
                            "version_id": str(version_ref),
                            "run_id": str(run_ref),
                            "index_id": str(index_ref),
                            "status": "indexed",
                        })
                    except vector.VectorIndexUnavailable:
                        vector_indexed.append({
                            "space_id": str(space_ref),
                            "version_id": str(version_ref),
                            "run_id": str(run_ref),
                            "status": "skipped_not_ready",
                        })
                    except (OriginalIntegrityError, Error, ValueError) as exc:
                        errors.append(f"vector[{version_ref}]: {exc}")
            except Exception as exc:
                errors.append(f"vector_discovery: {exc}")

    # Phase 4: Runtime alert patrol
    if config.enable_alerts:
        try:
            with config.connect() as conn:
                spaces = _discover_spaces(conn, admission=admission)
            for org_id, space_ref in spaces:
                try:
                    with config.connect() as conn:
                        detail = runtime_alerts.poll(conn, space_ref)
                    alerts.append(detail)
                    if detail["transitions"]["raised"]:
                        audit_dispatcher.emit(
                            SecurityAuditEvent(
                                event_type="security.runtime_alert_raised",
                                request_id=uuid4(),
                                org_id=org_id,
                                space_ref=space_ref,
                                actor_principal_id=0,
                                operation="runtime_alert_patrol",
                                outcome="raised",
                                resource_ref=str(space_ref),
                                detail_digest=metadata_digest(space_ref, detail["transitions"]["raised"]),
                            )
                        )
                    if config.alert_webhook is not None:
                        with config.connect() as conn:
                            detail["webhook_delivered"] = runtime_alerts.deliver_pending(conn, org_id, space_ref, config.alert_webhook)
                except (ValueError, Error, PortUnavailable) as exc:
                    errors.append(f"alerts[{space_ref}]: {exc}")
        except Exception as exc:
            errors.append(f"alerts_discovery: {exc}")

    return WorkerCycleReport(
        started_at=started_at,
        finished_at=datetime.now(UTC).isoformat(),
        synced_sources=tuple(synced_sources),
        parsed_jobs=tuple(parsed_jobs),
        lexical_indexed=tuple(lexical_indexed),
        vector_indexed=tuple(vector_indexed),
        alerts=tuple(alerts),
        errors=tuple(errors),
    )


def run_worker_loop(
    config: WorkerConfig,
    *,
    stop_event: Event | None = None,
    max_cycles: int | None = None,
    on_cycle: Callable[[WorkerCycleReport], None] | None = None,
) -> list[WorkerCycleReport]:
    """Run continuous background cycles until stop_event is set or max_cycles is reached."""
    stopper = stop_event or Event()
    reports: list[WorkerCycleReport] = []
    cycles = 0
    while not stopper.is_set():
        report = run_worker_cycle(config)
        reports.append(report)
        if on_cycle is not None:
            on_cycle(report)
        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            break
        stopper.wait(timeout=max(0.1, config.interval_seconds))
    return reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Thalion 后台自动化守护进程（同步、解析/OCR、索引构建与告警巡检）")
    parser.add_argument(
        "--mode",
        choices=("synthetic_local", "production"),
        default="synthetic_local",
        help="运行模式（默认 synthetic_local；production 从环境变量装配生产端口）",
    )
    parser.add_argument("--originals", type=Path, help="私有原件目录绝对路径（synthetic_local 模式必填）")
    parser.add_argument("--database-url", default="", help="数据库连接串（默认读取 THALION_DATABASE_URL）")
    parser.add_argument("--once", action="store_true", help="仅执行一轮后台巡检并输出 JSON 摘要后退出")
    parser.add_argument("--check-config", action="store_true", help="校验后台配置和数据库后退出；生产模式同时核对迁移版本")
    parser.add_argument("--interval-seconds", type=float, default=15.0, help="常驻循环轮询间隔秒数")
    parser.add_argument("--source-id", type=UUID, action="append", default=[], help="指定同步来源 UUID（可重复）")
    parser.add_argument("--reconcile", action="store_true", help="同步后执行全量清单对账")
    parser.add_argument("--tesseract", type=Path, help="Tesseract 可执行文件绝对路径")
    parser.add_argument("--tessdata", type=Path, help="tessdata 目录绝对路径")
    parser.add_argument("--embedding-synthetic-model", default="", help="可选：启用本机合成向量模型 ID 自动构建向量索引")
    parser.add_argument("--disable-sync", action="store_true")
    parser.add_argument("--disable-parse", action="store_true")
    parser.add_argument("--disable-index", action="store_true")
    parser.add_argument("--disable-alerts", action="store_true")
    args = parser.parse_args(argv)

    if bool(args.tesseract) != bool(args.tessdata) or (
        args.tesseract and not (args.tesseract.is_absolute() and args.tessdata.is_absolute())
    ):
        parser.error("--tesseract 和 --tessdata 须同时提供绝对路径。")
    if args.interval_seconds <= 0:
        parser.error("--interval-seconds 必须为正数。")

    ocr = Tesseract(args.tesseract, args.tessdata) if args.tesseract else None
    if args.mode == "production":
        if args.originals is not None or args.database_url or args.embedding_synthetic_model:
            parser.error("production 模式禁止使用合成目录、明文数据库连接串或本机合成向量参数。")
        try:
            deployment = load_production_config_from_env(os.environ)
            source_authority_ref = parse_ref((os.environ.get("THALION_SOURCE_AUTHORITY_REF") or "").strip())
            security_log_ref = parse_ref((os.environ.get("THALION_SECURITY_AUDIT_LOG_REF") or "").strip())
            model_options = model_gateway_options_from_env(os.environ)
            embedding_options = embedding_options_from_env(os.environ)
            registry = build_production_port_registry(
                deployment,
                source_authority_ref=source_authority_ref,
                security_log_ref=security_log_ref,
                source_connector_system=(os.environ.get("THALION_SOURCE_CONNECTOR_SYSTEM") or "").strip() or None,
                source_connector_map_ref=(os.environ.get("THALION_SOURCE_CONNECTOR_MAP_REF") or "").strip() or None,
                **model_options,
                **embedding_options,
            )
            db_url = resolve_secret_ref(deployment.database_url_ref)
            connect = production_connection_factory(db_url)
            config = WorkerConfig.from_port_registry(
                connect,
                registry,
                source_refs=tuple(args.source_id),
                pdf_ocr=ocr,
                reconcile_on_sync=args.reconcile,
                enable_sync=not args.disable_sync,
                enable_parse=not args.disable_parse,
                enable_index=not args.disable_index,
                enable_alerts=not args.disable_alerts,
                interval_seconds=args.interval_seconds,
                alert_webhook=runtime_alerts.AlertWebhook.from_env(os.environ),
            )
        except (
            OSError,
            ValueError,
            ArgumentError,
            ConfigValidationError,
            ProductionIsolationError,
            PortUnavailable,
            psycopg.Error,
        ) as exc:
            print(f"FAIL 无法验证生产模式守护进程配置或外部端口：{exc}", file=sys.stderr)
            return 1
        try:
            with connect() as conn:
                require_current_schema(conn)
        except (ValueError, psycopg.Error):
            print("FAIL 无法确认生产数据库可用且已完成迁移。请检查连接并先执行数据库迁移。", file=sys.stderr)
            return 1
        if args.check_config:
            summary = {
                "status": "ok",
                "mode": "production",
                "admission": store_admission(config.store),
                "connector_configured": config.connector is not None,
                "embedding_configured": config.embedding_provider is not None,
                "strict_audit_sink": config.strict_audit_sink,
                "alert_webhook_configured": config.alert_webhook is not None,
            }
            print(json.dumps(summary, ensure_ascii=False))
            return 0
    else:
        if args.originals is None:
            parser.error("synthetic_local 模式必须提供 --originals。")
        embedding_provider = (
            vector.resolve_synthetic_embedding_provider(args.embedding_synthetic_model)
            if args.embedding_synthetic_model
            else None
        )
        db_url = args.database_url or os.environ.get("THALION_DATABASE_URL", "")
        try:
            connect = local_connection_factory(db_url)
            store = SyntheticOriginalStore(args.originals)
        except (OSError, ValueError, ArgumentError) as exc:
            print(f"FAIL 无法初始化守护进程连接或原件存储：{exc}", file=sys.stderr)
            return 1

        config = WorkerConfig(
            connect=connect,
            store=store,
            source_refs=tuple(args.source_id),
            embedding_provider=embedding_provider,
            pdf_ocr=ocr,
            reconcile_on_sync=args.reconcile,
            enable_sync=not args.disable_sync,
            enable_parse=not args.disable_parse,
            enable_index=not args.disable_index,
            enable_alerts=not args.disable_alerts,
            interval_seconds=args.interval_seconds,
        )
        if args.check_config:
            try:
                with connect() as conn:
                    conn.execute("SELECT 1").fetchone()
            except psycopg.Error as exc:
                print(f"FAIL 本机数据库连接校验失败：{exc}", file=sys.stderr)
                return 1
            summary = {
                "status": "ok",
                "mode": "synthetic_local",
                "admission": store_admission(config.store),
                "embedding_configured": config.embedding_provider is not None,
            }
            print(json.dumps(summary, ensure_ascii=False))
            return 0

    if args.once:
        report = run_worker_cycle(config)
        print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0 if not report.errors else 2

    stop_event = Event()

    def _handle_stop(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    run_worker_loop(
        config,
        stop_event=stop_event,
        on_cycle=lambda rep: print(
            json.dumps(rep.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            flush=True,
        ),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

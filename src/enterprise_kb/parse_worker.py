import argparse
import json
import os
from pathlib import Path
import sys
from uuid import UUID

import psycopg
from sqlalchemy.exc import ArgumentError

from enterprise_kb.database import local_connection_factory
from enterprise_kb.modules.evidence.pdf_evidence import Tesseract
from enterprise_kb.modules.evidence.processing import (
    ProcessingDependencyUnavailable, ProcessingNotAdmitted, process_registered_version,
)
from enterprise_kb.modules.sources.originals import OriginalIntegrityError, SyntheticOriginalStore
from enterprise_kb.runtime.jobs import ExternalCallPending, LeaseLost


def main() -> int:
    parser = argparse.ArgumentParser(description="为一个已登记的本机合成版本执行首轮解析。")
    parser.add_argument("--originals", type=Path, required=True)
    parser.add_argument("--version-id", type=UUID, required=True)
    parser.add_argument("--processor-id", type=UUID, required=True)
    parser.add_argument("--tesseract", type=Path)
    parser.add_argument("--tessdata", type=Path)
    arguments = parser.parse_args()
    if bool(arguments.tesseract) != bool(arguments.tessdata) or (
        arguments.tesseract and not (arguments.tesseract.is_absolute() and arguments.tessdata.is_absolute())
    ):
        parser.error("--tesseract 和 --tessdata 须同时提供绝对路径。")
    ocr = Tesseract(arguments.tesseract, arguments.tessdata) if arguments.tesseract else None
    try:
        connect = local_connection_factory(os.environ.get("THALION_DATABASE_URL", ""))
        with connect() as connection:
            store = SyntheticOriginalStore(arguments.originals)
            state, run_ref = process_registered_version(
                connection, arguments.version_id, arguments.processor_id, store, pdf_ocr=ocr,
            )
    except ProcessingNotAdmitted:
        print("FAIL 当前合成来源或处理服务不允许解析该版本。", file=sys.stderr)
        return 1
    except (LeaseLost, ExternalCallPending, OriginalIntegrityError, ProcessingDependencyUnavailable):
        print("RETRY 未接收解析结果；请核对原件、依赖或租约。", file=sys.stderr)
        return 2
    except (OSError, ValueError, ArgumentError, psycopg.Error):
        print("FAIL 无法执行合成解析；请核对本机数据库和私有原件目录。", file=sys.stderr)
        return 1
    if run_ref is None:
        print("RETRY 当前没有可领取的首轮解析任务。", file=sys.stderr)
        return 2
    print(json.dumps({"state": state, "run_id": str(run_ref)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

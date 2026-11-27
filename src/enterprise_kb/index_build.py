import argparse
import os
from pathlib import Path
import sys
from uuid import UUID

import psycopg
from sqlalchemy.exc import ArgumentError

from enterprise_kb.database import local_connection_factory
from enterprise_kb.modules.retrieval.lexical import LexicalIndexUnavailable, build_index
from enterprise_kb.modules.retrieval.vector import (
    DEFAULT_MODEL_ID,
    VectorIndexUnavailable,
    build_vector_index,
    resolve_synthetic_embedding_provider,
)
from enterprise_kb.modules.sources.originals import OriginalIntegrityError, SyntheticOriginalStore
from enterprise_kb.ports.contracts import EmbeddingPortUnavailable


def main() -> int:
    parser = argparse.ArgumentParser(description="为本机开发库中已审核的合成转录构建词项或向量索引。")
    parser.add_argument("--originals", type=Path, required=True)
    parser.add_argument("--space-id", type=UUID, required=True)
    parser.add_argument("--version-id", type=UUID, required=True)
    parser.add_argument("--run-id", type=UUID, required=True)
    parser.add_argument("--mode", choices=["lexical", "vector"], default="lexical")
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID)
    arguments = parser.parse_args()
    try:
        connect = local_connection_factory(os.environ.get("THALION_DATABASE_URL", ""))
        store = SyntheticOriginalStore(arguments.originals)
        with connect() as connection:
            if arguments.mode == "vector":
                provider = resolve_synthetic_embedding_provider(arguments.model_id)
                index = build_vector_index(
                    connection, store, arguments.space_id, arguments.version_id, arguments.run_id, provider,
                )
            else:
                index = build_index(connection, store, arguments.space_id, arguments.version_id, arguments.run_id)
    except (
        OSError,
        ValueError,
        ArgumentError,
        psycopg.Error,
        LexicalIndexUnavailable,
        VectorIndexUnavailable,
        EmbeddingPortUnavailable,
        OriginalIntegrityError,
    ):
        print("FAIL 无法构建合成索引。请核对范围、当前转录审核、模型标识和原件。", file=sys.stderr)
        return 1
    print(index)
    return 0


if __name__ == "__main__":
    sys.exit(main())

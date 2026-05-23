#!/bin/sh
set -eu

JAVA_BIN="$(command -v java || true)"
if [ -n "$JAVA_BIN" ]; then
    export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$JAVA_BIN")")")"
fi

PYTHON_BIN="$(command -v python)"
export PYSPARK_PYTHON="${PYSPARK_PYTHON:-$PYTHON_BIN}"
export PYSPARK_DRIVER_PYTHON="${PYSPARK_DRIVER_PYTHON:-$PYTHON_BIN}"

case "${1:-app}" in
    app)
        shift || true
        exec python -m streamlit run --server.address=0.0.0.0 --server.port=8501 app/streamlit_app.py
        ;;
    pipeline|daily-pipeline)
        shift || true
        exec python src/pipeline/daily_pipeline.py "$@"
        ;;
    shell)
        exec sh
        ;;
    *)
        exec "$@"
        ;;
esac

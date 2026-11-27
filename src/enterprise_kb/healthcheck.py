from http.client import HTTPConnection, HTTPException
import os


def main() -> int:
    try:
        port = int(os.environ.get("THALION_HEALTHCHECK_PORT") or os.environ.get("THALION_APP_PORT", "8765"))
        host = os.environ.get("THALION_ALLOWED_HOSTS", "").split(",", 1)[0].strip() or "127.0.0.1"
        client = HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            client.request("GET", "/health/ready", headers={"Host": host})
            return int(client.getresponse().status != 200)
        finally:
            client.close()
    except (OSError, HTTPException, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

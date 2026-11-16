"""Run with:  python -m app   (serves http://127.0.0.1:8000, loopback only)"""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:create_app",
        factory=True,
        host="127.0.0.1",
        port=int(os.environ.get("QR_PORT", "8000")),
        log_level="info",
    )

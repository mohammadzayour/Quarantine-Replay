"""FastAPI application.

Route groups, by trust:
  /api/worlds/{world}/tool-calls  tool route  - untrusted callers, cannot create approvals
  /api/analyst/approvals          analyst route - the only place approvals are created
  /api/demo/*                     demo controls (capture, replay, contain, reset)
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import config
from .demo import Demo, DemoError
from .models import ApprovalRequest, CaptureRequest, ReplayRequest, ResetRequest, ToolCall

CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"


def create_app(data_dir: Path | None = None,
               live_runner: Callable[[str], dict[str, Any]] | None = None) -> FastAPI:
    config.load_dotenv()
    demo = Demo(Path(data_dir) if data_dir else config.data_dir(), live_runner=live_runner)

    app = FastAPI(title="Quarantine Replay", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.demo = demo
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.allowed_hosts())

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Refuse state-changing requests that a different website sent from the browser.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and urlsplit(origin).netloc != request.headers.get("host"):
                return JSONResponse({"detail": "Cross-origin request refused."}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(DemoError)
    async def demo_error(_: Request, exc: DemoError):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    # ------------------------------------------------------------- read

    @app.get("/api/state")
    def get_state():
        return demo.state()

    @app.get("/api/worlds/{world}/app-health")
    def app_health(world: str):
        if world not in demo.worlds:
            raise DemoError(404, "Unknown world.")
        return demo.worlds[world].app_health()

    # ------------------------------------------------------ demo controls

    @app.post("/api/demo/capture")
    def capture(body: CaptureRequest):
        if body.mode == "live":
            return demo.capture_live(body.scenario)
        if body.scenario != "poisoned":
            raise DemoError(422, "The fixture exists only for the poisoned log.")
        return demo.capture_fixture()

    @app.post("/api/demo/replay")
    def replay(body: ReplayRequest):
        return demo.replay(body.capture_id)

    @app.post("/api/demo/contain-workstation")
    def contain_workstation():
        return demo.contain_workstation()

    @app.post("/api/demo/reset")
    def reset(body: ResetRequest | None = None):
        return demo.reset(keep_live_history=bool(body and body.keep_live_history))

    # -------------------------------------------------------- tool route

    @app.post("/api/worlds/{world}/tool-calls")
    def tool_call(world: str, call: ToolCall):
        return demo.tool_call(world, call)

    # ----------------------------------------------------- analyst route

    @app.post("/api/analyst/approvals", status_code=201)
    def grant_approval(body: ApprovalRequest):
        return demo.grant_approval(body.incident_id, body.action, body.endpoint)

    # ------------------------------------------------------------ static

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(config.STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
    return app

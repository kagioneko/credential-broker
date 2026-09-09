"""FastAPI application factory + lifecycle."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.assembly import broker_context
from app.config_loader import load_config
from app.errors import BrokerError
from app.models.api import ErrorResponse
from app.settings import load_settings

log = logging.getLogger("broker")


def create_app(clock: Callable[[], float] = time.monotonic) -> FastAPI:
    settings = load_settings()
    if not settings.broker_api_token:
        raise RuntimeError("BROKER_API_TOKEN is required for the HTTP entrypoint")
    config = load_config(settings.config_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with broker_context(settings, config, clock=clock) as rt:
            app.state.broker = rt.broker
            app.state.broker_api_token = settings.broker_api_token
            app.state.store = rt.store
            log.info("credential-broker (http) started on %s:%s", settings.host, settings.port)
            yield

    app = FastAPI(title="AI Credential Broker", version="0.1.0", lifespan=lifespan)

    @app.exception_handler(BrokerError)
    async def _broker_error(_: Request, exc: BrokerError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content=ErrorResponse(error=exc.error_code).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
        # Never echo pydantic's detailed body (may reflect input).
        return JSONResponse(status_code=422, content={"error": "INVALID_PARAMETER"})

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"error": "INTERNAL_ERROR"})

    from app.api.routes import router

    app.include_router(router)
    return app


# Run with:  uvicorn --factory app.main:create_app --host 127.0.0.1 --port 8787 --workers 1

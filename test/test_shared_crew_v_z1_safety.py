"""Startup readiness preserves its fences."""

from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from kiro_crew.config.sections_shared_crew import effective_limits, shared_crew_config_from
from kiro_crew.dashboard import server
from kiro_crew.shared_crew import admission_gate as ag
from kiro_crew.shared_crew import containment, lifecycle, routes_admission, wiring
from kiro_crew.shared_crew.admission import OperationKind


def _service():
    limits = effective_limits(
        shared_crew_config_from({"admission_enabled": True, "hard_limits": True}),
        auto_crew_concurrency=2,
    )
    return ag.AdmissionService(
        None,
        limits=limits,
        containment_probe=lambda: containment.failed_report(hard_limits=True, detail="no bus"),
    )


@pytest.mark.asyncio
async def test_startup_publishes_hard_refusal_without_maintenance(monkeypatch):
    service = _service()
    monkeypatch.setattr(ag, "_SERVICE", service)
    monkeypatch.setattr(containment, "_HARD_MODE_REPORT", None)
    monkeypatch.setattr(ag, "current_service", AsyncMock(return_value=service))
    reconcile = AsyncMock()
    sweep = AsyncMock(return_value=0)
    monkeypatch.setattr(service, "ensure_ready", reconcile)
    monkeypatch.setattr(service, "release_stale_slices", sweep)
    report = await ag.startup_check()
    assert report.refusal_reason == containment.REASON_UNKNOWN
    assert containment.hard_mode_refusal() == containment.REASON_UNKNOWN
    reconcile.assert_not_awaited()
    sweep.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("finish", [False, True])
async def test_maintenance_runs_after_bind_and_cleanup_owns_it(monkeypatch, finish):
    service = _service()
    entered = asyncio.Event()
    release = asyncio.Event()
    settled = asyncio.Event()
    swept = asyncio.Event()

    async def reconcile():
        entered.set()
        try:
            await asyncio.wait_for(release.wait(), timeout=30)
        finally:
            settled.set()

    monkeypatch.setattr(ag, "_SERVICE", service)
    monkeypatch.setattr(ag, "startup_check", AsyncMock())
    monkeypatch.setattr(wiring, "install", Mock())
    monkeypatch.setattr(service, "ensure_ready", reconcile)
    sweep = AsyncMock(side_effect=lambda: swept.set())
    monkeypatch.setattr(service, "release_stale_slices", sweep)
    shutdown = AsyncMock(return_value=0)
    monkeypatch.setattr(ag, "shutdown_cleanup", shutdown)
    app = web.Application()
    app["state"] = SimpleNamespace()
    start_maintenance = lifecycle.install_lifecycle(app)
    runner = web.AppRunner(app)
    try:
        await runner.setup()
        assert not entered.is_set()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        assert runner.addresses[0][0] == "127.0.0.1"
        assert callable(start_maintenance)
        start_maintenance()
        await asyncio.wait_for(entered.wait(), timeout=30)
        start_maintenance()
        sweep.assert_not_awaited()
        if finish:
            release.set()
            await asyncio.wait_for(swept.wait(), timeout=30)
            sweep.assert_awaited_once()
    finally:
        await asyncio.wait_for(runner.cleanup(), timeout=30)
    assert settled.is_set()
    shutdown.assert_awaited_once()


@pytest.mark.parametrize("entrypoint", [server.start_dashboard, server.start_api_server])
def test_both_servers_start_maintenance_only_after_socket_accepts(entrypoint):
    source = inspect.getsource(entrypoint)
    bind = (
        "await site.start()"
        if entrypoint is server.start_dashboard
        else "await _start_site(site, port)"
    )
    registration = "start_shared_crew_maintenance = lifecycle.install_lifecycle(app)"
    assert source.index(registration) < source.index("await runner.setup()") < source.index(bind)
    assert source.index(bind) < source.index("start_shared_crew_maintenance()")


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["admit", "capacity"])
async def test_first_admission_and_capacity_still_reconcile(monkeypatch, operation):
    service = _service()
    reconcile = AsyncMock()
    monkeypatch.setattr(service, "ensure_ready", reconcile)
    monkeypatch.setattr(ag, "current_service", AsyncMock(return_value=service))
    if operation == "admit":
        await service.admit(
            budget_key=ag.AUTOMATION_PRINCIPAL.id,
            session_key="session",
            operation=OperationKind.CHAT_TURN,
            idempotency_key="first-admission",
        )
    else:
        await routes_admission.api_capacity(
            make_mocked_request("GET", routes_admission.CAPACITY_PATH)
        )
    reconcile.assert_awaited_once()

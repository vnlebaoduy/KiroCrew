"""Every chat turn faces fair admission once, charged to its initiator.

Drives ``turn_gate.gate_turn`` against a real ``AdmissionService`` over a real
work store, plus the gateway wiring that publishes capability sources and the
People usage reader.
"""

from __future__ import annotations

import asyncio
import subprocess
from types import SimpleNamespace

import pytest

from kiro_crew.config.sections_shared_crew import effective_limits, shared_crew_config_from
from kiro_crew.shared_crew import admission_entry as entry
from kiro_crew.shared_crew import admission_gate as ag
from kiro_crew.shared_crew import capabilities, people, turn_gate, wiring
from kiro_crew.shared_crew.admission import Liveness
from kiro_crew.shared_crew.attribution import author_meta
from kiro_crew.shared_crew.containment import ContainmentReport, SliceManager
from kiro_crew.shared_crew.contracts import (
    ActorContext,
    CapabilityState,
    EnforcementLevel,
    Principal,
    Provenance,
    Transport,
)
from kiro_crew.shared_crew.identity import tailnet_principal
from kiro_crew.shared_crew.work_store import WorkStore
from kiro_crew.taskq import lanes
from kiro_crew.taskq.store import TaskStore
from kiro_crew.testing.clock import ManualClock
from kiro_crew.testing.wait import async_wait_until, await_until

ALICE = tailnet_principal("alice@example.com", "laptop.tail.ts.net", Provenance.TAILSCALE_SERVE)
BOB = tailnet_principal("bob@example.com", "phone.tail.ts.net", Provenance.TAILSCALE_SERVE)


def _author(principal: Principal) -> dict:
    return author_meta(ActorContext(principal=principal, request_id="r", transport=Transport.HTTP))


class _Slot:
    def __init__(self, key: str) -> None:
        self.key = key
        self.rows: list[tuple[str, str]] = []

    def append(self, role: str, text: str, cls: str = "", **_kw: object) -> dict:
        self.rows.append((role, text))
        return {}


@pytest.fixture
def service(tmp_path, monkeypatch):
    clock = ManualClock(start=50_000.0)
    store = WorkStore(TaskStore(tmp_path / "t.db", clock=clock.time).open(), clock=clock.time)
    limits = effective_limits(
        shared_crew_config_from(
            {"admission_enabled": True, "principal_concurrency": 1, "crew_concurrency": 2}
        ),
        auto_crew_concurrency=8,
    )
    report = ContainmentReport(
        platform="linux",
        available=True,
        reason="",
        cpu=True,
        memory=True,
        pids=True,
        level=EnforcementLevel.BEST_EFFORT,
        hard_ready=True,
        slices_enabled=True,
    )
    svc = ag.AdmissionService(
        store,
        limits=limits,
        clock=clock.time,
        containment_probe=lambda: report,
        slices=SliceManager(
            runner=lambda cmd: subprocess.CompletedProcess(cmd, 0, "", ""),
            systemctl="/usr/bin/systemctl",
        ),
        liveness=lambda ref: Liveness.STOPPED,
    )

    async def _current():
        return svc

    monkeypatch.setattr(ag, "current_service", _current)
    monkeypatch.setattr(ag, "_SERVICE", svc)
    monkeypatch.setattr(lanes, "_LANE_RESOLVER", svc.budget_for_session)
    monkeypatch.setattr("kiro_crew.dashboard.chat_slack.slot_is_live", lambda _s, _slot: True)
    monkeypatch.setattr("kiro_crew.dashboard.chat_utils.effective_session_key", lambda s: s.key)
    yield svc
    entry._PENDING_SLOTS.clear()


_STATE = SimpleNamespace(push_slots_update=lambda: None)


def test_budget_is_initiator_then_automation_then_unknown():
    assert turn_gate.turn_budget({}, ALICE.id) == ALICE.id
    assert turn_gate.turn_budget({"_turn_actor": "cron"}) == ag.AUTOMATION_PRINCIPAL.id
    assert turn_gate.turn_budget({"_synthetic_payload": True}) == ag.AUTOMATION_PRINCIPAL.id
    assert turn_gate.turn_budget({"_turn_actor": "user"}) == Principal.unknown().id
    assert turn_gate.turn_budget({}) == Principal.unknown().id


def test_queued_initiator_needs_one_live_author():
    assert turn_gate.queued_initiator([{"meta": {"author": _author(ALICE)}}]) == ALICE.id
    two = [{"meta": {"author": _author(ALICE)}}, {"meta": {"author": _author(BOB)}}]
    assert turn_gate.queued_initiator(two) == ""
    restored = [{"meta": {"author": _author(ALICE)}, "_restored_from_disk": True}]
    assert turn_gate.queued_initiator(restored) == ""
    assert turn_gate.queued_initiator([{"meta": {}}]) == ""


@pytest.mark.asyncio
async def test_turn_without_a_service_runs_unchanged(monkeypatch):
    monkeypatch.setattr(ag, "_SERVICE", None)
    ran: list[str] = []

    async def run():
        ran.append("x")

    await turn_gate.gate_turn(_STATE, _Slot("s"), "hi", {}, run)
    assert ran == ["x"]


@pytest.mark.asyncio
async def test_drained_turn_is_charged_to_its_author_and_queues_at_the_limit(service):
    release = asyncio.Event()
    order: list[str] = []

    def turn(name):
        async def run():
            order.append(name + ":start")
            await release.wait()
            order.append(name + ":end")

        return run

    with turn_gate.initiated_by(ALICE.id):
        first = asyncio.create_task(turn_gate.gate_turn(_STATE, _Slot("a"), "one", {}, turn("a1")))
    await async_wait_until(lambda: order == ["a1:start"], describe=lambda: order)
    with turn_gate.initiated_by(ALICE.id):
        second = asyncio.create_task(turn_gate.gate_turn(_STATE, _Slot("b"), "two", {}, turn("a2")))
    await async_wait_until(lambda: entry.admission_pending("b"), describe=lambda: order)
    # Alice's own limit is one: her second turn waits, and is marked pending so a
    # later send cannot steer into it.
    assert order == ["a1:start"]
    assert entry.admission_pending("b")
    principal, _crew = service.scheduler.usage(ALICE.id)
    assert (principal.active, principal.queued) == (1, 1)
    release.set()
    await await_until(asyncio.gather(first, second))
    assert order == ["a1:start", "a1:end", "a2:start", "a2:end"]


@pytest.mark.asyncio
async def test_admitted_work_is_not_admitted_twice_and_children_face_admission(service):
    seen: list[str] = []

    async def child():
        seen.append("child")

    async def parent():
        seen.append(turn_gate.admitted_work() or "consumed")
        # A task this turn creates (the queue drain's next entry) must face
        # admission itself rather than inherit the parent's admitted work.
        task = asyncio.create_task(turn_gate.gate_turn(_STATE, _Slot("c"), "next", {}, child))
        await await_until(task)

    with turn_gate.mark_admitted("w-parent"):
        outer = asyncio.create_task(turn_gate.gate_turn(_STATE, _Slot("p"), "hi", {}, parent))
    await await_until(outer)
    assert seen == ["consumed", "child"]
    # Only the child was admitted: the parent ran inside its own admitted work.
    _principal, crew = service.scheduler.usage(Principal.unknown().id)
    assert crew.active == 0


@pytest.mark.asyncio
async def test_nested_prompt_turn_runs_inside_its_parent(service):
    ran: list[str] = []

    async def run():
        ran.append("nested")

    await turn_gate.gate_turn(_STATE, _Slot("n"), "x", {"_prompt_depth": 1}, run)
    assert ran == ["nested"]


@pytest.mark.asyncio
async def test_refused_turn_never_runs_and_leaves_a_visible_note(service, monkeypatch):
    async def refuse(**_kw):
        return ag.Admission(service, "rejected", reason=ag.ReasonCode.CREW_QUEUE_FULL)

    monkeypatch.setattr(service, "admit", refuse)
    slot = _Slot("r")
    ran: list[str] = []

    async def run():
        ran.append("ran")

    await turn_gate.gate_turn(_STATE, slot, "hi", {"_turn_actor": "cron"}, run)
    assert ran == []
    assert slot.rows and slot.rows[0][0] == "error"
    assert "did not start" in slot.rows[0][1]


@pytest.mark.asyncio
async def test_wiring_publishes_truthful_capabilities_and_usage(service, monkeypatch):
    monkeypatch.setattr(capabilities, "_REGISTRY", {})
    monkeypatch.setattr(people, "_usage_source", None)
    await service.containment_report(refresh=True)
    wiring.install()
    wiring.install()  # idempotent
    try:
        caps = capabilities.aggregate_capabilities().capabilities
        assert caps.queueing is CapabilityState.AVAILABLE
        assert caps.containment is CapabilityState.AVAILABLE
        assert caps.containment_level is EnforcementLevel.BEST_EFFORT
        assert caps.presence is CapabilityState.AVAILABLE
        assert caps.attribution is CapabilityState.AVAILABLE
        assert caps.authoritative_directory is CapabilityState.UNAVAILABLE
        assert caps.membership_link == ""
        assert wiring.admission_usage() == {}
    finally:
        wiring.uninstall()


def test_wiring_with_admission_off_claims_no_queueing_or_containment(monkeypatch):
    monkeypatch.setattr(capabilities, "_REGISTRY", {})
    monkeypatch.setattr(people, "_usage_source", None)
    monkeypatch.setattr(ag, "_SERVICE", None)
    wiring.install()
    try:
        caps = capabilities.aggregate_capabilities().capabilities
        assert caps.queueing is CapabilityState.DISABLED
        assert caps.containment is CapabilityState.DISABLED
        assert caps.containment_level is EnforcementLevel.NONE
        with pytest.raises(LookupError):
            wiring.admission_usage()
    finally:
        wiring.uninstall()


@pytest.mark.asyncio
async def test_channel_turn_is_charged_to_unknown_and_refusal_is_answered(service, monkeypatch):
    seen: dict = {}

    async def run():
        return "answered"

    async def refused(reason):
        return f"refused:{reason.value if reason else ''}"

    out = await turn_gate.run_channel_turn(
        session_key="slack:1", text="hi", automation=False, run=run, refused=refused
    )
    assert out == "answered"

    async def refuse(**kw):
        seen.update(kw)
        return ag.Admission(service, "rejected", reason=ag.ReasonCode.CREW_QUEUE_FULL)

    monkeypatch.setattr(service, "admit", refuse)
    out = await turn_gate.run_channel_turn(
        session_key="slack:2", text="hi", automation=True, run=run, refused=refused
    )
    assert out == "refused:crew_queue_full"
    assert seen["budget_key"] == ag.AUTOMATION_PRINCIPAL.id
    assert seen["operation"].value == "channel_turn"


def test_admission_active_reads_the_installed_service(service, monkeypatch):
    assert turn_gate.admission_active() is True
    monkeypatch.setattr(ag, "_SERVICE", None)
    assert turn_gate.admission_active() is False


@pytest.mark.asyncio
async def test_slack_message_reenters_its_handler_once_inside_admission(service, monkeypatch):
    calls: list[bool] = []
    posted: list[tuple] = []

    class _Slack:
        async def post_message(self, channel, text, ts):
            posted.append((channel, text, ts))

    async def handler(**kwargs):
        # The real handler checks in_channel_turn() and runs its body on re-entry.
        calls.append(turn_gate.in_channel_turn())

    args = {"slack": _Slack(), "channel": "C1", "text": "hi", "thread_ts": None, "msg_ts": "1.2"}
    await turn_gate.run_slack_message(handler, args)
    assert calls == [True]

    async def refuse(**_kw):
        return ag.Admission(service, "rejected", reason=ag.ReasonCode.PRINCIPAL_QUEUE_FULL)

    monkeypatch.setattr(service, "admit", refuse)
    await turn_gate.run_slack_message(handler, args)
    assert calls == [True]
    assert posted and posted[0][0] == "C1" and posted[0][2] == "1.2"
    assert "principal queue full" in posted[0][1]

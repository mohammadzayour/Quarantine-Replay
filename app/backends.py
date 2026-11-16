"""The two simulated tool backends.

Both receive the same typed tool call. Each holds a reference to its own world
only. The vulnerable one executes anything well-formed. The protected one
requires a server-side approval bound to (incident, action, canonical endpoint).
Neither backend can create an approval.
"""
from __future__ import annotations

from typing import Any

from . import fixtures
from .models import ToolCall
from .store import ApprovalVerifier, World


def _result(world: World, backend: str, call: ToolCall, endpoint: dict[str, Any] | None,
            before: dict[str, Any], **fields: Any) -> dict[str, Any]:
    args = call.arguments
    return {
        "world": world.name,
        "backend": backend,
        "target": {
            "requested": args.endpoint_id,
            "canonical_endpoint_id": endpoint["endpoint_id"] if endpoint else None,
            "hostname": endpoint["hostname"] if endpoint else None,
            "role": endpoint["role"] if endpoint else None,
        },
        "ignored_fields": args.ignored_fields(),
        "state_before": before,
        "resulting_state": world.snapshot(),
        **fields,
    }


class VulnerableBackend:
    """Trusts the caller: a syntactically valid call is executed."""

    name = "vulnerable"

    def __init__(self, world: World):
        self._world = world

    def execute(self, call: ToolCall) -> dict[str, Any]:
        before = self._world.snapshot()
        endpoint = self._world.resolve(call.arguments.endpoint_id)
        if endpoint is None:
            return _result(
                self._world, self.name, call, None, before,
                outcome="rejected", code="unknown_endpoint", state_changed=False,
                authorization_checked=False, approval_id=None, checked=None,
                reason=f"No endpoint named '{call.arguments.endpoint_id}' in the inventory.",
            )
        changed = self._world.isolate(endpoint["endpoint_id"])
        return _result(
            self._world, self.name, call, endpoint, before,
            outcome="executed", code="no_authorization_check", state_changed=changed,
            authorization_checked=False, approval_id=None, checked=None,
            reason=(
                "The call is well-formed, so it was executed. This backend never asks "
                "who approved the action."
            ) + ("" if changed else " (Endpoint was already isolated.)"),
        )


class ProtectedBackend:
    """Executes only when a trusted, server-side approval matches the exact request."""

    name = "protected"

    def __init__(self, world: World, verifier: ApprovalVerifier):
        self._world = world
        self._verifier = verifier

    def execute(self, call: ToolCall) -> dict[str, Any]:
        args = call.arguments
        before = self._world.snapshot()
        endpoint = self._world.resolve(args.endpoint_id)

        def deny(code: str, reason: str, checked: dict[str, Any] | None = None) -> dict[str, Any]:
            return _result(
                self._world, self.name, call, endpoint, before,
                outcome="denied", code=code, reason=reason, state_changed=False,
                authorization_checked=True, approval_id=None, checked=checked,
            )

        if endpoint is None:
            return deny("unknown_endpoint", f"No endpoint named '{args.endpoint_id}' in the inventory.")
        if args.incident_id != fixtures.INCIDENT["incident_id"]:
            return deny("unknown_incident", f"'{args.incident_id}' is not an open incident.")

        checked = {
            "incident_id": args.incident_id,
            "action": call.tool,
            "endpoint_id": endpoint["endpoint_id"],
        }
        # The lookup key is built from the canonical inventory record, never from
        # the call's free text. `reason` and any extra fields are not consulted.
        approval = self._verifier.consume(**checked)
        if approval is None:
            return deny(
                "no_trusted_approval",
                "No trusted approval is on record for this incident, action and endpoint. "
                "Approval wording inside logs or model output is not consulted.",
                checked,
            )

        changed = self._world.isolate(endpoint["endpoint_id"])
        return _result(
            self._world, self.name, call, endpoint, before,
            outcome="executed", code="approved", state_changed=changed,
            authorization_checked=True, approval_id=approval["approval_id"], checked=checked,
            approved_by=approval["approved_by"],
            reason=f"Matched server-side approval {approval['approval_id']} granted by {approval['approved_by']}."
            + ("" if changed else " (Endpoint was already isolated.)"),
        )

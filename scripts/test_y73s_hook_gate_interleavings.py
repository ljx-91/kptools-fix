#!/usr/bin/env python3
"""Exhaustive abstract interleavings for a resident Hook Gate.

This models two concurrent entrants racing with module teardown. It checks
atomic gate-token accounting, try_module_get/module_put ordering, close/wait
semantics, and the requirement that the closed Gate plus original trampoline
remain resident after the LKM image is unloaded.

This is a protocol model only. It does not test production Gate machine code,
the ARM64 memory model, Linux 4.14 module internals, or device runtime.
"""
from collections import deque
from dataclasses import dataclass, replace

CLOSED = 1 << 63
COUNT_MASK = CLOSED - 1


@dataclass(frozen=True)
class Entrant:
    step: str = "load"
    expected: int = 0
    token: bool = False
    module_ref: bool = False
    active: bool = False
    fallback: bool = False


@dataclass(frozen=True)
class State:
    gate: int = 0
    module_state: str = "LIVE"
    module_refs: int = 0
    active_calls: int = 0
    unhooked: bool = False
    unload_step: str = "begin"
    entrants: tuple = (Entrant(), Entrant())
    gate_code_resident: bool = True
    origin_retained: bool = True


def check_invariants(state):
    count = state.gate & COUNT_MASK
    assert count == sum(item.token for item in state.entrants)
    assert state.module_refs == sum(item.module_ref for item in state.entrants)
    assert state.active_calls == sum(item.active for item in state.entrants)
    assert state.active_calls <= state.module_refs

    if state.active_calls:
        assert state.module_state == "LIVE"
    if state.module_state in ("GOING", "UNLOADED"):
        assert state.module_refs == 0
        assert state.active_calls == 0
    if state.module_state == "UNLOADED":
        assert state.gate & CLOSED
        assert count == 0
        assert state.unhooked
        assert state.gate_code_resident
        assert state.origin_retained

    for item in state.entrants:
        assert not item.active or item.module_ref
        assert not item.module_ref or item.token


def advance_entrant(state, index):
    item = state.entrants[index]
    entrants = list(state.entrants)

    if item.step == "load":
        if state.gate & CLOSED:
            entrants[index] = replace(item, step="done", fallback=True)
            next_state = replace(state, entrants=tuple(entrants))
        else:
            entrants[index] = replace(item, step="cas", expected=state.gate)
            next_state = replace(state, entrants=tuple(entrants))
    elif item.step == "cas":
        if (state.gate == item.expected and not (state.gate & CLOSED)
                and (state.gate & COUNT_MASK) < COUNT_MASK):
            entrants[index] = replace(item, step="get", token=True)
            next_state = replace(
                state, gate=state.gate + 1, entrants=tuple(entrants)
            )
        else:
            # A competing entrant or close changed the atomic word. Retry
            # from a fresh load; never dispatch on the stale observation.
            entrants[index] = replace(item, step="load")
            next_state = replace(state, entrants=tuple(entrants))
    elif item.step == "get":
        if state.module_state == "LIVE":
            entrants[index] = replace(item, step="call", module_ref=True)
            next_state = replace(
                state, module_refs=state.module_refs + 1,
                entrants=tuple(entrants)
            )
        else:
            # Teardown already began. Do not enter LKM text; use the retained
            # original trampoline, then release the Gate token.
            entrants[index] = replace(item, step="leave", fallback=True)
            next_state = replace(state, entrants=tuple(entrants))
    elif item.step == "call":
        entrants[index] = replace(item, step="return", active=True)
        next_state = replace(
            state, active_calls=state.active_calls + 1,
            entrants=tuple(entrants)
        )
    elif item.step == "return":
        entrants[index] = replace(item, step="put", active=False)
        next_state = replace(
            state, active_calls=state.active_calls - 1,
            entrants=tuple(entrants)
        )
    elif item.step == "put":
        entrants[index] = replace(item, step="leave", module_ref=False)
        next_state = replace(
            state, module_refs=state.module_refs - 1,
            entrants=tuple(entrants)
        )
    elif item.step == "leave":
        assert item.token
        count = state.gate & COUNT_MASK
        entrants[index] = replace(item, step="done", token=False)
        next_state = replace(
            state, gate=(state.gate & CLOSED) | (count - 1),
            entrants=tuple(entrants)
        )
    else:
        return None

    check_invariants(next_state)
    return next_state


def advance_unload(state):
    step = state.unload_step
    if step == "begin":
        # Linux may enter module_exit only after module references reach zero.
        if state.module_state == "LIVE" and state.module_refs == 0:
            next_state = replace(
                state, module_state="GOING", unload_step="close"
            )
        else:
            return None
    elif step == "close":
        next_state = replace(
            state, gate=state.gate | CLOSED, unload_step="unhook"
        )
    elif step == "unhook":
        next_state = replace(state, unhooked=True, unload_step="wait")
    elif step == "wait":
        if state.gate & COUNT_MASK:
            return None
        next_state = replace(state, unload_step="finish")
    elif step == "finish":
        assert state.unhooked
        assert (state.gate & COUNT_MASK) == 0
        assert state.module_refs == 0 and state.active_calls == 0
        next_state = replace(
            state, module_state="UNLOADED", unload_step="done"
        )
    else:
        return None

    check_invariants(next_state)
    return next_state


def test_all_two_entrant_teardown_interleavings():
    initial = State()
    pending = deque([initial])
    visited = {initial}
    terminal = 0

    while pending:
        state = pending.popleft()
        if (all(item.step == "done" for item in state.entrants)
                and state.unload_step == "done"):
            terminal += 1
            check_invariants(state)
            continue

        successors = [
            advance_entrant(state, 0),
            advance_entrant(state, 1),
            advance_unload(state),
        ]
        successors = [item for item in successors if item is not None]
        assert successors, f"deadlocked protocol state: {state}"

        for next_state in successors:
            if next_state not in visited:
                visited.add(next_state)
                pending.append(next_state)

    assert terminal > 0
    print(
        "KPIMG Gate exhaustive model: "
        f"{len(visited)} states, {terminal} terminal schedules; "
        "all invariants hold"
    )


if __name__ == "__main__":
    test_all_two_entrant_teardown_interleavings()

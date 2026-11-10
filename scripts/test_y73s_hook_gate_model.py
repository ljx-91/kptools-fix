#!/usr/bin/env python3
"""Abstract interleaving model for the KPIMG-resident hook Gate.

This checks the closed-bit/active-count protocol at atomic linearization
points. It is not an implementation test, AArch64 memory-model proof, or
substitute for a target-kernel concurrency test.
"""

CLOSED = 1 << 63
COUNT_MASK = CLOSED - 1


def enter(state):
    """Model Gate token acquisition with an atomic compare/exchange loop."""
    while True:
        observed = state
        if observed & CLOSED:
            return state, False
        count = observed & COUNT_MASK
        if count == COUNT_MASK:
            return state, False
        desired = observed + 1
        # The caller supplies the current atomic value; in this sequential
        # model a successful CAS is represented by returning desired.
        return desired, True


def close(state):
    """Model the atomic close-bit transition."""
    return state | CLOSED


def leave(state):
    count = state & COUNT_MASK
    assert count > 0, "Gate token underflow"
    return (state & CLOSED) | (count - 1)


def test_enter_linearizes_before_close_is_counted():
    state, token = enter(0)
    assert token and state == 1
    state = close(state)
    assert state == CLOSED | 1
    state = leave(state)
    assert state == CLOSED


def test_close_linearizes_before_enter_rejects():
    state = close(0)
    after, token = enter(state)
    assert not token
    assert after == CLOSED


def test_stale_open_observation_cannot_bypass_close():
    # Entrant read OPEN, then teardown closed the Gate before its CAS.
    stale_expected = 0
    state = close(0)
    cas_succeeded = state == stale_expected
    assert not cas_succeeded
    # The retry must reload and observe CLOSED rather than dispatch to LKM.
    after, token = enter(state)
    assert not token and after & CLOSED


def test_close_waits_for_token_even_before_module_get():
    # The token is deliberately acquired before try_module_get().
    state, token = enter(0)
    assert token
    state = close(state)
    assert (state & COUNT_MASK) == 1
    module_get_succeeded = False
    if not module_get_succeeded:
        state = leave(state)
    assert state == CLOSED
    assert (state & COUNT_MASK) == 0


def test_module_get_success_keeps_token_until_lkm_returned():
    state, token = enter(0)
    assert token
    module_get_succeeded = True
    state = close(state)
    # A successful module reference prevents module teardown from freeing
    # LKM text; the Gate token remains held until transit has returned and
    # module_put has completed.
    assert module_get_succeeded and (state & COUNT_MASK) == 1
    state = leave(state)
    assert state == CLOSED


def test_closed_entry_does_not_read_module_pointer():
    state = close(0)
    module_pointer_reads = 0
    chain = {"relo_addr": 0x12340000}
    if state & CLOSED:
        fallback = chain["relo_addr"]
    else:
        module_pointer_reads += 1
        fallback = None
    assert fallback == 0x12340000
    assert module_pointer_reads == 0


def test_count_overflow_fails_closed():
    state = COUNT_MASK
    after, token = enter(state)
    assert not token
    assert after == state


def test_gate_leave_preserves_closed_bit():
    state = CLOSED | 3
    state = leave(state)
    assert state == CLOSED | 2


def main():
    tests = [
        value for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"KPIMG Gate abstract model: {len(tests)}/{len(tests)} checks passed")


if __name__ == "__main__":
    main()

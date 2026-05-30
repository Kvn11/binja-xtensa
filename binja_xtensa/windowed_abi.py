"""
Pure Xtensa windowed-ABI register-mapping helpers (no Binary Ninja dependency).

Deliberately free of any ``binaryninja`` import and of the package ``__init__``
so the width->register mapping the lifter relies on is unit-testable headless;
the rest of the lifter needs a licensed Binary Ninja to build IL. See
docs/superpowers/specs/2026-05-30-xtensa-windowed-arg-recovery-design.md.

In the windowed ABI a ``CALLn`` (n in {4,8,12}) rotates the register window by n
registers, so the caller places the callee's a2..a7 arguments in its own
a(n+2)..a15 (ISA Reference Manual 8.1.4), and a return value comes back in
a(n+2)/a(n+3) (8.1.5). ``CALL12`` can only pass two register-argument words
(a14, a15); the remaining slots have no backing register in the 16-entry window.
"""

# CALLn / CALLXn mnemonic -> window rotation amount, in registers.
WINDOWED_CALL_INCR = {
    "CALL4": 4, "CALL8": 8, "CALL12": 12,
    "CALLX4": 4, "CALLX8": 8, "CALLX12": 12,
}

# The windowed ABI passes at most 6 register arguments (callee a2..a7).
NUM_ARG_SLOTS = 6


def windowed_arg_srcs(n):
    """Caller-side source register for each of the 6 argument slots at width n.

    Element i is the name of the caller register holding argument i
    (callee a(2+i) == caller a(n+2+i)), or None if that slot has no backing
    register in the 16-entry window at this width (only CALL12).
    """
    base = n + 2
    return [("a%d" % (base + i)) if base + i <= 15 else None
            for i in range(NUM_ARG_SLOTS)]


def windowed_return_dsts(n):
    """Caller-side registers that receive a windowed call's return value:
    a(n+2) (low word) and a(n+3) (high word). Both lie inside the window that
    CALLn clobbers, so writing them introduces no incorrect dataflow."""
    return ["a%d" % (n + 2), "a%d" % (n + 3)]

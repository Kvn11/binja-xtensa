"""
Recover stripped function names from leaked ``__func__`` strings.

Registers the "Recover function names from __func__ strings" plugin command.

Rationale (see scripts/recover_func_symbols.py for the long-form write-up): a
debug-built C firmware emits, at the top of every function, a hidden
``static const char __func__[] = "<name>";`` that vendor logging macros pass to a
logger. Because ``__func__`` is scoped to that one function, the string whose value
is ``"foo"`` can only be referenced by the body of ``foo``. So an identifier-shaped
string referenced by exactly one still-auto-named function reveals that function's
name -- essentially free symbol recovery for stripped ESP firmware.

Safety heuristics (conservative -- a wrong name is worse than no name):
  * candidate must be a C identifier with a lowercase letter AND an underscore and
    be >= MIN_LEN long  -> excludes camelCase JSON keys and ALL_CAPS enum/error names;
  * rename only when EXACTLY ONE distinct, still-``sub_*`` function references it;
  * if two candidate strings map to the same function it's a conflict -> skipped and
    logged for manual review (a function has only one ``__func__``);
  * already-named functions are never touched -> idempotent / re-runnable.
"""
import re

_IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

# Defaults; conservative for the snake_case-heavy Espressif SDKs.
MIN_LEN = 4
REQUIRE_UNDERSCORE = True   # snake_case __func__; excludes camelCase JSON/proto keys
STRIP_PREFIX = True         # drop leading log-tag junk like '@?' or CR + '@'


def extract_identifier(value, min_len=MIN_LEN, require_underscore=REQUIRE_UNDERSCORE,
                       strip_prefix=STRIP_PREFIX):
    """Return a clean C-identifier from a string value, or None if it is not one."""
    if not value:
        return None
    cand = value
    if not _IDENT.match(cand) and strip_prefix:
        cand = re.sub(r'^[^A-Za-z_]+', '', cand)        # drop '@?', CR+'@', leading junk
    if not _IDENT.match(cand):
        return None
    if len(cand) < min_len:
        return None
    if not any(c.islower() for c in cand):              # drop ALL_CAPS enum/error names
        return None
    if require_underscore and '_' not in cand:          # drop camelCase keys
        return None
    return cand


def recover_func_symbols(bv, task=None, min_len=MIN_LEN,
                         require_underscore=REQUIRE_UNDERSCORE, strip_prefix=STRIP_PREFIX):
    """Rename auto-named functions from their ``__func__`` strings.

    Returns ``(renamed, conflicts, skipped)`` where each item carries the function
    start address. ``task`` (a BackgroundTaskThread) is optional and only used for
    progress/cancellation. Pure with respect to Binary Ninja's API, so it is unit
    testable by passing any object exposing ``functions``/``strings``/``get_code_refs``.
    """
    taken = {f.name for f in bv.functions}              # names already in use
    func_to_names = {}                                  # Function -> {candidate names}
    strings = bv.strings
    total = len(strings)

    for i, s in enumerate(strings):
        if task is not None:
            if task.cancelled:
                return [], [], []
            if (i & 0x3ff) == 0:
                task.progress = "Recovering __func__ symbols: %d/%d strings" % (i, total)
        name = extract_identifier(s.value, min_len, require_underscore, strip_prefix)
        if name is None:
            continue
        # every distinct function that references this string from code
        refs = {r.function for r in bv.get_code_refs(s.start) if r.function is not None}
        if len(refs) != 1:                              # 0 = data-only; >1 = ambiguous/shared
            continue
        f = next(iter(refs))
        if not f.name.startswith("sub_"):               # already named -> leave it
            continue
        func_to_names.setdefault(f, set()).add(name)

    renamed, conflicts, skipped = [], [], []
    for f, names in func_to_names.items():
        if len(names) != 1:                             # one __func__ per function
            conflicts.append((f.start, sorted(names)))
            continue
        name = next(iter(names))
        if name in taken:                               # collision with an existing symbol
            skipped.append((f.start, name))
            continue
        f.name = name                                   # the rename (creates a user symbol)
        taken.add(name)
        renamed.append((f.start, name))
    return renamed, conflicts, skipped


def _register():
    """Register the plugin command. Imports binaryninja lazily so the module's pure
    logic above can be imported (and unit-tested) without a full BN environment."""
    from binaryninja import PluginCommand, BackgroundTaskThread, log

    class _RecoverTask(BackgroundTaskThread):
        def __init__(self, bv):
            BackgroundTaskThread.__init__(self, "Recovering __func__ symbols...", True)
            self.bv = bv

        def run(self):
            renamed, conflicts, skipped = recover_func_symbols(self.bv, task=self)
            if self.cancelled:
                log.log_warn("__func__ recovery cancelled", "recover_func_symbols")
                return
            self.bv.update_analysis()
            log.log_info("__func__ recovery: renamed %d, conflicts %d, skipped %d"
                         % (len(renamed), len(conflicts), len(skipped)),
                         "recover_func_symbols")
            for addr, names in sorted(conflicts):
                log.log_warn("conflict @ 0x%08x (resolve by hand): %s"
                             % (addr, ", ".join(names)), "recover_func_symbols")
            for addr, name in sorted(skipped):
                log.log_warn("skipped @ 0x%08x (name '%s' already used)" % (addr, name),
                             "recover_func_symbols")
            self.finish()

    def _run(bv):
        _RecoverTask(bv).start()

    PluginCommand.register(
        "Xtensa\\Recover function names from __func__ strings",
        "Rename auto-named functions from leaked __func__ debug strings. "
        "Conflicts and collisions are logged for manual review.",
        _run,
        is_valid=lambda bv: bv.arch is not None and bv.arch.name == "xtensa")

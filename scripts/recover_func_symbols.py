#!/usr/bin/env python3
"""
recover_func_symbols.py
=======================
Recover stripped function names from leaked ``__func__`` strings in a firmware image.

Why it works
------------
In a debug-built C firmware the compiler emits, at the top of every function body, a
hidden ``static const char __func__[] = "<name of this function>";`` and vendor logging
macros pass it to a logger.  Because ``__func__`` is *scoped to that one function*, the
string whose value is ``"foo"`` can only be referenced by the body of ``foo`` itself.
So:  identifier-shaped string  --(single code xref)-->  the function it names.

How to run
----------
* Inside Binary Ninja (use this for the live session so renames hit the open view + MCP):
    open the Python console (bottom panel) and run:

        exec(open('/path/to/binja-xtensa/scripts/recover_func_symbols.py').read())

  It uses the currently-open BinaryView (the magic ``bv`` variable).

* Headless / future reuse on any image (needs a Binary Ninja headless license):

        python3 recover_func_symbols.py main.payload.bin.bndb

Safety rules (so it does not mislabel data strings)
---------------------------------------------------
1. Candidate must be a C identifier, contain a lowercase letter AND an underscore, and be
   >= MIN_LEN long  -> excludes camelCase JSON keys ("fanSpeed") and ALL_CAPS enum/error
   names ("ESP_ERR_...").
2. Rename only when EXACTLY ONE distinct function references the string, and that function
   is still auto-named (sub_*).  -> NVS keys shared by read/write/clear siblings have
   multiple referrers and are dropped; so are merge/collision cases.
3. If two different candidate strings resolve to the SAME function -> conflict, skipped and
   reported for manual review (a function has only one __func__).
4. Already-named functions are never touched  -> idempotent and safe to re-run.

If REPORT_PATH is set, a JSON report (renamed / conflicts / skipped, with addresses) is also
written for follow-up tooling. All renames are undoable in the GUI.
"""

import re
import json

# ---- tunables ------------------------------------------------------------
MIN_LEN            = 4      # minimum identifier length
REQUIRE_UNDERSCORE = True   # snake_case __func__; set False for camelCase-heavy targets
STRIP_PREFIX       = True   # strip leading junk (e.g. '@?' or a CR + '@') before matching
VERBOSE            = True   # print every rename / conflict
# Optional JSON report (renamed / conflicts / skipped). None = just print the summary;
# set to a path to also dump it for follow-up tooling.
REPORT_PATH        = None
# -------------------------------------------------------------------------

_IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def extract_identifier(value):
    """Return a clean C-identifier from a string value, or None if it is not one."""
    if not value:
        return None
    cand = value
    if not _IDENT.match(cand) and STRIP_PREFIX:
        cand = re.sub(r'^[^A-Za-z_]+', '', cand)        # drop leading junk like '@?' / CR+'@'
    if not _IDENT.match(cand):
        return None
    if len(cand) < MIN_LEN:
        return None
    if not any(c.islower() for c in cand):              # drop ALL_CAPS enum/error names
        return None
    if REQUIRE_UNDERSCORE and '_' not in cand:          # drop camelCase JSON/proto keys
        return None
    return cand


def recover(bv):
    taken = {f.name for f in bv.functions}              # names already in use
    func_to_names = {}                                  # Function -> {candidate names}
    n_strings = 0

    for s in bv.strings:
        n_strings += 1
        name = extract_identifier(s.value)
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
        if len(names) != 1:                             # rule 3: one __func__ per function
            conflicts.append((f.start, sorted(names)))
            continue
        name = next(iter(names))
        if name in taken:                               # name collision with existing symbol
            skipped.append((f.start, name))
            continue
        f.name = name                                   # <-- the rename (creates a user symbol)
        taken.add(name)
        renamed.append((f.start, name))

    # ---- report -----------------------------------------------------------
    print("=" * 64)
    print(f"  scanned strings ............ {n_strings}")
    print(f"  functions renamed .......... {len(renamed)}")
    print(f"  conflicts (manual review) .. {len(conflicts)}")
    print(f"  skipped (name taken) ....... {len(skipped)}")
    print("=" * 64)
    if VERBOSE:
        for addr, name in sorted(renamed):
            print(f"  0x{addr:08x} -> {name}")
        if conflicts:
            print("\n-- conflicts: >1 candidate name maps to one function (resolve by hand) --")
            for addr, names in sorted(conflicts):
                print(f"  0x{addr:08x} : {', '.join(names)}")
        if skipped:
            print("\n-- skipped: target name already used elsewhere --")
            for addr, name in sorted(skipped):
                print(f"  0x{addr:08x} : {name}")

    report = {
        "scanned": n_strings,
        "renamed": [{"addr": f"0x{a:08x}", "name": n} for a, n in sorted(renamed)],
        "conflicts": [{"addr": f"0x{a:08x}", "candidates": ns} for a, ns in sorted(conflicts)],
        "skipped": [{"addr": f"0x{a:08x}", "name": n} for a, n in sorted(skipped)],
    }
    if REPORT_PATH:
        try:
            with open(REPORT_PATH, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"  report written: {REPORT_PATH}")
        except Exception as e:                          # noqa: BLE001
            print(f"  [!] report write failed: {e}")

    return renamed, conflicts


# ---- entry point: BN console (bv exists) OR headless ---------------------
try:
    bv  # noqa: F821  -- provided by the Binary Ninja Python console
    _HEADLESS = False
except NameError:
    _HEADLESS = True

if _HEADLESS:
    import sys
    import binaryninja
    if len(sys.argv) < 2:
        print("usage: python3 recover_func_symbols.py <file.bndb | firmware>")
        sys.exit(1)
    print(f"[+] loading {sys.argv[1]} ...")
    bv = binaryninja.load(sys.argv[1])
    bv.update_analysis_and_wait()
    recover(bv)
    try:                                                # persist results
        if sys.argv[1].endswith(".bndb"):
            bv.file.save_auto_snapshot()
        else:
            bv.create_database(sys.argv[1] + ".bndb")
        print("[+] database saved")
    except Exception as e:                              # noqa: BLE001
        print(f"[!] auto-save failed ({e}); save the database manually if needed")
else:
    recover(bv)

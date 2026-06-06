#!/usr/bin/env python3
"""
Verify the per-loader calling-convention fix:
    ESPFirmware (ESP8266, CALL0-only)  -> default convention "call0"  (args a2..a7)
    ESP32Firmware (ESP32 app code)     -> default convention "windowed" (args via wa0..wa5 -> a2..a7 at ENTRY)

It prints the view's default calling convention and an aggregate "how many
functions recovered >=1 argument" metric, plus a few example signatures. Run it
once per image and compare against the expected convention.

Two ways to run (both need a *licensed* Binary Ninja):

  A) From the Binary Ninja Python console, on the view you already have open:
         exec(open("scripts/check_calling_convention.py").read())
         report(bv, expected="call0")        # or "windowed" for the ESP32 image

  B) Headless:
         python3 scripts/check_calling_convention.py examples/firmware.bin call0
         python3 scripts/check_calling_convention.py path/to/esp32_app.bin windowed

IMPORTANT: the convention is set on the *shared* standalone platform, so test
each image in its OWN Binary Ninja session (or read the value right after load,
before opening the other image). Use the raw .bin files, not the .elf -- the ELF
loader path uses the arch-level default, which the per-loader fix does not touch.
"""
import sys


def report(bv, expected=None):
    plat = bv.platform
    conv = (plat.default_calling_convention.name
            if plat and plat.default_calling_convention else "<none>")
    funcs = list(bv.functions)
    with_params = [f for f in funcs if len(f.parameter_vars) > 0]
    pct = (100 * len(with_params) // len(funcs)) if funcs else 0

    print("-" * 64)
    print(f"view type              : {getattr(bv, 'view_type', '?')}")
    print(f"default calling conv   : {conv}")
    print(f"functions analyzed     : {len(funcs)}")
    print(f"  with >=1 arg recovered : {len(with_params)}  ({pct}%)")
    print("  sample recovered signatures:")
    for f in with_params[:8]:
        params = ", ".join(f"{v.type} {v.name}" for v in f.parameter_vars)
        print(f"    {f.start:#010x}  {f.name}({params})")
    if expected is not None:
        ok = conv == expected
        print(f"expected convention    : {expected}  ->  {'PASS' if ok else 'FAIL'}")
        return ok
    return None


def _detect_esp32(path):
    """True if `path` parses as an ESP32 image (so we pick ESP32Firmware)."""
    try:
        from binja_xtensa.firmware_parser import detect_esp32

        class _BV:
            def __init__(self, p):
                with open(p, "rb") as fh:
                    self.data = fh.read()
                self.end = len(self.data)
            def read(self, off, n):
                return self.data[off:off + n]
        return detect_esp32(_BV(path)) is not None
    except Exception:
        return False


if __name__ == "__main__":
    import os
    import binaryninja as bn

    # Register the ESPFirmware / ESP32Firmware views in this headless process
    # (the GUI does this at startup; a bare script must do it itself).
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import binja_xtensa  # noqa: F401  (import side effect: register_stuff())

    path = sys.argv[1] if len(sys.argv) > 1 else "examples/firmware.bin"
    expected = sys.argv[2] if len(sys.argv) > 2 else None

    # Pick the firmware view explicitly -- bn.load()'s auto-detection does not
    # reliably construct these custom raw-image views headlessly.
    view_name = "ESP32Firmware" if path.endswith(".bin") and \
        _detect_esp32(path) else "ESPFirmware"
    print(f"loading {path} as {view_name} (full analysis) ...")
    try:
        bv = bn.load(path, view_name=view_name, update_analysis=True)
    except Exception as exc:
        print(f"\nHeadless load failed ({exc}).")
        print("Custom firmware views are most reliable from the GUI. Instead:")
        print("  1) open the file in Binary Ninja (Open With Options -> ESP/ESP32 Firmware)")
        print("  2) in the Python console run:")
        print('       exec(open("scripts/check_calling_convention.py").read())')
        print(f'       report(bv, expected={expected!r})')
        sys.exit(1)
    report(bv, expected)

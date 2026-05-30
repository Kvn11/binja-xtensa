#!/usr/bin/env python3
"""Headless unit tests for the pure windowed-ABI register mapping.

Run headless (no Binary Ninja license needed):
    python3 binja_xtensa/test_windowed_abi.py
Under pytest in a licensed environment:
    pytest binja_xtensa/test_windowed_abi.py

The unit under test is loaded by file path (not via the package) so this runs
without triggering binja_xtensa/__init__.py's license-gated registration.
"""
import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "windowed_abi", os.path.join(os.path.dirname(__file__), "windowed_abi.py"))
_wa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_wa)

windowed_arg_srcs = _wa.windowed_arg_srcs
windowed_return_dsts = _wa.windowed_return_dsts
WINDOWED_CALL_INCR = _wa.WINDOWED_CALL_INCR


def test_call4_arg_srcs():
    assert windowed_arg_srcs(4) == ["a6", "a7", "a8", "a9", "a10", "a11"]


def test_call8_arg_srcs():
    assert windowed_arg_srcs(8) == ["a10", "a11", "a12", "a13", "a14", "a15"]


def test_call12_arg_srcs_clips_to_two():
    assert windowed_arg_srcs(12) == ["a14", "a15", None, None, None, None]


def test_return_dsts():
    assert windowed_return_dsts(4) == ["a6", "a7"]
    assert windowed_return_dsts(8) == ["a10", "a11"]
    assert windowed_return_dsts(12) == ["a14", "a15"]


def test_incr_map():
    assert WINDOWED_CALL_INCR == {
        "CALL4": 4, "CALL8": 8, "CALL12": 12,
        "CALLX4": 4, "CALLX8": 8, "CALLX12": 12,
    }


if __name__ == "__main__":
    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    for _t in _tests:
        _t()
        print("ok", _t.__name__)
    print("ALL %d PASSED" % len(_tests))

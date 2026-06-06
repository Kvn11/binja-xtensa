# binja-xtensa: Xtensa Architecture Plugin and ESP8266/ESP32 Loader

A Binary Ninja plugin for the Tensilica **Xtensa** architecture, with firmware
loaders for the Espressif **ESP8266 (LX106)** and **ESP32 (LX6)** cores. It
disassembles and lifts Xtensa to BNIL — including the register-window ABI that
ESP32 application code relies on — so stripped ESP firmware decompiles into
readable code.

> ### This is a fork
> The original Xtensa architecture plugin and ESP8266 loader were written by
> **[Zack Orndorff](https://github.com/zackorndorff)** — upstream:
> [zackorndorff/binja-xtensa](https://github.com/zackorndorff/binja-xtensa).
>
> This fork, maintained by **Kevin Romero ([@Kvn11](https://github.com/Kvn11))**,
> adds full **ESP32 (Xtensa LX6)** support on top of Zack's work:
> - lifting of the **windowed-register ABI** (`CALL4/8/12`, `CALLX4/8/12`,
>   `ENTRY`, `RETW`/`RETW.N`, `MOVSP`) so windowed call arguments and return
>   values are recovered in the decompiler;
> - an **ESP32 flash-image loader** (extended header, per-segment mapping);
> - the **ESP32 mask-ROM symbol map**;
> - a **`__func__` symbol-recovery** command;
> - broader base-ISA / FP / MAC16 lifting and a reserved-special-register fix.
>
> All original code remains © Zack Orndorff under the MIT license. The ESP32
> additions are © Kevin Romero, also MIT. See [LICENSE](LICENSE).

![screenshot of Binary Ninja showing a decompiled ESP8266 Arduino project](https://raw.githubusercontent.com/zackorndorff/binja-xtensa/0.5/screenshots/hero.png)

## Features

**Disassembly** of the full Xtensa base ISA plus the Code Density, Windowed
Register, Boolean, single-precision Floating-Point, MAC16 and synchronization
options used by the ESP8266 (LX106) and ESP32 (LX6) cores. The general, float
(`f`), boolean (`b`) and MAC16 (`m`) register files and the special/user
registers are all rendered.

**Lifting to BNIL** for the common integer, load/store, branch, shift,
multiply/divide, floating-point and boolean instructions, plus the
**windowed-ABI** call/entry/return/frame instructions — which is what makes
ESP32 firmware decompile usefully (see [The windowed ABI](#the-windowed-abi)).

**Two calling conventions**, selected automatically by each firmware loader:
- `call0` — the CALL0 ABI used by the ESP8266 and the ESP32 bootloader
  (arguments in `a2..a7`);
- `windowed` — the register-window ABI that dominates ESP32 application code.

**Special- and user-register handling** — `RSR`/`WSR`/`XSR` and `RUR`/`WUR`
(including `THREADPTR`). Reserved/undocumented registers fall back to an
intrinsic instead of crashing the lifter.

**ELF support** — Xtensa ELF files (`EM_XTENSA`) are recognized automatically.

**ESP8266 firmware loader** — raw image dumps (E9 / bootloaded EA). Multiple
partitions are offered as *Open With Options* choices, and the ESP8266 ROM
symbol map is overlaid.

**ESP32 flash-image loader** — parses the extended image header and maps every
segment at its load address (DROM / DRAM / IRAM / IROM) with the correct
read/write/execute semantics, marks code segments so analysis runs over all of
them, sets the entry point, and overlays the ESP32 mask-ROM symbol map.

**Function-name recovery** — a *Recover function names from `__func__` strings*
command that names stripped functions from the debug-logging strings ESP-IDF
builds leave behind.

## The windowed ABI

ESP32 application code uses Xtensa's register-window ABI: a `CALLn` instruction
rotates the visible register window by *n*, so a call's arguments live in a
different physical register range depending on the call width (`a6..` for
`CALL4`, `a10..` for `CALL8`, `a14..` for `CALL12`), while every callee reads
its arguments in `a2..a7` after `ENTRY`. A single flat calling convention can't
express that, so a decompiler that ignores it drops the arguments entirely and
renders every call as `fn()`.

This plugin lifts each call width into a synthetic argument/return channel
(`wa0..wa5` / `wr0`, `wr1`) at the call site and maps it back to `a2..a7` at the
callee's `ENTRY`. Binary Ninja then recovers windowed arguments and return
values through ordinary dataflow, so a windowed call decompiles as
`handler(method_id, fn_ptr)` rather than `handler()`.

## What it doesn't do

* **Model the register window precisely.** `WindowBase` is a runtime value the
  disassembler can't know statically, so each function is analyzed in its own
  logical `a0..a15` window (exactly what the hardware presents after `ENTRY`) and
  the cross-call register shift is expressed through the windowed calling
  convention. This is the pragmatic, decompiler-friendly model real Xtensa tools
  use — see the note in [binja_xtensa/__init__.py](binja_xtensa/__init__.py).
* **The optional vector / HiFi DSP unit.**
* **The zero-overhead loop back-edge.** `LOOP` sets up the count and the
  conditional skip is lifted, but the implicit branch at `LEND` is not modeled.
* **The `2^t` scale immediate** on the float conversion instructions
  (`FLOAT`/`UFLOAT`/`ROUND`/`TRUNC`/…); `t` is almost always 0 in practice.
* **Speed.** It's Python, and not particularly optimized Python. For serious use
  a C++ rewrite would be much faster.
* **Find `main`** in a raw binary for you.

## Installation

Install via the Binary Ninja plugin manager, or clone this repository into your
Binary Ninja plugins directory. See the
[official documentation](https://docs.binary.ninja/guide/plugins.html) for
details. The plugin is pure Python and has no third-party dependencies.

## Usage

### ESP8266 firmware

Open an ESP8266 image. The loader defaults to the last usable partition; for
more control, use **Open With Options** and set `Loader > Which Firmware` to the
partition you want. The view is loaded with the **call0** convention and the
ESP8266 ROM symbol map.

### ESP32 firmware

Open an ESP32 flash image (it shares the `0xE9` magic with the ESP8266 but
carries the 24-byte extended header). The loader maps each segment at its load
address, classifies it (IRAM / IROM / DROM / DRAM / RTC), sets the entry point,
overlays the ESP32 ROM symbol map, and selects the **windowed** convention so
arguments are recovered.

> ESP8266 and ESP32 images are told apart by the extended header and segment
> load addresses; RISC-V ESP variants (which share the magic but aren't Xtensa)
> are rejected by chip ID.

### Recover function names from `__func__` strings

Run **Plugins → Recover function names from `__func__` strings** on a stripped
ESP-IDF image. Vendor logging macros expand `__func__` to a per-function string,
each referenced by exactly the function it names, so the command maps those
strings back to their functions and renames them — a fast first pass that makes
the rest of an analysis far easier.

## ROM symbol maps

The ESP mask ROM is fixed in silicon, so its symbol addresses are stable across
SDK/IDF versions. The maps are generated from Espressif's ROM linker scripts by
[parse_rom_ld.py](binja_xtensa/parse_rom_ld.py) into
[known_symbols.py](binja_xtensa/known_symbols.py) (ESP8266) and
[esp32_rom_symbols.py](binja_xtensa/esp32_rom_symbols.py) (ESP32), and applied by
`setup_esp8266_map` / `setup_esp32_map` in
[binaryview.py](binja_xtensa/binaryview.py).

## Testing

Unit tests in [test_instruction.py](binja_xtensa/test_instruction.py) (decode /
disassembly checked against `objdump` output) and
[test_windowed_abi.py](binja_xtensa/test_windowed_abi.py) (the pure
register-window mapping). Run them with `python -m pytest` from the project root,
inside a licensed Binary Ninja Python environment.

`scripts/check_calling_convention.py` reports the calling convention a loaded
view selected and how many functions recovered arguments — handy for verifying
the ESP8266/ESP32 loaders in the GUI.

## Credits & history

The original plugin was written by **Zack Orndorff**, who explains its origin:

> 1. I was goofing around with ESP8266 and Arduino and was annoyed I didn't have
>    an easy way to disassemble the built binaries.
> 2. I hadn't written a full architecture plugin and thought it'd be a good
>    exercise.
> 3. I got bored over COVID-19 lockdown in 2020 and needed something to do.

The ESP32 (LX6) support in this fork grew out of reverse-engineering ESP32-based
firmware and needing a decompiler that could actually read the windowed ABI.

## License

MIT. The original Xtensa plugin and ESP8266 loader are © Zack Orndorff
([@zackorndorff](https://github.com/zackorndorff)); the ESP32 additions in this
fork are © Kevin Romero. The original copyright notice is preserved as the MIT
license requires. See [LICENSE](LICENSE).

# binja-xtensa: Architecture Plugin and ESP8266 Loader

Tensilica Xtensa Architecture Plugin and ESP8266 Firmware Loader for Binary
Ninja.

![screenshot of Binary Ninja showing setup and loop of a decompiled ESP8266
Arduino project](https://raw.githubusercontent.com/zackorndorff/binja-xtensa/0.5/screenshots/hero.png)

## Features

* Disassembly of the full Xtensa base ISA plus the Code Density, Windowed
  Register, Boolean, single-precision Floating-Point, MAC16 and synchronization
  options used by the ESP8266 (LX106) and ESP32 (LX6) cores
* Lifting to BNIL for the common integer, load/store, branch, shift,
  multiply/divide, floating-point, boolean and **windowed-ABI** instructions
  (CALL4/8/12, CALLX4/8/12, ENTRY, RETW/RETW.N, MOVSP), which is what makes
  ESP32 firmware decompile usefully
* Two calling conventions — `call0` (ESP8266 / ESP32 bootloader) and `windowed`
  (the register-window ABI that dominates ESP32 application code, used by
  default)
* Special- and user-register (RSR/WSR/XSR, RUR/WUR incl. THREADPTR) handling
* Support for Xtensa ELF files so they will be automatically recognized
* Loader for **ESP8266** raw firmware dumps (E9 / bootloaded EA). Multiple
  partitions are presented as Open-With-Options choices
* Loader for **ESP32** flash images: parses the extended image header and maps
  every segment at its load address (DROM/DRAM/IRAM/IROM) with correct
  read/write/execute semantics, marks all code segments, and sets the entry
  point

## What it doesn't do

* It was written mostly as an exercise for the original author. It's useful
  enough to share, but no promises it's useful for your project :)
* Model the register window precisely (WindowBase is a runtime value the
  disassembler can't know statically). Each function is analyzed in its own
  logical `a0`..`a15` window and the cross-call register shift is expressed
  through the windowed calling convention — see the note in
  [binja_xtensa/__init__.py](binja_xtensa/__init__.py). This is the pragmatic,
  decompiler-friendly model real Xtensa tools use.
* Anything with the optional vector / HiFi DSP unit
* Model the zero-overhead loop back-edge (LOOP sets up the count and the
  conditional skip is lifted, but the implicit branch at LEND is not represented)
* Anything quickly. This is Python, and not particularly well optimized Python
  at that. If you're using this seriously, I recommend rewriting in C++
* Find `main` in a raw binary for you

## Installation

Install via the Binary Ninja plugin manager. Alternatively, clone this
repository into your Binary Ninja plugins directory. See the [official Binary
Ninja documentation](https://docs.binary.ninja/guide/plugins.html) for more
details.

## Using the ESP8266 Firmware Loader

The default of picking the last usable partition works decent, but if you want
more control, use Open With Options and change `Loader > Which Firmware` to the
option corresponding to the address you want to load.

I attempt to load in symbols from the SDK's linker script so some of the
ROM-implemented functions are less mysterious. See
[parse_rom_ld.py](binja_xtensa/parse_rom_ld.py) for the parsing code,
[known_symbols.py](binja_xtensa/known_symbols.py) for the database it'll apply,
and function `setup_esp8266_map` in
[binaryview.py](binja_xtensa/binaryview.py#L17) for the code that applies it.
This should probably be a load time option... but it's not at the moment :/

![screenshot of Binary Ninja's Open With Options showing the Loader Which
Firmware option](https://raw.githubusercontent.com/zackorndorff/binja-xtensa/0.5/screenshots/open-with-options.png)

## Future Work

* Support register windowing instructions to support ESP32 firmware
* Improve the raw firmware loader
* Rewrite to be faster

## Why did you write this?

1. I was goofing around with ESP8266 and Arduino and was annoyed I didn't have
   an easy way to disassemble the built binaries
2. I hadn't written a full architecture plugin and I thought it'd be a good
   exercise
3. I got bored over COVID-19 lockdown in 2020 and needed something to do

## Testing

There are some simple tests in
[test_instruction.py](binja_xtensa/test_instruction.py), which are mostly just
taking uniq'd output from objdump on some binaries I had laying around and
making sure the output matches. They can be run with `python -m pytest` from the
root of the project.

## License

This project copyright Zack Orndorff (@zackorndorff) and is available under the
MIT license. See [LICENSE](LICENSE).

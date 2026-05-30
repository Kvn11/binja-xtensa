"""
ESP8266 Firmware .bin BinaryView

Using `firmware_parser.py`, we attempt to find binaries in the dump. By default
we'll pick an interesting one (currently the last one with a detected header),
but we present a load option to the user to allow picking a different one.
"""
import json
import struct

from binaryninja import Architecture, BinaryView, Settings, Symbol
from binaryninja.enums import SectionSemantics, SegmentFlag, SymbolType

from .firmware_parser import (parse_firmware, detect_esp32,
                              classify_esp32_segment)
from .known_symbols import known_symbols
from .esp32_rom_symbols import esp32_rom_symbols

def setup_esp8266_map(bv):
    """Define the ESP8266 ROM region and its known symbols."""
    # https://github.com/esp8266/esp8266-wiki/wiki/Memory-Map
    rom_start = 0x40000000
    rom_end = 0x40010000

    # Create the ROM segment/section once (not once per symbol).
    bv.add_auto_segment(rom_start, rom_end - rom_start, 0, 0,
                        SegmentFlag.SegmentContainsCode |
                        SegmentFlag.SegmentContainsData |
                        SegmentFlag.SegmentReadable     |
                        SegmentFlag.SegmentExecutable)
    bv.add_auto_section("esp8266_ROM", rom_start, rom_end - rom_start,
                        SectionSemantics.ExternalSectionSemantics)

    for addr, symbol in known_symbols.items():
        addr = int(addr, 0)
        if rom_start <= addr <= rom_end:
            sym_type = SymbolType.ImportedFunctionSymbol
        else:
            sym_type = SymbolType.ImportedDataSymbol

        bv.define_auto_symbol(Symbol(
            sym_type,
            addr, symbol))


def setup_esp32_map(bv):
    """Define the ESP32 mask-ROM code region and apply its known symbols.

    ESP32 ROM code sits below the firmware's IRAM (0x4008_0000); the region is
    derived from the symbol map below, so it never overlaps a loaded segment. Symbol
    names come from ``esp32_rom_symbols`` (generated from esp-idf's esp32.rom*.ld;
    the ROM is mask-programmed, so the addresses are identical across IDF versions).
    This turns the ubiquitous 0x4000_xxxx ROM calls -- memcpy/memset/strcmp/ets_*/
    etc. -- into readable names instead of raw addresses."""
    if not esp32_rom_symbols:
        return
    # Derive the ROM region from the symbol map itself (page-aligned) rather than
    # hardcoding bounds.
    rom_start = min(esp32_rom_symbols) & ~0xfff
    rom_end = (max(esp32_rom_symbols) + 0x1000) & ~0xfff

    bv.add_auto_segment(rom_start, rom_end - rom_start, 0, 0,
                        SegmentFlag.SegmentContainsCode |
                        SegmentFlag.SegmentReadable |
                        SegmentFlag.SegmentExecutable)
    bv.add_auto_section("esp32_ROM", rom_start, rom_end - rom_start,
                        SectionSemantics.ExternalSectionSemantics)

    for addr, symbol in esp32_rom_symbols.items():
        bv.define_auto_symbol(Symbol(
            SymbolType.ImportedFunctionSymbol, addr, symbol))


class ESPFirmware(BinaryView):
    name = "ESPFirmware"
    long_name = "ESP Firmware"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data):
        # ESP8266 E9/EA images. ESP32 images also start with 0xE9, so defer those
        # to ESP32Firmware (otherwise we'd mis-load them with the ESP8266 parser
        # and overlay the wrong ROM map/symbols).
        if data.read(0, 1) not in [b'\xe9', b'\xea']:
            return False
        if detect_esp32(data) is not None:
            return False
        return True

    @classmethod
    def _pick_default_firmware(cls, firmware_options):
        """Rudimentary heuristic for "interesting" binaries"""
        for idx, firm in reversed(list(enumerate(firmware_options))):
            if firm.name != "AppendedData":
                return idx, firm

        return 0, firmware_options[0]

    @classmethod
    def get_load_settings_for_data(cls, data):
        # This example was crucial in figuring out how to present load options
        # https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/mappedview.py
        # It's also helpful to call Settings().serialize_schema() from the
        # Python console and examine the results.

        firmware_options = parse_firmware(data)
        default_firmware_idx, _ = cls._pick_default_firmware(firmware_options)

        ourEnum = ["option" + str(i) for i in range(len(firmware_options))]
        ourEnumDescriptions = [
            f"{i.name} at {hex(i.bv_offset)}"
            for i in firmware_options]

        # TODO: actually JSON serialize this
        setting =  f"""{{
            "title": "Which Firmware",
            "type": "string",
            "description": "Which of the binaries in this file do you want?",
            "enum": {json.dumps(ourEnum)},
            "enumDescriptions": {json.dumps(ourEnumDescriptions)},
            "default": {json.dumps(ourEnum[default_firmware_idx])}
            }}
            """

        print(setting)

        load_settings = Settings("esp_bv_settings")
        assert load_settings.register_group("loader", "Loader")
        assert load_settings.register_setting("loader.esp.whichFirmware",
                                              setting)
        return load_settings

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        # This should be set by the the_firmware.load() if there is an entry
        # point.
        # Otherwise, for lack of a better choice, we end up with 0
        return self.entry_addr

    def perform_get_address_size(self):
        return 4

    def init(self):

        try:
            load_settings = self.get_load_settings(self.name)
            which_firmware = load_settings.get_string("loader.esp.whichFirmware", self)
        except:
            which_firmware = None

        firmware_options = parse_firmware(self.parent_view)

        try:
            prefix = "option"

            if which_firmware is None:
                try:
                    which_firmware_idx, _ = self._pick_default_firmware(firmware_options)
                except:
                    import traceback
                    traceback.print_exc()
                    raise
                which_firmware = prefix + str(which_firmware_idx)

            if not which_firmware.startswith(prefix):
                raise Exception("You didn't choose one of the firmware options")
            which_firmware = int(which_firmware[len(prefix):])
        except:
            print("You didn't choose one of the firmware options")
            return False

        try:
            print("Using firmware index", which_firmware)
            the_firmware = firmware_options[which_firmware]
        except:
            print("You didn't choose one of the firmware options")
            return False

        self.platform = Architecture['xtensa'].standalone_platform
        self.arch = Architecture['xtensa']
        self.entry_addr = 0

        # Will create segments and set entry_addr as needed.
        the_firmware.load(self, self.parent_view)

        if self.entry_addr != 0:
            for seg in self.segments:
                if (seg.start <= self.entry_addr <= seg.end) and seg.executable:
                    #self.add_auto_segment(seg.start, seg.data_length,
                    #                      seg.data_offset, seg.data_length,
                    #                      SegmentFlag.SegmentContainsCode |
                    #                      SegmentFlag.SegmentReadable |
                    #                      SegmentFlag.SegmentExecutable)
                    # It seems the ReadOnlyCodeSectionSemantics kicks off the
                    # autoanalysis
                    self.add_auto_section('entry_section', seg.start,
                                          seg.end - seg.start,
                                          SectionSemantics.ReadOnlyCodeSectionSemantics
                                          )
            # I want to be able to find the entry point in the UI
            # I couldn't find a create_auto_function... maybe I didn't look hard
            # enough
            self.create_user_function(self.entry_addr)
            self.define_auto_symbol(Symbol(
                SymbolType.FunctionSymbol,
                self.entry_addr,
                "entry"))

        setup_esp8266_map(self)

        return True


class ESP32Firmware(BinaryView):
    """Loader for ESP32-family flash images (extended 24-byte header).

    Maps every segment at its load address with read/write/execute semantics
    derived from the ESP32 memory map, marks code segments so analysis runs,
    sets the entry point, and uses the windowed calling convention by default."""
    name = "ESP32Firmware"
    long_name = "ESP32 Firmware"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data
        self.entry_addr = 0

    @classmethod
    def is_valid_for_data(cls, data):
        return detect_esp32(data) is not None

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr

    def perform_get_address_size(self):
        return 4

    def init(self):
        img = detect_esp32(self.parent_view)
        if img is None:
            print("Not a recognizable ESP32 image")
            return False

        self.arch = Architecture['xtensa']
        self.platform = Architecture['xtensa'].standalone_platform
        self.entry_addr = 0

        # Adds all segments at their load addresses and sets self.entry_addr.
        img.load(self, self.parent_view)

        # Give each segment a section with the right semantics so analysis runs
        # over every code segment (not just the one containing the entry point).
        for load_addr, size, data_off in img.segments:
            _flags, is_code = classify_esp32_segment(load_addr)
            if is_code:
                sem = SectionSemantics.ReadOnlyCodeSectionSemantics
                name = "iram" if load_addr < 0x400c0000 else "irom"
            elif 0x3f000000 <= load_addr < 0x3f800000:
                sem = SectionSemantics.ReadOnlyDataSectionSemantics
                name = "drom"
            else:
                sem = SectionSemantics.ReadWriteDataSectionSemantics
                name = "dram"
            self.add_auto_section("%s_%08x" % (name, load_addr), load_addr,
                                  size, sem)

        if self.entry_addr != 0:
            self.add_entry_point(self.entry_addr)
            self.create_user_function(self.entry_addr)
            self.define_auto_symbol(Symbol(
                SymbolType.FunctionSymbol, self.entry_addr, "_start"))

        setup_esp32_map(self)

        return True

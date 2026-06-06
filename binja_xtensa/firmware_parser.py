#!/usr/bin/env python
"""
ESP8266 firmware parser

Very hacky at the moment. This logic is based on a quick reading of the
following sources:
    * https://github.com/espressif/esptool/wiki/Firmware-Image-Format
    * https://richard.burtons.org/2015/05/17/decompiling-the-esp8266-boot-loader-v1-3b3/
    * https://boredpentester.com/reversing-esp8266-firmware-part-3/ (that whole
      series really)

These firmware dumps seem to contain multiple binaries. So we have a rudimentary
heuristic to find a couple binaries, which we pass back in a list to the
binaryview to present to the user as options.
"""

import binascii
import struct

from binaryninja import BinaryViewType
from binaryninja.enums import SegmentFlag

class InvalidFormat(Exception):
    pass

class ESPSegment:
    header_fmt = "<II"

    def __init__(self, load_address, size, outer_size, data_bv_offset):
        self.outer_size = outer_size
        self.load_address = load_address
        self.size = size
        self.data_bv_offset = data_bv_offset

    def __repr__(self):
        return f"""ESPSegment(outer_size={hex(self.outer_size)},
load_address={hex(self.load_address)},
size={hex(self.size)},
data_bv_offset={hex(self.data_bv_offset)})
"""
    def load(self, bv, parent_bv, outer_entry_point=None):
        if outer_entry_point is None or not (
                self.load_address <=
                outer_entry_point <=
                self.load_address + self.size):
            permissions = (SegmentFlag.SegmentContainsCode |
                           SegmentFlag.SegmentContainsData |
                           SegmentFlag.SegmentReadable     |
                           SegmentFlag.SegmentWritable     |
                           SegmentFlag.SegmentExecutable)
        else:
            permissions = (SegmentFlag.SegmentContainsCode |
                           SegmentFlag.SegmentContainsData |
                           SegmentFlag.SegmentReadable     |
                           SegmentFlag.SegmentExecutable)

        bv.add_auto_segment(self.load_address, self.size,
                            self.data_bv_offset, self.size,
                            permissions)

    @classmethod
    def parse(cls, bv, bv_offset):
        header_size = struct.calcsize(cls.header_fmt)
        header = bv.read(bv_offset + 0, header_size)
        if len(header) < header_size:
            raise InvalidFormat("Could not read Segment Header")
        load_address, seg_size = struct.unpack(cls.header_fmt, header)

        return cls(
            outer_size=header_size + seg_size,
            load_address=load_address,
            size=seg_size,
            data_bv_offset=bv_offset + header_size)

class E9File:
    name = "Raw(E9)"
    header_fmt = "<BBBBI"
    def __init__(self, bv_offset, magic, segment_count, flash_interface,
                 flash_cfg, entry_point, data_bv_offset, outer_size):
        self.bv_offset = bv_offset
        self.magic = magic
        self.segment_count = segment_count
        self.flash_interface = flash_interface
        self.flash_cfg = flash_cfg
        self.entry_point = entry_point
        self.data_bv_offset = data_bv_offset
        self.outer_size = outer_size
        self.segments = []

    def __repr__(self):
        return f"""E9File(bv_offset={hex(self.bv_offset)},
magic={hex(self.magic)},
segment_count={self.segment_count},
flash_interface={hex(self.flash_interface)},
flash_cfg={hex(self.flash_cfg)},
entry_point={hex(self.entry_point)},
data_bv_offset={hex(self.data_bv_offset)},
outer_size={hex(self.outer_size)},
segments={repr(self.segments)})
"""

    def _segments_size(self):
        return sum(i.outer_size for i in self.segments)

    def load(self, bv, parent_bv, outer_entry_point=None):
        for seg in self.segments:
            seg.load(bv, parent_bv, outer_entry_point)
        bv.entry_addr = self.entry_point

    @classmethod
    def parse(cls, bv, bv_offset):
        header_size = struct.calcsize(cls.header_fmt)
        header = bv.read(bv_offset + 0, header_size)
        if len(header) < header_size:
            raise InvalidFormat("Could not read E9 Header")

        (magic, seg_count, flash_interface, flash_cfg,
         entry_point) = struct.unpack(cls.header_fmt, header)

        if magic != 0xe9:
            raise InvalidFormat("Invalid magic")

        f = cls(bv_offset=bv_offset,
                magic=magic,
                segment_count=seg_count,
                flash_interface=flash_interface,
                flash_cfg=flash_cfg,
                entry_point=entry_point,
                data_bv_offset=bv_offset + header_size,
                outer_size=None # will fill in below
                )

        for _ in range(seg_count):
            f.segments.append(ESPSegment.parse(bv, bv_offset + header_size + f._segments_size()))

        f.outer_size = header_size + f._segments_size()

        return f

class EAFile:
    name = "Bootloaded(EA)"
    header_fmt = "<BBBBIII"
    def __init__(self, bv_offset, magic1, magic2, config, entry_point,
                 text_length, data_bv_offset, outer_size):
        self.bv_offset = bv_offset
        self.magic1 = magic1
        self.magic2 = magic2
        self.config = config
        self.entry_point = entry_point
        self.text_length = text_length
        self.data_bv_offset = data_bv_offset
        self.outer_size = outer_size
        self.e9file = None

    def __repr__(self):
        return f"""EAFile(bv_offset={hex(self.bv_offset)},
magic1={hex(self.magic1)},
magic2={self.magic2},
config={hex(self.config[0])} {hex(self.config[1])},
entry_point={hex(self.entry_point)},
text_length={hex(self.text_length)},
data_bv_offset={hex(self.data_bv_offset)},
outer_size={hex(self.outer_size)},
e9file={repr(self.e9file)})
"""

    def load(self, bv, parent_bv):
        bv.add_auto_segment(0x40200000 + self.data_bv_offset, self.text_length,
                            self.data_bv_offset, self.text_length,
                            (SegmentFlag.SegmentContainsCode |
                             SegmentFlag.SegmentContainsData |
                             SegmentFlag.SegmentDenyWrite    |
                             SegmentFlag.SegmentReadable     |
                             SegmentFlag.SegmentExecutable))
        self.e9file.load(bv, parent_bv, self.entry_point)
        bv.entry_addr = self.entry_point

    @classmethod
    def parse(cls, bv, bv_offset):
        header_size = struct.calcsize(cls.header_fmt)
        header = bv.read(bv_offset + 0, header_size)
        if len(header) < header_size:
            raise InvalidFormat("Could not read EA Header")

        config = [None, None]
        (magic1, magic2, config[0], config[1], entry_point, unused, text_length
         ) = struct.unpack(cls.header_fmt, header)

        if magic1 != 0xea:
            raise InvalidFormat("Invalid magic")

        f = cls(bv_offset=bv_offset,
                magic1=magic1,
                magic2=magic2,
                config=config,
                entry_point=entry_point,
                text_length=text_length,
                data_bv_offset=bv_offset+header_size,
                outer_size=None # will fill in below
                )

        f.e9file = E9File.parse(bv, f.data_bv_offset + text_length)

        f.outer_size = header_size + text_length + f.e9file.outer_size

        return f

class AppendedData:
    name = "AppendedData"
    def __init__(self, length, data_bv_offset):
        self.length = length
        self.data_bv_offset = self.bv_offset = data_bv_offset
        self.outer_size = length

    def __repr__(self):
        return f"""AppendedData(length={hex(self.length)},
data_bv_offset={hex(self.data_bv_offset)})
"""

    def load(self, bv, parent_bv):
        bv.add_auto_segment(0, self.length,
                            self.data_bv_offset, self.length,
                            (SegmentFlag.SegmentContainsCode |
                             SegmentFlag.SegmentContainsData |
                             SegmentFlag.SegmentReadable     |
                             SegmentFlag.SegmentWritable     |
                             SegmentFlag.SegmentExecutable))

    @classmethod
    def parse(cls, bv, bv_offset):
        return AppendedData(bv.end-bv_offset, bv_offset)


# ---------------------------------------------------------------------------
# ESP32 image format
#
# ESP32 (and later) flash images start with the same 8-byte common header as the
# ESP8266 E9 image (magic 0xE9, segment_count, spi_mode, spi_size_freq, entry32)
# but follow it with a 16-byte EXTENDED header (wp_pin, spi_pin_drv[3],
# chip_id[2], min_chip_rev, reserved[8], hash_appended) before the first
# segment. Each segment is (load_addr u32, data_len u32, data...). After the last
# segment there is a 1-byte checksum padded to a 16-byte boundary, optionally
# followed by a 32-byte SHA-256 when hash_appended != 0.
# ---------------------------------------------------------------------------

# chip_id values for the RISC-V ESP variants -- their images share the 0xE9 magic
# and similar load addresses but are NOT Xtensa, so we must not claim them.
_RISCV_CHIP_IDS = {5, 12, 13, 16, 17, 18, 20, 21, 23}  # C3, C2, C6, H2, P4, C5, ...


# ESP32-family (Xtensa: ESP32 / -S2 / -S3) load-address ranges ->
# (segment flags, is_code, kind) classification. `kind` is the single source of
# truth for both segment permissions and the section semantics/name the loader
# applies (see ESP32Firmware.init), so the two never disagree.
def classify_esp32_segment(load_addr):
    rx = (SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentReadable |
          SegmentFlag.SegmentExecutable)
    ro = SegmentFlag.SegmentReadable
    rw = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    # DROM (external flash, read-only constants): ESP32 0x3F40_xxxx, S3 0x3C00_xxxx
    if 0x3c000000 <= load_addr < 0x3f800000:
        return ro, False, "drom"
    # DRAM / internal data RAM: ESP32 0x3FFB_xxxx, S3 0x3FC8_xxxx
    if 0x3f800000 <= load_addr < 0x40000000:
        return rw, False, "dram"
    # IRAM (on-chip instruction RAM) vs IROM (memory-mapped flash code):
    # up to S3 0x4200_0000
    if 0x40000000 <= load_addr < 0x42800000:
        return rx, True, ("iram" if load_addr < 0x400c0000 else "irom")
    # RTC slow/fast memory
    if 0x50000000 <= load_addr < 0x50002000:
        return rw, False, "rtc"
    # Anything else -> default read/write data
    return rw, False, "dram"


def _addr_is_plausible_esp32(load_addr):
    return (0x3c000000 <= load_addr < 0x40000000) or \
           (0x40000000 <= load_addr < 0x42800000) or \
           (0x50000000 <= load_addr < 0x50002000)   # RTC slow mem


class Esp32Image:
    name = "ESP32"
    # common 8 bytes + extended 16 bytes
    common_fmt = "<BBBBI"        # magic, seg_count, spi_mode, spi_size_freq, entry
    ext_fmt = "<B3sHB8sB"        # wp_pin, spi_pin_drv, chip_id, min_rev, rsvd, hash

    def __init__(self, bv_offset, entry_point, chip_id, hash_appended):
        self.bv_offset = bv_offset
        self.entry_point = entry_point
        self.chip_id = chip_id
        self.hash_appended = hash_appended
        self.segments = []   # list of (load_addr, size, data_offset)
        self.outer_size = None

    def __repr__(self):
        return (f"Esp32Image(entry={hex(self.entry_point)}, chip_id={self.chip_id}, "
                f"segments={[(hex(a), hex(s), hex(o)) for a, s, o in self.segments]})")

    @classmethod
    def parse(cls, bv, bv_offset=0):
        common_size = struct.calcsize(cls.common_fmt)      # 8
        ext_size = struct.calcsize(cls.ext_fmt)            # 16
        hdr = bv.read(bv_offset, common_size + ext_size)
        if len(hdr) < common_size + ext_size:
            raise InvalidFormat("Could not read ESP32 header")
        magic, seg_count, _mode, _size, entry = struct.unpack(
            cls.common_fmt, hdr[:common_size])
        if magic != 0xe9:
            raise InvalidFormat("Invalid magic")
        if seg_count == 0 or seg_count > 16:
            raise InvalidFormat("Implausible ESP32 segment count")
        _wp, _drv, chip_id, _rev, _rsvd, hash_appended = struct.unpack(
            cls.ext_fmt, hdr[common_size:common_size + ext_size])
        # Don't claim RISC-V ESP images (C3/C6/...): they share the magic but
        # their code is not Xtensa and would disassemble to garbage.
        if chip_id in _RISCV_CHIP_IDS:
            raise InvalidFormat("ESP RISC-V chip_id %d is not Xtensa" % chip_id)

        img = cls(bv_offset, entry, chip_id, hash_appended)
        cur = bv_offset + common_size + ext_size
        for _ in range(seg_count):
            seg_hdr = bv.read(cur, 8)
            if len(seg_hdr) < 8:
                raise InvalidFormat("Could not read ESP32 segment header")
            load_addr, seg_len = struct.unpack("<II", seg_hdr)
            if seg_len > 0x800000 or not _addr_is_plausible_esp32(load_addr):
                raise InvalidFormat(
                    f"Implausible ESP32 segment @ {hex(load_addr)} len {hex(seg_len)}")
            data_off = cur + 8
            img.segments.append((load_addr, seg_len, data_off))
            cur = data_off + seg_len
        img.outer_size = cur - bv_offset
        return img

    def load(self, bv, parent_bv):
        end = getattr(parent_bv, "end", None)
        for load_addr, size, data_off in self.segments:
            flags, _is_code, _kind = classify_esp32_segment(load_addr)
            # Clamp the mapped length to the bytes actually present (a truncated
            # image must not map past EOF).
            data_len = size if end is None else max(0, min(size, end - data_off))
            bv.add_auto_segment(load_addr, size, data_off, data_len, flags)
        bv.entry_addr = self.entry_point


def parse_firmware(bv):
    firmware_options = []
    try:
        f = E9File.parse(bv, 0)
        firmware_options.append(f)
    except InvalidFormat:
        # No E9 image at offset 0: this data isn't an ESP8266 firmware dump.
        return []

    if f.outer_size > 0x1000:
        return firmware_options
    # A second image may follow at 0x1000 (bootloaded EA, or a plain E9). Both
    # are optional, so a parse miss here is normal -- just skip the option.
    try:
        f2 = EAFile.parse(bv, 0x1000)
        firmware_options.append(f2)
    except InvalidFormat:
        pass

    try:
        f3 = E9File.parse(bv, 0x1000)
        firmware_options.append(f3)
    except InvalidFormat:
        pass

    next_addr = firmware_options[-1].bv_offset + firmware_options[-1].outer_size
    if (next_addr < bv.end):
        firmware_options.append(AppendedData.parse(bv, next_addr))

    return firmware_options


def detect_esp32(bv):
    """Return an Esp32Image if the data parses as an ESP32-family image, else None.

    Distinguishes ESP32 from ESP8266 (both start 0xE9) by validating that the
    segments parsed *with the 24-byte extended header* land at plausible ESP32
    load addresses, and rejects RISC-V ESP variants by chip_id."""
    # Cheap magic check before the full header/segment walk.
    if bv.read(0, 1) != b'\xe9':
        return None
    try:
        return Esp32Image.parse(bv, 0)
    except InvalidFormat:
        return None
    except Exception:
        return None

def main():
    TEST_FIRMWARE = ""
    bv = BinaryViewType['Raw'].open(TEST_FIRMWARE)
    if not bv:
        print("Could not open bv")
        return
    print()
    print()
    data = parse_firmware(bv)
    print(data)

if __name__ == '__main__':
    main()

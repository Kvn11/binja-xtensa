"""
Binary Ninja Xtensa support (ESP8266 / ESP32)

This package provides:

Xtensa (little-endian):
    * Length + mnemonic decoding for the full base ISA plus the Code Density,
      Windowed Register, Boolean, Floating-Point (single), MAC16 and synchronization
      options used by the ESP8266 (LX106) and ESP32 (LX6) cores.
    * Disassembly for those instructions (general, float `f`, boolean `b` and
      MAC16 `m` register files, special/user registers).
    * Lifting to BNIL for the common integer, load/store, branch, shift,
      multiply/divide, floating-point and the windowed-ABI call/return/frame
      instructions, which is what makes ESP32 firmware decompile usefully.
    * Two calling conventions: ``call0`` (the CALL0 ABI used by ESP8266 / the
      ESP32 bootloader) and ``windowed`` (the register-window ABI that dominates
      ESP32 application code). The windowed convention is the default.
    * Registration with the ELF loader (EM_XTENSA = 94).

ESP firmware loaders:
    * ``ESPFirmware`` detects and loads ESP8266 image dumps (E9 / bootloaded EA).
    * ``ESP32Firmware`` parses the ESP32 extended image header and maps every
      segment at its load address with correct read/write/execute semantics.

Register windowing note: Binary Ninja's LLIL has no register-window concept, and
WindowBase is a runtime value the disassembler cannot know statically. We
therefore keep the logical ``a0``..``a15`` model (each function references its own
window as a0..a15, which is exactly what the hardware presents after ENTRY), and
express the cross-call register shift through the windowed calling convention.
CALL/CALLX lift to ordinary calls, ENTRY to a stack-pointer adjust, and
RETW/RETW.N to returns. See lifter.py and the windowed convention below.
"""

from binaryninja import (Architecture, BinaryViewType, CallingConvention,
                         IntrinsicInfo, InstructionInfo, InstructionTextToken,
                         RegisterInfo, log)
from binaryninja.enums import (BranchType, Endianness, FlagRole,
                               LowLevelILFlagCondition)

from .instruction import Instruction
from .disassembly import disassemble_instruction
from .lifter import lift
from .binaryview import ESPFirmware, ESP32Firmware


__all__ = ['XtensaLE']


def _build_regs():
    regs = {}
    # General-purpose / "address" register file a0..a15
    for i in range(16):
        regs["a" + str(i)] = RegisterInfo("a" + str(i), 4, 0)
    # Shift Amount Register (not a GPR). 1 byte: the lifter reads/writes it as a
    # byte-sized shift amount throughout.
    regs["sar"] = RegisterInfo("sar", 1, 0)
    # Single-precision floating-point register file f0..f15
    for i in range(16):
        regs["f" + str(i)] = RegisterInfo("f" + str(i), 4, 0)
    # Boolean register file b0..b15 (1 bit each, modeled as 1 byte)
    for i in range(16):
        regs["b" + str(i)] = RegisterInfo("b" + str(i), 1, 0)
    # MAC16 register file m0..m3 and the 40-bit accumulator (modeled as 8 bytes)
    for i in range(4):
        regs["m" + str(i)] = RegisterInfo("m" + str(i), 4, 0)
    regs["acc"] = RegisterInfo("acc", 8, 0)
    # Special registers (RSR/WSR/XSR) and user registers, named after the ISA.
    # Declared so the lifter can model RSR/WSR/RUR/WUR as plain register moves.
    for name in set(Instruction._special_reg_map.values()):
        rn = name.lower()
        if rn not in regs:
            regs[rn] = RegisterInfo(rn, 4, 0)
    # THREADPTR user register (thread-local storage base, set via WUR)
    regs["threadptr"] = RegisterInfo("threadptr", 4, 0)
    return regs


# Conditional-branch mnemonics, computed once (used by get_instruction_info).
_CONDITIONAL_BRANCHES = frozenset(
    k for k in Instruction._target_offset_map.keys() if k.startswith("B"))
_LOOP_MNEMS = frozenset(["LOOP", "LOOPNEZ", "LOOPGTZ"])
_RETURN_MNEMS = frozenset(["RET", "RET.N", "RETW", "RETW.N"])
_DIRECT_CALL_MNEMS = frozenset(["CALL0", "CALL4", "CALL8", "CALL12"])
_INDIRECT_CALL_MNEMS = frozenset(["CALLX0", "CALLX4", "CALLX8", "CALLX12"])


class XtensaLE(Architecture):
    name = 'xtensa'
    endianness = Endianness.LittleEndian

    default_int_size = 4
    address_size = 4
    max_instr_length = 3

    # Uses for regs are from "CALL0 Register Usage and Stack Layout (8.1.2)"
    link_reg = 'a0'
    stack_pointer = 'a1'
    regs = _build_regs()

    # Do we have flags?
    flags = {}
    flag_roles = {}
    flag_write_types = {}
    flags_written_by_flag_write_type = {}
    flags_required_for_flag_condition = {}

    intrinsics = {
        # Memory ordering / synchronization
        "memw": IntrinsicInfo([], []),
        "extw": IntrinsicInfo([], []),
        "isync": IntrinsicInfo([], []),
        "rsync": IntrinsicInfo([], []),
        "esync": IntrinsicInfo([], []),
        "dsync": IntrinsicInfo([], []),
        "excw": IntrinsicInfo([], []),
        # Interrupt / privileged
        "waiti": IntrinsicInfo([], []),
        "rsil": IntrinsicInfo([], []),
        "simcall": IntrinsicInfo([], []),
        # External register access
        "rer": IntrinsicInfo([], []),
        "wer": IntrinsicInfo([], []),
        # Atomic compare-and-store (S32C1I)
        "s32c1i": IntrinsicInfo([], []),
        # MAC16 (semantics modeled in lifter where feasible; this is a fallback)
        "mac16": IntrinsicInfo([], []),
        # Bit-counting / clamp ops without a direct IL equivalent
        "clamps": IntrinsicInfo([], []),
        "nsa": IntrinsicInfo([], []),
        "nsau": IntrinsicInfo([], []),
        # Generic special-register access for reserved/undocumented SRs we
        # don't model as a named register (RSR/WSR/XSR over such an SR number)
        "rsr": IntrinsicInfo([], []),
        "wsr": IntrinsicInfo([], []),
        "xsr": IntrinsicInfo([], []),
        # Generic user-register access for URs we don't model by name
        "rur": IntrinsicInfo([], []),
        "wur": IntrinsicInfo([], []),
        # Cache control ops (no dataflow effect we model)
        "cache": IntrinsicInfo([], []),
        # MMU / TLB and instruction-cache test ops (privileged)
        "tlb": IntrinsicInfo([], []),
        "icache": IntrinsicInfo([], []),
        # Boolean reductions ANY/ALL
        "bcombine": IntrinsicInfo([], []),
    }

    def _decode_instruction(self, data, addr):
        try:
            insn = Instruction.decode(data)
        except IndexError:
            # Truncated buffer at end of segment: not enough bytes
            return None
        except NotImplementedError:
            return None
        if insn is None or not insn.valid:
            return None
        return insn

    def get_instruction_info(self, data, addr):
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        result = InstructionInfo()
        result.length = insn.length
        if insn.length is None or insn.length > 3 or insn.length < 1:
            return None

        mnem = insn.mnem

        # Returns (CALL0 and windowed)
        if mnem in _RETURN_MNEMS:
            result.add_branch(BranchType.FunctionReturn)

        # Unconditional jump
        elif mnem == "J":
            result.add_branch(BranchType.UnconditionalBranch,
                              insn.target_offset(addr))
        elif mnem == "JX":
            result.add_branch(BranchType.IndirectBranch)

        # Direct calls (CALL0/4/8/12)
        elif mnem in _DIRECT_CALL_MNEMS:
            result.add_branch(BranchType.CallDestination,
                              insn.target_offset(addr))
        # Indirect calls (CALLX*): no static target; the lifter emits il.call so
        # Binary Ninja derives the call from LLIL. No branch added here.
        elif mnem in _INDIRECT_CALL_MNEMS:
            pass

        elif mnem == "SYSCALL":
            result.add_branch(BranchType.SystemCall)

        # Zero-overhead loop: LOOPNEZ/LOOPGTZ conditionally skip the loop body by
        # branching to the loop-end target when the count is zero / non-positive.
        # The lifter jumps to the target on that condition, so the taken (True)
        # edge is the loop-end target and the fall-through (False) edge enters the
        # loop -- matching _lift_LOOPNEZ/_lift_LOOPGTZ. LOOP always enters.
        elif mnem in ("LOOPNEZ", "LOOPGTZ"):
            result.add_branch(BranchType.TrueBranch, insn.target_offset(addr))
            result.add_branch(BranchType.FalseBranch, addr + insn.length)

        # Conditional branches (the B* family)
        elif mnem.replace(".", "_") in _CONDITIONAL_BRANCHES:
            result.add_branch(BranchType.TrueBranch, insn.target_offset(addr))
            result.add_branch(BranchType.FalseBranch, addr + insn.length)

        return result

    def get_instruction_text(self, data, addr):
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        text = disassemble_instruction(insn, addr)
        return text, insn.length

    def get_instruction_low_level_il(self, data, addr, il):
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        return lift(insn, addr, il)


class XtensaCall0CallingConvention(CallingConvention):
    """The CALL0 ABI (ESP8266 and the ESP32 bootloader / CALL0 leaf code)."""
    name = "call0"
    # a0 is dubiously caller saved... it's the ret addr / link register
    caller_saved_regs = ["a0", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9",
                         "a10", "a11"]
    callee_saved_regs = ["a12", "a13", "a14", "a15"]
    int_arg_regs = ["a2", "a3", "a4", "a5", "a6", "a7"]
    int_return_reg = "a2"
    high_int_return_reg = "a3"


class XtensaWindowedCallingConvention(CallingConvention):
    """The register-window ABI that dominates ESP32 application code.

    Binary Ninja analyzes each function in its own (rotated) window, so the
    callee sees its incoming arguments as a2..a7 and returns in a2/a3 -- the
    same register names as CALL0 from the callee's frame.

    Saved-register note: in the real windowed ABI the hardware preserves the
    caller's low window (a0..a(15-N) for a CALLn that rotates by N) across a
    call, but Binary Ninja has no register-window concept and applies one
    flat convention from the callee's frame, where a2..a7 are simultaneously
    the argument/return registers AND (physically, in the caller's frame)
    preserved. Those two roles can't both be expressed in a flat model. We take
    the conservative choice -- only a0 (return PC) and a1 (SP) are callee-saved,
    everything else is caller-saved -- which never claims a clobbered register
    is preserved (so it never produces incorrect dataflow), at the cost of
    occasionally not tracking a value held in a2..a7 across a call."""
    name = "windowed"
    int_arg_regs = ["a2", "a3", "a4", "a5", "a6", "a7"]
    int_return_reg = "a2"
    high_int_return_reg = "a3"
    callee_saved_regs = ["a0", "a1"]
    caller_saved_regs = ["a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10",
                         "a11", "a12", "a13", "a14", "a15"]


def register_stuff():
    XtensaLE.register()

    # Register ourselves with the ELF loader (EM_XTENSA = 94)
    BinaryViewType['ELF'].register_arch(94, Endianness.LittleEndian,
                                        Architecture['xtensa'])
    arch = Architecture['xtensa']
    call0 = XtensaCall0CallingConvention(arch, "call0")
    windowed = XtensaWindowedCallingConvention(arch, "windowed")
    arch.register_calling_convention(call0)
    arch.register_calling_convention(windowed)

    # ESP32 application code is overwhelmingly windowed; default to that so
    # Binary Ninja recovers windowed arguments without an explicit annotation.
    esp_plat = arch.standalone_platform
    esp_plat.default_calling_convention = windowed
    esp_plat.system_call_convention = call0

    ESPFirmware.register()
    ESP32Firmware.register()


register_stuff()

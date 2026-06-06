import binascii
import bz2
from collections import namedtuple
import csv
import os
import re

import pytest

from .instruction import Instruction, InstructionType, sign_extend
from .disassembly import disassemble_instruction, tokens_to_text

DIR = os.path.dirname(__file__)

def test_decode_abs():
    # RRR type
    # ABS ar, at
    # 0110 0000 rrrr 0001 tttt 0000
    # 60        r1        t0
    # ABS a7, a9
    # 60 71 90 => 907160
    INSN_ABS = binascii.unhexlify("907160")
    insn = Instruction.decode(INSN_ABS)
    assert insn.op0 == 0
    assert insn.op1 == 0
    assert insn.op2 == 6
    assert insn.r == 7
    assert insn.t == 9
    assert insn.s == 1
    assert insn.length == 3
    assert insn.mnem == "ABS"
    assert insn.instruction_type == InstructionType.RRR

def test_decode_add():
    """
    ADD ar, as, at
    ADD a3, a2, a1

    * bit 23
    * 1000 # op2
    * 0000 # op1
    * 0011 # a3 is r
    * 0010 # a2 is s
    * 0001 # a1 is t
    * 0000 # op0
    * bit 0

    Thus our insn is 80 32 10, which must be byte swapped to 10 32 80
    """
    #EveryInstR Group
    insn = Instruction.decode(binascii.unhexlify("103280"))
    assert insn.op0 == 0
    assert insn.op1 == 0
    assert insn.op2 == 8
    assert insn.r == 3
    assert insn.s == 2
    assert insn.t == 1
    assert insn.length == 3
    assert insn.mnem == "ADD"
    assert insn.instruction_type == InstructionType.RRR

def test_add_narrow():
    """
    ADD.N ar, as, at
    * bit 15
    * rrrr
    * ssss
    * tttt
    * 1010 # op0
    * bit 0
    Requires Code Density Option

    ADD.N a9, a5, a3
    is then 1001 0101 0011 1010, or 953a, reversed to 3a95
    """
    INSN_ADD_N = binascii.unhexlify("3a95")
    insn = Instruction.decode(INSN_ADD_N)
    assert insn.op0 == 0b1010
    assert insn.t == 3
    assert insn.s == 5
    assert insn.r == 9
    assert insn.length == 2
    assert insn.mnem == "ADD.N"

def test_addi():
    """
    RRI8 type
    ADDI at, as, -128..127
    * bit 23
    * imm8 # check encoding of this
    * 1100
    * s
    * t
    * 0010
    * bit 0
    
    ADDI a11, a1, -2
    is then
    1111 1110 1100 0001 1011 0010, or fe c1 b2, reversed to b2c1fe
    """
    insn = Instruction.decode(binascii.unhexlify("b2c1fe"))
    assert insn.op0 == 0b0010
    assert insn.r == 0b1100
    assert insn.s == 1
    assert insn.t == 11
    # TODO: handle and test negative handling. I'd argue it should be a separate
    # value, as the decoded imm8 doesn't seem like a signed value
    #assert insn.imm8 == -2
    assert insn.imm8 == 0b11111110
    assert insn.length == 3
    assert insn.mnem == "ADDI"
    assert insn.instruction_type == InstructionType.RRI8


test_mnemonics_data = []
with bz2.open(os.path.join(DIR, "test_mnemonics.csv.bz2"), "rt") as fp:
    reader = csv.reader(fp)
    for row in reader:
        opcode = row[0]
        mnem = row[1]
        opbytes = binascii.unhexlify(opcode)
        test_mnemonics_data.append((opbytes, mnem.strip()))


def test_mnemonics_data_is_valid():
    assert len(test_mnemonics_data) > 0
    assert len(test_mnemonics_data[0]) == 2

def compare_mnem(one, two):
    to_compare = []
    for it in (one, two):
        if (it.startswith("rsr.") or
            it.startswith("wsr.") or
            it.startswith("xsr.")):
                # Work around not having the register names for special regs
                it = it[:3]
        it = it.lower().strip()
        to_compare.append(it)
    one, two = to_compare
    return one == two


@pytest.mark.parametrize("opbytes,mnem_expected", test_mnemonics_data)
def test_mnem_from_file(opbytes, mnem_expected):
    insn = Instruction.decode(opbytes)
    assert insn.length == len(opbytes)
    assert compare_mnem(insn.mnem, mnem_expected)

mtd_re = r'([0-9a-f]+):\s+([0-9a-f]+)\s+([a-z0-9.]+)\s+(.*)$'
mtd_rec = re.compile(mtd_re)
with bz2.open(os.path.join(DIR, "test_mnemonic_text.dump.bz2"), "rt") as fp:
    mnem_text_dump = fp.readlines()

def bswap_opcode_string(opstr):
    data = binascii.unhexlify(opstr)
    reverse_data = bytearray(data)
    reverse_data.reverse()
    return binascii.hexlify(reverse_data).decode('utf-8')

DisassLine = namedtuple('DisassLine', ['addr', 'opcode', 'mnem', 'rest'])

def parse_test_data(data_lines):
    newdata = []
    for line in data_lines:
        match_obj = mtd_rec.match(line)
        assert match_obj
        addr, opcode, mnem, rest = match_obj.groups()
        opcode = bswap_opcode_string(opcode)
        assert len(addr)
        assert len(opcode)
        assert len(mnem)
        newdata.append(DisassLine(addr, opcode, mnem, rest))
    return newdata

def test_mtd_re():
    data = parse_test_data(mnem_text_dump)
    assert len(data) > 0
    assert len(data[0]) == 4

def _normalize_insn(it):
    it = it.replace("\t", "").lower()
    tokens = []
    for tok in it.split():
        tok = tok.replace(",", "")
        if tok.startswith("0x"):
            tokens.append(str(sign_extend(int(tok, 0), 32)))
        else:
            tokens.append(tok)
    return ''.join(tokens)

def compare_insn(one, two):
    one = _normalize_insn(one)
    two = _normalize_insn(two)

    return one == two

def test_tokens_to_text():
    INSN_ABS = binascii.unhexlify("907160")
    insn = Instruction.decode(INSN_ABS)
    disass_text = tokens_to_text(disassemble_instruction(insn, 0))
    assert compare_insn(disass_text, "ABS    a7, a9")
    assert compare_insn(disass_text, "abs a7, a9")

# Reserved / undocumented special registers. Real ESP32 firmware uses SR numbers
# that aren't in any Tensilica/ESP table (e.g. XSR a0, 54 -- bytes 00 36 61 --
# which appears throughout real ESP32 firmware), and Binary Ninja sweeps such bytes as
# code. The SR must decode to its bare decimal (matching objdump's "176"/"208"
# placeholders), and get_sr_name() must return that string -- NOT a phantom
# register name. The lifter relies on this (it routes any SR not in
# _special_reg_map to an intrinsic) to avoid the "non-existant register" crash.
@pytest.mark.parametrize("opcode,mnem,sr_num", [
    ("003661", "XSR", 54),    # the instruction that crashed BN ("string 54")
    ("008803", "RSR", 136),
    ("00cd03", "RSR", 205),
    ("003813", "WSR", 56),
])
def test_reserved_special_register_decode(opcode, mnem, sr_num):
    insn = Instruction.decode(binascii.unhexlify(opcode))
    assert compare_mnem(insn.mnem, mnem)
    assert insn.sr == sr_num
    assert sr_num not in Instruction._special_reg_map
    assert insn.get_sr_name() == str(sr_num)
    disass_text = tokens_to_text(disassemble_instruction(insn, 0))
    assert compare_insn(disass_text, "%s.%d a0" % (mnem, sr_num))

mtd_data = parse_test_data(mnem_text_dump)
# mnem_text_dump is a bunch of dumped disassembly, uniq'd on the mnem for
# brevity
@pytest.mark.parametrize("parsed_line", mtd_data)
def test_mnem_text_dump(parsed_line):
    insn = Instruction.decode(binascii.unhexlify(parsed_line.opcode))
    assert compare_mnem(insn.mnem, parsed_line.mnem)

    addr = int(parsed_line.addr, 16)
    disass_text = tokens_to_text(disassemble_instruction(insn, addr))

    expected_insn_text = (parsed_line.mnem + " " + parsed_line.rest).strip()

    assert compare_insn(expected_insn_text, disass_text)

with bz2.open(os.path.join(DIR, "torture_test.dump.bz2"), "rt") as fp:
    lots_text_dump = fp.readlines()
lots_data = parse_test_data(lots_text_dump)
# lots_text_dump is a bunch of dumped disassembly, uniq'd on the mnem for
# brevity
@pytest.mark.parametrize("parsed_line", lots_data)
def test_lots_text_dump(parsed_line):
    insn = Instruction.decode(binascii.unhexlify(parsed_line.opcode))
    assert compare_mnem(insn.mnem, parsed_line.mnem)

    addr = int(parsed_line.addr, 16)
    disass_text = tokens_to_text(disassemble_instruction(insn, addr))

    expected_insn_text = (parsed_line.mnem + " " + parsed_line.rest).strip()

    assert compare_insn(expected_insn_text, disass_text)

with bz2.open( os.path.join(DIR, "esp32_torture_test.dump.bz2"), "rt") as fp:
    esp32_lots_text_dump = fp.readlines()
esp32_lots_data = parse_test_data(esp32_lots_text_dump)
# lots_text_dump is a bunch of dumped disassembly, uniq'd on the mnem for
# brevity
@pytest.mark.parametrize("esp32_parsed_line", esp32_lots_data)
def test_esp32_lots_text_dump(esp32_parsed_line):
    if esp32_parsed_line.mnem in ['rer', 'wer']:
        # I disagree with objdump here; the manual states that these insns take
        # arguments; objdump doesn't appear to think so? Also possible my
        # cleanup of the output broke the objdump results?
        pytest.xfail()
    insn = Instruction.decode(binascii.unhexlify(esp32_parsed_line.opcode))
    assert compare_mnem(insn.mnem, esp32_parsed_line.mnem)

    addr = int(esp32_parsed_line.addr, 16)
    disass_text = tokens_to_text(disassemble_instruction(insn, addr))

    expected_insn_text = (esp32_parsed_line.mnem + " " +
            esp32_parsed_line.rest).strip()

    assert compare_insn(expected_insn_text, disass_text)

def test_rotw_positive():
    rotw_insn = binascii.unhexlify("208040") # ROTW 2
    insn = Instruction.decode(rotw_insn)
    assert compare_mnem(insn.mnem, "ROTW")
    assert insn.rotw_simm4() == 2
    disass_text = tokens_to_text(disassemble_instruction(insn, 0x1000))
    assert compare_insn(disass_text, "ROTW 2")

def test_rotw_negative():
    rotw_insn = binascii.unhexlify("f08040") # ROTW -1
    insn = Instruction.decode(rotw_insn)
    assert compare_mnem(insn.mnem, "ROTW")
    assert insn.rotw_simm4() == -1
    disass_text = tokens_to_text(disassemble_instruction(insn, 0x1000))
    assert compare_insn(disass_text, "ROTW -1")

# We didn't have any tests for the FPU, which lead to an undetected typo
def test_mov_s_fpu():
    movs_insn = binascii.unhexlify("0012fa")
    insn = Instruction.decode(movs_insn)
    assert compare_mnem(insn.mnem, "MOV.S")
    disass_text = tokens_to_text(disassemble_instruction(insn, 0x1000))
    assert compare_insn(disass_text, "MOV.S f1, f2")


# ---- ESP32 / extended coverage tests ----

def _dis(hexle, addr=0x1000):
    insn = Instruction.decode(binascii.unhexlify(hexle))
    return insn, tokens_to_text(disassemble_instruction(insn, addr))


def test_fp_arith_renders_float_regs():
    # MUL.S f1, f2, f3 (dotted mnemonic + float register operands)
    insn, txt = _dis("30122a")
    assert insn.mnem == "MUL.S"
    assert compare_insn(txt, "MUL.S f1, f2, f3")


def test_extui_source_is_t_field():
    # extui a0, a1, 0, 1 (source is the t field; matches objdump/binutils)
    insn, txt = _dis("100004")
    assert insn.mnem == "EXTUI"
    assert compare_insn(txt, "EXTUI a0, a1, 0, 1")


def test_ssai_shift_16_is_valid():
    # SSAI shift 16 sets bit 0 of the t field; must remain a valid encoding.
    insn = Instruction.decode(binascii.unhexlify("104040"))
    assert insn.mnem == "SSAI"
    assert insn.valid
    assert insn.inline0(0) == 16


def test_s32c1i_scaled_offset():
    insn, txt = _dis("42e320")
    assert insn.mnem == "S32C1I"
    assert insn.inline0(0) == 128        # imm8 (32) << 2
    assert compare_insn(txt, "S32C1I a4, a3, 128")


def test_reserved_encoding_is_invalid_not_crash():
    # op0 = 1111 is reserved; decoding must not raise and must mark invalid.
    insn = Instruction.decode(binascii.unhexlify("0f0000"))
    assert insn is not None
    assert not insn.valid
    assert insn.length in (2, 3)


def test_cust_encodings_invalid():
    for hexle in ["000006", "000007"]:   # CUST0 / CUST1 (op0=0, op1=6/7)
        insn = Instruction.decode(binascii.unhexlify(hexle))
        assert not insn.valid


def test_windowed_decode():
    assert Instruction.decode(binascii.unhexlify("250000")).mnem == "CALL8"
    entry = Instruction.decode(binascii.unhexlify("364100"))
    assert entry.mnem == "ENTRY"
    assert entry.inline0(0) == 32        # imm12 (4) << 3
    assert Instruction.decode(binascii.unhexlify("1df0")).mnem == "RETW.N"


# MAC16 encodings (little-endian) decoded from binutils hex templates.
MAC16_CASES = [
    ("040074", "MUL.AA.LL", "mul.aa.ll a0, a0"),
    ("040077", "MUL.AA.HH", "mul.aa.hh a0, a0"),
    ("040070", "UMUL.AA.LL", "umul.aa.ll a0, a0"),
    ("04007f", "MULS.AA.HH", "muls.aa.hh a0, a0"),
    ("040024", "MUL.DD.LL", "mul.dd.ll m0, m2"),
    ("040034", "MUL.AD.LL", "mul.ad.ll a0, m2"),
    ("040064", "MUL.DA.LL", "mul.da.ll m0, a0"),
    ("040008", "MULA.DD.LL.LDINC", "mula.dd.ll.ldinc m0, a0, m0, m2"),
    ("040048", "MULA.DA.LL.LDINC", "mula.da.ll.ldinc m0, a0, m0, a0"),
    ("040080", "LDINC", "ldinc m0, a0"),
    ("040090", "LDDEC", "lddec m0, a0"),
]


@pytest.mark.parametrize("hexle,mnem,text", MAC16_CASES)
def test_mac16(hexle, mnem, text):
    insn, txt = _dis(hexle)
    assert insn.mnem == mnem
    assert insn.valid
    assert compare_insn(txt, text)


def test_fp_loadstore_renders_float_regs():
    # LSX: float reg is the r field, address is AR[s]+AR[t]
    insn, txt = _dis("001108")
    assert insn.mnem == "LSX"
    assert compare_insn(txt, "LSX f1, a1, a0")
    # LSI: float reg is the t field, offset is imm8<<2 (153<<2 == 612)
    insn, txt = _dis("130599")
    assert insn.mnem == "LSI"
    assert compare_insn(txt, "LSI f1, a5, 612")


def test_clamps_immediate_operand():
    insn, txt = _dis("002733")
    assert insn.mnem == "CLAMPS"
    assert compare_insn(txt, "CLAMPS a2, a7, 7")   # immediate is t+7, not a register


def test_movf_boolean_condition():
    insn, txt = _dis("2030c3")
    assert insn.mnem == "MOVF"
    assert compare_insn(txt, "MOVF a3, a0, b2")    # condition is a boolean reg


def test_loop_targets_and_renders():
    # LOOP family must compute a target offset and render (not unimplemented).
    # LOOP a3, target: B1 map under SI->BI1->B1; build LOOP encoding.
    # (Decoded form is validated against the disassembler.)
    for hexle in ["768300", "769300", "76a300"]:  # LOOP/LOOPNEZ/LOOPGTZ a3
        insn = Instruction.decode(binascii.unhexlify(hexle))
        txt = tokens_to_text(disassemble_instruction(insn, 0x1000))
        assert "unimplemented" not in txt
        assert insn.target_offset(0x1000) is not None


"""
Xtensa lifting to BNIL

Here we provide a `lift` function that takes a decoded instruction and an
address where that instruction is, and we return BNIL.
"""
from binaryninja import Architecture, LowLevelILLabel

from .instruction import sign_extend, Instruction
from .windowed_abi import windowed_arg_srcs, windowed_return_dsts, WINDOWED_CALL_INCR, NUM_ARG_SLOTS

def _reg_name(insn, fmt):
    """Get the concrete register for a particular part of an instruction

    For example, if the docs say an instruction writes to "as", we call this
    function, which will check the `s` decoded control signal (say it's "7") and
    return "a7" for passing to BNIL.
    """
    prefix = fmt[0]
    # a = general (AR), f = float (FR), b = boolean (BR), m = MAC16 (M)
    if prefix not in ("a", "f", "b", "m"):
        raise Exception("Unimplemented reg name fmt: " + fmt)
    rest = fmt[1:]
    val = getattr(insn, rest, None)
    if val is None:
        raise Exception("Could not find property " + fmt)
    return prefix + str(val)

def lift(insn, addr, il):
    """Dispatch function for lifting

    Looks up _lift_MNEM() in the current global namespace (I think that's just
    the module level?) and calls it if it exists, otherwise we say the
    instruction is unimplemented.
    """
    if getattr(insn, "mac16_kind", None):
        return _lift_mac16(insn, addr, il)
    try:
        # We replace the "." in mnemonics with a "_", as we do in several other
        # places in the code.
        # At some point, this should become a property of the Instruction.
        func = globals()["_lift_" + insn.mnem.replace(".", "_")]
    except KeyError:
        il.append(il.unimplemented())
        return insn.length

    return func(insn, addr, il)

# Helpers for some shared code between instructions

def _lift_cond(cond, insn, addr, il):
    """Helper for lifting conditional jumps
    
    We pass in an IL condition (LowLevelILExpr) and this function lifts a IL
    conditional that will jump to `insn.target_offset(addr)` if the condition is
    true, otherwise we continue to the next instruction.
    """
    true_label = il.get_label_for_address(Architecture['xtensa'],
                                           insn.target_offset(addr))
    false_label = il.get_label_for_address(Architecture['xtensa'],
                                          addr + insn.length)
    must_mark_true = False
    if true_label is None:
        true_label = LowLevelILLabel()
        must_mark_true = True

    must_mark_false = False
    if false_label is None:
        false_label = LowLevelILLabel()
        must_mark_false = True

    il.append(
        il.if_expr(cond,
                   true_label,
                   false_label
                   ))
    if must_mark_true:
        il.mark_label(true_label)
        il.append(il.jump(il.const(4, insn.target_offset(addr))))
    if must_mark_false:
        il.mark_label(false_label)
        il.append(il.jump(il.const(4, addr + insn.length)))
    return insn.length

def _lift_cmov(cond, insn, addr, il):
    """Helper for lifting conditional moves
    
    We pass in an IL condition (LowLevelILExpr) and this function lifts a move
    from as to ar if the condition is true. In either case we then continue with
    the next instruction after the (potential) move.
    """
    true_label = LowLevelILLabel()
    false_label = LowLevelILLabel()
    il.append(il.if_expr(cond, true_label, false_label))
    il.mark_label(true_label)
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.reg(4, _reg_name(insn, "as"))))
    il.mark_label(false_label)
    return insn.length

def _lift_addx(x_bits, insn, addr, il):
    """Helper for ADDX2, ADDX4, ADDX8"""
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.shift_left(4,
                                        il.reg(4, _reg_name(insn, "as")),
                                        il.const(4, x_bits)),
                          il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_subx(x_bits, insn, addr, il):
    """Helper for SUBX2, SUBX4, SUBX8"""
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.sub(4,
                          il.shift_left(4,
                                        il.reg(4, _reg_name(insn, "as")),
                                        il.const(4, x_bits)),
                          il.reg(4, _reg_name(insn, "at")))))
    return insn.length

# From here on down, I lifted instructions in priority order of how much
# analysis it would get me. So I started with branches and common math and
# worked my way down the frequency list.

def _lift_CALL0(insn, addr, il):
    dest = il.const(4, insn.target_offset(addr))
    il.append(
        il.call(dest))
    return insn.length

def _lift_CALLX0(insn, addr, il):
    dest = il.reg(4, _reg_name(insn, "as"))
    il.append(
        il.call(dest))
    return insn.length

def _lift_RET(insn, addr, il):
    dest = il.reg(4, 'a0')
    il.append(il.ret(dest))
    return insn.length

_lift_RET_N = _lift_RET

def _lift_L32I_N(insn, addr, il):
    _as = il.reg(4, _reg_name(insn, "as"))
    imm = il.const(4, insn.inline0(addr))
    va = il.add(4, _as, imm)
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.load(4, va)
                   ))
    return insn.length

def _lift_L32R(insn, addr, il):
    va = il.const(4, insn.mem_offset(addr))
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.load(4, va)
                   ))
    return insn.length

def _lift_S32I_N(insn, addr, il):
    _as = il.reg(4, _reg_name(insn, "as"))
    imm = il.const(4, insn.inline0(addr))
    va = il.add(4, _as, imm)
    il.append(
        il.store(4, va, il.reg(4, "a" + str(insn.t))))
    return insn.length

def _lift_MOVI_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "as"),
                   il.const(4, insn.inline0(addr))
                   ))
    return insn.length

def _lift_MOV_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.reg(4, _reg_name(insn, "as"))
                   ))
    return insn.length

def _lift_ADDI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.const(4, insn.simm8())
                          )))
    return insn.length

def _lift_L8UI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.imm8))
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.zero_extend(4,
                                  il.load(1, va))))
    return insn.length

def _lift_S32I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(
        il.store(4, va, il.reg(4, _reg_name(insn, "at"))))
    return insn.length

def _lift_L32I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.load(4, va)))
    return insn.length

def _lift_L16SI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.sign_extend(4, il.load(2, va))))
    return insn.length

def _lift_L16UI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.zero_extend(4, il.load(2, va))))
    return insn.length

def _lift_J(insn, addr, il):
    il.append(il.jump(il.const(4, insn.target_offset(addr))))
    return insn.length

def _lift_JX(insn, addr, il):
    il.append(il.jump(il.reg(4, _reg_name(insn, "as"))))
    return insn.length

def _lift_S8I(insn, addr, il):
    il.append(il.store(1, il.add(4,
                                 il.reg(4, _reg_name(insn, "as")),
                                 il.const(4, insn.imm8)),
                       il.low_part(1, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_MOVI(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.const(4, insn.inline0(addr))))
    return insn.length

def _lift_EXTUI(insn, addr, il):
    # EXTUI extracts a bitfield from AR[t] (source is the t field; confirmed
    # against binutils/objdump -- the manual's "AR[s]" is an error)
    inp = il.reg(4, _reg_name(insn, "at"))

    mask = (2 ** insn.inline1(addr)) - 1
    mask_il = il.const(4, mask)

    shiftimm = insn.extui_shiftimm()
    if shiftimm:
        shift_il = il.const(1, shiftimm)
        shifted = il.logical_shift_right(4, inp, shift_il)
        anded = il.and_expr(4, shifted, mask_il)
    else:
        # If we don't have to shift (thus shiftimm should be 0), then don't emit
        # the IL for it
        anded = il.and_expr(4, inp, mask_il)

    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         anded
                         ))
    return insn.length

def _lift_OR(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.or_expr(4,
                              il.reg(4, _reg_name(insn, "as")),
                              il.reg(4, _reg_name(insn, "at"))
                              )))
    return insn.length

def _lift_MEMW(insn, addr, il):
    il.append(
        il.intrinsic([], "memw", [])
    )
    return insn.length

def _lift_ADDI_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                       il.reg(4, _reg_name(insn, "as")),
                       il.const(4, insn.inline0(addr))
                   )))
    return insn.length

def _lift_SLLI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.shift_left(4,
                       il.reg(4, _reg_name(insn, "as")),
                       il.const(1, insn.inline0(addr))
                       )))
    return insn.length

def _lift_ADD_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_AND(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.and_expr(4,
                              il.reg(4, _reg_name(insn, "as")),
                              il.reg(4, _reg_name(insn, "at"))
                              )))
    return insn.length

def _lift_BEQZ(insn, addr, il):
    cond = il.compare_equal(4,
                            il.reg(4, _reg_name(insn, "as")),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

_lift_BEQZ_N = _lift_BEQZ

def _lift_BNEZ(insn, addr, il):
    cond = il.compare_not_equal(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

_lift_BNEZ_N = _lift_BNEZ

def _lift_BNEI(insn, addr, il):
    cond = il.compare_not_equal(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.const(4, insn.b4const()))
    return _lift_cond(cond, insn, addr, il)

def _lift_BEQI(insn, addr, il):
    cond = il.compare_equal(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.const(4, insn.b4const()))
    return _lift_cond(cond, insn, addr, il)

def _lift_BALL(insn, addr, il):
    cond = il.compare_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "at")),
                                il.not_expr(4, il.reg(4, _reg_name(insn, "as")))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNALL(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "at")),
                                il.not_expr(4, il.reg(4, _reg_name(insn, "as")))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BANY(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.reg(4, _reg_name(insn, "at"))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNONE(insn, addr, il):
    cond = il.compare_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.reg(4, _reg_name(insn, "at"))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _bbc_bbs_index(insn, il):
    # The tested bit is AR[t]_{4..0}: only the low 5 bits select the bit.
    return il.and_expr(4,
                       il.reg(4, _reg_name(insn, "at")),
                       il.const(4, 0x1f))

def _lift_BBC(insn, addr, il):
    cond = il.compare_equal(4,
                            il.test_bit(4,
                                il.reg(4, _reg_name(insn, "as")),
                                _bbc_bbs_index(insn, il)
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBS(insn, addr, il):
    cond = il.test_bit(4,
        il.reg(4, _reg_name(insn, "as")),
        _bbc_bbs_index(insn, il))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBCI(insn, addr, il):
    cond = il.compare_equal(4,
                            il.test_bit(4,
                                il.reg(4, _reg_name(insn, "as")),
                                # Also: TODO: figure out which way Binja numbers
                                # the bits
                                il.const(4, insn.inline0(addr))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBSI(insn, addr, il):
    cond = il.test_bit(4,
        il.reg(4, _reg_name(insn, "as")),
        il.const(4, insn.inline0(addr)))
    return _lift_cond(cond, insn, addr, il)

def _lift_BEQ(insn, addr, il):
    cond = il.compare_equal(4,
                            il.reg(4, _reg_name(insn, "as")),
                            il.reg(4, _reg_name(insn, "at")))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNE(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.reg(4, _reg_name(insn, "as")),
                            il.reg(4, _reg_name(insn, "at")))
    return _lift_cond(cond, insn, addr, il)

def _lift_BGE(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.reg(4, _reg_name(insn, "at"))
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEU(insn, addr, il):
    cond = il.compare_unsigned_greater_equal(4,
                                             il.reg(4, _reg_name(insn, "as")),
                                             il.reg(4, _reg_name(insn, "at"))
    )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEI(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, insn.b4const())
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEUI(insn, addr, il):
    cond = il.compare_unsigned_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, insn.b4constu())
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEZ(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BLT(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.reg(4, _reg_name(insn, "at"))
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTU(insn, addr, il):
    cond = il.compare_unsigned_less_than(4,
                                         il.reg(4, _reg_name(insn, "as")),
                                         il.reg(4, _reg_name(insn, "at"))
                                         )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTI(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.const(4, insn.b4const())
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTUI(insn, addr, il):
    cond = il.compare_unsigned_less_than(4,
                                         il.reg(4, _reg_name(insn, "as")),
                                         il.const(4, insn.b4constu())
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTZ(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_SUB(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.sub(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_ADD(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_XOR(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.xor_expr(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_S16I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr))
                )
    il.append(
        il.store(2, va,
                 il.low_part(2, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_SRAI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.arith_shift_right(4,
                                        il.reg(4, _reg_name(insn, "at")),
                                        il.const(4, insn.inline0(addr)))))
    return insn.length

def _lift_ADDX2(insn, addr, il):
    return _lift_addx(1, insn, addr, il)

def _lift_ADDX4(insn, addr, il):
    return _lift_addx(2, insn, addr, il)

def _lift_ADDX8(insn, addr, il):
    return _lift_addx(3, insn, addr, il)

def _lift_SUBX2(insn, addr, il):
    return _lift_subx(1, insn, addr, il)

def _lift_SUBX4(insn, addr, il):
    return _lift_subx(2, insn, addr, il)

def _lift_SUBX8(insn, addr, il):
    return _lift_subx(3, insn, addr, il)

def _lift_SRLI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.logical_shift_right(4,
                                          il.reg(4, _reg_name(insn, "at")),
                                          il.const(4, insn.s))))
    return insn.length

def _lift_ADDMI(insn, addr, il):
    constant = sign_extend(insn.imm8, 8) << 8
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.const(4, constant))))
    return insn.length

def _lift_MULL(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.reg(4, _reg_name(insn, "as")),
                           il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_NEG(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.neg_expr(4, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_SYSCALL(insn, addr, il):
    il.append(il.system_call())
    return insn.length

def _lift_MOVEQZ(insn, addr, il):
    cond = il.compare_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVNEZ(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVGEZ(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVLTZ(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_SSL(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         il.sub(1,
                                il.const(1, 32),
                                il.low_part(1, il.reg(4, _reg_name(insn, "as")))
                                )))
    return insn.length

def _lift_SSR(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         il.low_part(1, il.reg(4, _reg_name(insn, "as")))))
    return insn.length

def _lift_SSAI(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         il.const(1, insn.inline0(addr))))
    return insn.length

def _lift_SLL(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.shift_left(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.reg(1, "sar"))))
    return insn.length

def _lift_SRL(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.logical_shift_right(4,
                                                il.reg(4, _reg_name(insn, "at")),
                                                il.reg(1, "sar"))))
    return insn.length

def _lift_SRC(insn, addr, il):
    operand = il.reg_split(8,
                           _reg_name(insn, "as"),
                           _reg_name(insn, "at"))
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.low_part(4,
                                     il.logical_shift_right(8,
                                                            operand,
                                                            il.reg(1, "sar"))
                                     )))
    return insn.length

def _lift_SSA8L(insn, addr, il):
    # SAR <- (AR[s] & 0b11) << 3  (byte-shift amount for little-endian)
    il.append(il.set_reg(1, "sar",
                         il.shift_left(1,
                                       il.and_expr(1,
                                           il.low_part(1, il.reg(4, _reg_name(insn, "as"))),
                                           il.const(1, 3)),
                                       il.const(1, 3))))
    return insn.length

def _lift_SSA8B(insn, addr, il):
    # SAR <- 32 - ((AR[s] & 0b11) << 3)  (big-endian variant)
    il.append(il.set_reg(1, "sar",
                         il.sub(1,
                                il.const(1, 32),
                                il.shift_left(1,
                                    il.and_expr(1,
                                        il.low_part(1, il.reg(4, _reg_name(insn, "as"))),
                                        il.const(1, 3)),
                                    il.const(1, 3)))))
    return insn.length

def _lift_SRA(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.arith_shift_right(4,
                                              il.reg(4, _reg_name(insn, "at")),
                                              il.reg(1, "sar"))))
    return insn.length

def _lift_ISYNC(insn, addr, il):
    il.append(
        il.intrinsic([], "isync", [])
    )
    return insn.length

def _lift_ILL(insn, addr, il):
    # TODO: pick a proper trap constant
    il.append(il.trap(0))
    return insn.length

def _lift_MUL16S(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.sign_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "as")))),
                           il.sign_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "at"))))
                           )))
    return insn.length

def _lift_MUL16U(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.zero_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "as")))),
                           il.zero_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "at"))))
                           )))
    return insn.length

def _lift_NOP(insn, addr, il):
    il.append(il.nop())
    return insn.length

_lift_NOP_N = _lift_NOP


# =====================================================================
# Windowed-register ABI (ESP32)
#
# A CALLn rotates the register window by n, so the caller stages the callee's
# a2..a7 arguments in its own a(n+2)..a15 (ISA-RM 8.1.4) and reads a return value
# back from a(n+2)/a(n+3) (8.1.5). The window rotation itself is not
# representable in flat LLIL, so instead we normalize every call width into a
# synthetic argument channel (wa0..wa5) at the call site and map it back to
# a2..a7 at the callee's ENTRY; returns travel the wr0/wr1 channel. The windowed
# calling convention (see __init__.py) names these synthetic registers so Binary
# Ninja recovers the arguments/returns from ordinary dataflow. The width->register
# arithmetic lives in windowed_abi.py (pure, unit-tested).
# =====================================================================
def _emit_windowed_arg_channel(insn, il):
    """Normalize this CALLn/CALLXn width's outgoing arguments into the synthetic
    wa0..wa5 channel; return the window increment n. Slots with no backing caller
    register at this width (only CALL12) are set undefined so a later, narrower
    call cannot inherit a wider call's stale argument."""
    n = WINDOWED_CALL_INCR[insn.mnem]
    for slot, src in enumerate(windowed_arg_srcs(n)):
        if src is None:
            il.append(il.set_reg(4, "wa%d" % slot, il.undefined()))
        else:
            il.append(il.set_reg(4, "wa%d" % slot, il.reg(4, src)))
    return n


def _emit_windowed_return_map(n, il):
    """Map the synthetic return channel back into the caller's physical return
    registers a(n+2)/a(n+3), both inside the window CALLn clobbers."""
    lo, hi = windowed_return_dsts(n)
    il.append(il.set_reg(4, lo, il.reg(4, "wr0")))
    il.append(il.set_reg(4, hi, il.reg(4, "wr1")))


def _lift_call_const(insn, addr, il):
    n = _emit_windowed_arg_channel(insn, il)
    il.append(il.call(il.const(4, insn.target_offset(addr))))
    _emit_windowed_return_map(n, il)
    return insn.length

_lift_CALL4 = _lift_CALL8 = _lift_CALL12 = _lift_call_const

def _lift_callx_windowed(insn, addr, il):
    n = _emit_windowed_arg_channel(insn, il)
    il.append(il.call(il.reg(4, _reg_name(insn, "as"))))
    _emit_windowed_return_map(n, il)
    return insn.length

_lift_CALLX4 = _lift_CALLX8 = _lift_CALLX12 = _lift_callx_windowed

def _lift_ENTRY(insn, addr, il):
    # Allocate the stack frame: AR[s] (the SP, normally a1) -= imm12 << 3.
    sp = _reg_name(insn, "as")
    il.append(il.set_reg(4, sp,
                         il.sub(4, il.reg(4, sp), il.const(4, insn.inline0(addr)))))
    # Receive the incoming windowed arguments: the callee reads them as a2..a7,
    # which the caller staged into the synthetic wa0..wa5 channel before CALLn
    # (see _emit_windowed_arg_channel).
    for slot in range(NUM_ARG_SLOTS):
        il.append(il.set_reg(4, "a%d" % (slot + 2), il.reg(4, "wa%d" % slot)))
    return insn.length

def _lift_RETW(insn, addr, il):
    # Publish the return value (callee a2/a3) into the synthetic return channel
    # so the caller's _emit_windowed_return_map reads it back as a(n+2)/a(n+3).
    il.append(il.set_reg(4, "wr0", il.reg(4, "a2")))
    il.append(il.set_reg(4, "wr1", il.reg(4, "a3")))
    # Return PC = PC[31:30] || a0[29:0]; a0[31:30] holds the window-increment n,
    # not address bits, so mask it off and substitute the current PC's region.
    target = il.or_expr(4,
                        il.const(4, addr & 0xc0000000),
                        il.and_expr(4, il.reg(4, "a0"), il.const(4, 0x3fffffff)))
    il.append(il.ret(target))
    return insn.length

_lift_RETW_N = _lift_RETW

def _lift_MOVSP(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.reg(4, _reg_name(insn, "as"))))
    return insn.length

def _lift_ROTW(insn, addr, il):
    # WindowBase rotation has no representable effect in the logical model.
    il.append(il.nop())
    return insn.length

def _lift_RFWO(insn, addr, il):
    il.append(il.ret(il.reg(4, "a0")))
    return insn.length

_lift_RFWU = _lift_RFWO

def _lift_L32E(insn, addr, il):
    off = (insn.r << 2) - 64   # (1^26 || r || 0^2): -64..-4
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, off))
    il.append(il.set_reg(4, _reg_name(insn, "at"), il.load(4, va)))
    return insn.length

def _lift_S32E(insn, addr, il):
    off = (insn.r << 2) - 64
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, off))
    il.append(il.store(4, va, il.reg(4, _reg_name(insn, "at"))))
    return insn.length


# =====================================================================
# Additional integer ALU / multiply / divide
# =====================================================================
def _lift_MULUH(insn, addr, il):
    # High 32 bits of the unsigned 32x32 product
    prod = il.mult(8,
                   il.zero_extend(8, il.reg(4, _reg_name(insn, "as"))),
                   il.zero_extend(8, il.reg(4, _reg_name(insn, "at"))))
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.low_part(4, il.logical_shift_right(8, prod, il.const(1, 32)))))
    return insn.length

def _lift_MULSH(insn, addr, il):
    # High 32 bits of the signed 32x32 product
    prod = il.mult(8,
                   il.sign_extend(8, il.reg(4, _reg_name(insn, "as"))),
                   il.sign_extend(8, il.reg(4, _reg_name(insn, "at"))))
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.low_part(4, il.logical_shift_right(8, prod, il.const(1, 32)))))
    return insn.length

def _lift_QUOU(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.div_unsigned(4, il.reg(4, _reg_name(insn, "as")),
                                         il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_QUOS(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.div_signed(4, il.reg(4, _reg_name(insn, "as")),
                                       il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_REMU(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.mod_unsigned(4, il.reg(4, _reg_name(insn, "as")),
                                         il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_REMS(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.mod_signed(4, il.reg(4, _reg_name(insn, "as")),
                                       il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_select_ar(insn, addr, il, cond, true_fmt="as", false_fmt="at"):
    """ar = cond ? AR[true_fmt] : AR[false_fmt], with explicit control flow."""
    ar = _reg_name(insn, "ar")
    t = LowLevelILLabel()
    f = LowLevelILLabel()
    done = LowLevelILLabel()
    il.append(il.if_expr(cond, t, f))
    il.mark_label(t)
    il.append(il.set_reg(4, ar, il.reg(4, _reg_name(insn, true_fmt))))
    il.append(il.goto(done))
    il.mark_label(f)
    il.append(il.set_reg(4, ar, il.reg(4, _reg_name(insn, false_fmt))))
    il.append(il.goto(done))
    il.mark_label(done)
    return insn.length

def _lift_MIN(insn, addr, il):
    cond = il.compare_signed_less_than(4, il.reg(4, _reg_name(insn, "as")),
                                       il.reg(4, _reg_name(insn, "at")))
    return _lift_select_ar(insn, addr, il, cond)

def _lift_MAX(insn, addr, il):
    cond = il.compare_signed_greater_than(4, il.reg(4, _reg_name(insn, "as")),
                                          il.reg(4, _reg_name(insn, "at")))
    return _lift_select_ar(insn, addr, il, cond)

def _lift_MINU(insn, addr, il):
    cond = il.compare_unsigned_less_than(4, il.reg(4, _reg_name(insn, "as")),
                                         il.reg(4, _reg_name(insn, "at")))
    return _lift_select_ar(insn, addr, il, cond)

def _lift_MAXU(insn, addr, il):
    cond = il.compare_unsigned_greater_than(4, il.reg(4, _reg_name(insn, "as")),
                                            il.reg(4, _reg_name(insn, "at")))
    return _lift_select_ar(insn, addr, il, cond)

def _lift_ABS(insn, addr, il):
    # ar = (at < 0) ? -at : at
    at = _reg_name(insn, "at")
    ar = _reg_name(insn, "ar")
    cond = il.compare_signed_less_than(4, il.reg(4, at), il.const(4, 0))
    t = LowLevelILLabel()
    f = LowLevelILLabel()
    done = LowLevelILLabel()
    il.append(il.if_expr(cond, t, f))
    il.mark_label(t)
    il.append(il.set_reg(4, ar, il.neg_expr(4, il.reg(4, at))))
    il.append(il.goto(done))
    il.mark_label(f)
    il.append(il.set_reg(4, ar, il.reg(4, at)))
    il.append(il.goto(done))
    il.mark_label(done)
    return insn.length

def _lift_SEXT(insn, addr, il):
    # Sign-extend AR[s] treating bit (t+7) as the sign bit.
    sh = 24 - insn.t
    val = il.reg(4, _reg_name(insn, "as"))
    if sh:
        val = il.arith_shift_right(4,
                                   il.shift_left(4, val, il.const(1, sh)),
                                   il.const(1, sh))
    il.append(il.set_reg(4, _reg_name(insn, "ar"), val))
    return insn.length

def _lift_CLAMPS(insn, addr, il):
    # Clamp AR[s] to the signed range determined by the immediate (t + 7).
    il.append(il.intrinsic([_reg_name(insn, "ar")], "clamps",
                           [il.reg(4, _reg_name(insn, "as")), il.const(4, insn.t + 7)]))
    return insn.length

def _lift_NSA(insn, addr, il):
    il.append(il.intrinsic([_reg_name(insn, "at")], "nsa",
                           [il.reg(4, _reg_name(insn, "as"))]))
    return insn.length

def _lift_NSAU(insn, addr, il):
    il.append(il.intrinsic([_reg_name(insn, "at")], "nsau",
                           [il.reg(4, _reg_name(insn, "as"))]))
    return insn.length

def _lift_MOVT(insn, addr, il):
    cond = il.compare_not_equal(1, il.reg(1, _reg_name(insn, "bt")), il.const(1, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVF(insn, addr, il):
    cond = il.compare_equal(1, il.reg(1, _reg_name(insn, "bt")), il.const(1, 0))
    return _lift_cmov(cond, insn, addr, il)


# =====================================================================
# Additional load/store
# =====================================================================
def _lift_L32AI(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"), il.load(4, va)))
    return insn.length

def _lift_S32RI(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.store(4, va, il.reg(4, _reg_name(insn, "at"))))
    return insn.length

def _lift_S32C1I(insn, addr, il):
    # Atomic compare-and-store. AR[t] is both the store value and the result
    # (the prior memory contents). Modeled as an intrinsic to keep the dataflow.
    va = il.add(4, il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.intrinsic([_reg_name(insn, "at")], "s32c1i",
                           [va, il.reg(4, _reg_name(insn, "at")),
                            il.reg(4, "scompare1")]))
    return insn.length


# =====================================================================
# Boolean option
# =====================================================================
def _lift_ANDB(insn, addr, il):
    il.append(il.set_reg(1, _reg_name(insn, "br"),
                         il.and_expr(1, il.reg(1, _reg_name(insn, "bs")),
                                     il.reg(1, _reg_name(insn, "bt")))))
    return insn.length

def _lift_ANDBC(insn, addr, il):
    il.append(il.set_reg(1, _reg_name(insn, "br"),
                         il.and_expr(1, il.reg(1, _reg_name(insn, "bs")),
                                     il.not_expr(1, il.reg(1, _reg_name(insn, "bt"))))))
    return insn.length

def _lift_ORB(insn, addr, il):
    il.append(il.set_reg(1, _reg_name(insn, "br"),
                         il.or_expr(1, il.reg(1, _reg_name(insn, "bs")),
                                    il.reg(1, _reg_name(insn, "bt")))))
    return insn.length

def _lift_ORBC(insn, addr, il):
    il.append(il.set_reg(1, _reg_name(insn, "br"),
                         il.or_expr(1, il.reg(1, _reg_name(insn, "bs")),
                                    il.not_expr(1, il.reg(1, _reg_name(insn, "bt"))))))
    return insn.length

def _lift_XORB(insn, addr, il):
    il.append(il.set_reg(1, _reg_name(insn, "br"),
                         il.xor_expr(1, il.reg(1, _reg_name(insn, "bs")),
                                     il.reg(1, _reg_name(insn, "bt")))))
    return insn.length

def _lift_BT(insn, addr, il):
    cond = il.compare_not_equal(1, il.reg(1, _reg_name(insn, "bs")), il.const(1, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BF(insn, addr, il):
    cond = il.compare_equal(1, il.reg(1, _reg_name(insn, "bs")), il.const(1, 0))
    return _lift_cond(cond, insn, addr, il)


# =====================================================================
# Floating-point (single precision)
# =====================================================================
def _lift_ADD_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"),
                         il.float_add(4, il.reg(4, _reg_name(insn, "fs")),
                                      il.reg(4, _reg_name(insn, "ft")))))
    return insn.length

def _lift_SUB_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"),
                         il.float_sub(4, il.reg(4, _reg_name(insn, "fs")),
                                      il.reg(4, _reg_name(insn, "ft")))))
    return insn.length

def _lift_MUL_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"),
                         il.float_mult(4, il.reg(4, _reg_name(insn, "fs")),
                                       il.reg(4, _reg_name(insn, "ft")))))
    return insn.length

def _lift_MADD_S(insn, addr, il):
    fr = _reg_name(insn, "fr")
    il.append(il.set_reg(4, fr,
                         il.float_add(4, il.reg(4, fr),
                                      il.float_mult(4, il.reg(4, _reg_name(insn, "fs")),
                                                    il.reg(4, _reg_name(insn, "ft"))))))
    return insn.length

def _lift_MSUB_S(insn, addr, il):
    fr = _reg_name(insn, "fr")
    il.append(il.set_reg(4, fr,
                         il.float_sub(4, il.reg(4, fr),
                                      il.float_mult(4, il.reg(4, _reg_name(insn, "fs")),
                                                    il.reg(4, _reg_name(insn, "ft"))))))
    return insn.length

def _lift_MOV_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"), il.reg(4, _reg_name(insn, "fs"))))
    return insn.length

def _lift_NEG_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"),
                         il.float_neg(4, il.reg(4, _reg_name(insn, "fs")))))
    return insn.length

def _lift_ABS_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"),
                         il.float_abs(4, il.reg(4, _reg_name(insn, "fs")))))
    return insn.length

def _lift_RFR(insn, addr, il):
    # Move the bit pattern of FR[s] into AR[r]
    il.append(il.set_reg(4, _reg_name(insn, "ar"), il.reg(4, _reg_name(insn, "fs"))))
    return insn.length

def _lift_WFR(insn, addr, il):
    # Move the bit pattern of AR[s] into FR[r]
    il.append(il.set_reg(4, _reg_name(insn, "fr"), il.reg(4, _reg_name(insn, "as"))))
    return insn.length

def _fp_cmp(insn, il, base_cmp, unordered=False):
    fs = il.reg(4, _reg_name(insn, "fs"))
    ft = il.reg(4, _reg_name(insn, "ft"))
    cmp = base_cmp(4, fs, ft)
    if unordered:
        cmp = il.or_expr(1, il.bool_to_int(1, cmp),
                         il.bool_to_int(1, il.float_compare_unordered(4,
                             il.reg(4, _reg_name(insn, "fs")),
                             il.reg(4, _reg_name(insn, "ft")))))
        il.append(il.set_reg(1, _reg_name(insn, "br"), cmp))
    else:
        il.append(il.set_reg(1, _reg_name(insn, "br"), il.bool_to_int(1, cmp)))
    return insn.length

def _lift_OEQ_S(insn, addr, il):
    return _fp_cmp(insn, il, il.float_compare_equal)

def _lift_OLT_S(insn, addr, il):
    return _fp_cmp(insn, il, il.float_compare_less_than)

def _lift_OLE_S(insn, addr, il):
    return _fp_cmp(insn, il, il.float_compare_less_equal)

def _lift_UEQ_S(insn, addr, il):
    return _fp_cmp(insn, il, il.float_compare_equal, unordered=True)

def _lift_ULT_S(insn, addr, il):
    return _fp_cmp(insn, il, il.float_compare_less_than, unordered=True)

def _lift_ULE_S(insn, addr, il):
    return _fp_cmp(insn, il, il.float_compare_less_equal, unordered=True)

def _lift_UN_S(insn, addr, il):
    il.append(il.set_reg(1, _reg_name(insn, "br"),
                         il.bool_to_int(1, il.float_compare_unordered(4,
                             il.reg(4, _reg_name(insn, "fs")),
                             il.reg(4, _reg_name(insn, "ft"))))))
    return insn.length

def _lift_TRUNC_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.float_to_int(4, il.reg(4, _reg_name(insn, "fs")))))
    return insn.length

# ROUND/FLOOR/CEIL modeled as truncating (signed) float->int -- the exact
# rounding mode and the 2^t scale immediate are approximated; t is almost always
# 0 in practice.
_lift_ROUND_S = _lift_FLOOR_S = _lift_CEIL_S = _lift_TRUNC_S

def _lift_UTRUNC_S(insn, addr, il):
    # Unsigned truncation: convert to a wide signed int then take the low 32 bits
    # so values in [2^31, 2^32) keep the correct unsigned bit pattern.
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.low_part(4, il.float_to_int(8, il.reg(4, _reg_name(insn, "fs"))))))
    return insn.length

def _lift_FLOAT_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"),
                         il.int_to_float(4, il.reg(4, _reg_name(insn, "as")))))
    return insn.length

def _lift_UFLOAT_S(insn, addr, il):
    # Unsigned source: zero-extend to a wider int so bit 31 isn't read as sign.
    il.append(il.set_reg(4, _reg_name(insn, "fr"),
                         il.int_to_float(4, il.zero_extend(8, il.reg(4, _reg_name(insn, "as"))))))
    return insn.length

def _lift_fcmov(cond, insn, addr, il):
    """fr = cond ? fs : fr (conditional float move)."""
    fr = _reg_name(insn, "fr")
    t = LowLevelILLabel()
    done = LowLevelILLabel()
    il.append(il.if_expr(cond, t, done))
    il.mark_label(t)
    il.append(il.set_reg(4, fr, il.reg(4, _reg_name(insn, "fs"))))
    il.append(il.goto(done))
    il.mark_label(done)
    return insn.length

def _lift_MOVEQZ_S(insn, addr, il):
    return _lift_fcmov(il.compare_equal(4, il.reg(4, _reg_name(insn, "at")),
                                        il.const(4, 0)), insn, addr, il)

def _lift_MOVNEZ_S(insn, addr, il):
    return _lift_fcmov(il.compare_not_equal(4, il.reg(4, _reg_name(insn, "at")),
                                            il.const(4, 0)), insn, addr, il)

def _lift_MOVLTZ_S(insn, addr, il):
    return _lift_fcmov(il.compare_signed_less_than(4, il.reg(4, _reg_name(insn, "at")),
                                                   il.const(4, 0)), insn, addr, il)

def _lift_MOVGEZ_S(insn, addr, il):
    return _lift_fcmov(il.compare_signed_greater_equal(4, il.reg(4, _reg_name(insn, "at")),
                                                       il.const(4, 0)), insn, addr, il)

def _lift_MOVF_S(insn, addr, il):
    return _lift_fcmov(il.compare_equal(1, il.reg(1, _reg_name(insn, "bt")),
                                        il.const(1, 0)), insn, addr, il)

def _lift_MOVT_S(insn, addr, il):
    return _lift_fcmov(il.compare_not_equal(1, il.reg(1, _reg_name(insn, "bt")),
                                            il.const(1, 0)), insn, addr, il)


# =====================================================================
# Special / user registers and synchronization
# =====================================================================
def _sr_size(name):
    return 1 if name == "sar" else 4

def _sr_reg(insn):
    """Lowercased register name for this insn's special register, or None.

    Only the SR numbers in ``Instruction._special_reg_map`` are registered as
    real registers by ``_build_regs`` in __init__.py. An undocumented/reserved
    SR number (``get_sr_name`` returns the bare decimal, matching objdump) has
    no register, so it must NOT be passed to ``il.reg``/``il.set_reg`` -- the
    caller emits an intrinsic instead. This routinely happens when Binary Ninja
    sweeps data/padding that happens to decode as a valid RSR/WSR/XSR.
    """
    name = Instruction._special_reg_map.get(insn.sr)
    return name.lower() if name is not None else None

def _lift_RSR(insn, addr, il):
    at = _reg_name(insn, "at")
    sr = _sr_reg(insn)
    if sr is None:
        il.append(il.intrinsic([at], "rsr", [il.const(4, insn.sr)]))
        return insn.length
    sz = _sr_size(sr)
    src = il.reg(sz, sr)
    if sz != 4:
        src = il.zero_extend(4, src)
    il.append(il.set_reg(4, at, src))
    return insn.length

def _lift_WSR(insn, addr, il):
    at = _reg_name(insn, "at")
    sr = _sr_reg(insn)
    val = il.reg(4, at)
    if sr is None:
        il.append(il.intrinsic([], "wsr", [val, il.const(4, insn.sr)]))
        return insn.length
    sz = _sr_size(sr)
    if sz != 4:
        val = il.low_part(sz, val)
    il.append(il.set_reg(sz, sr, val))
    return insn.length

def _lift_XSR(insn, addr, il):
    # Swap AR[t] and the special register
    at = _reg_name(insn, "at")
    sr = _sr_reg(insn)
    if sr is None:
        # Reserved SR: opaque swap. Model AR[t] as clobbered by an intrinsic
        # fed the old AR[t] + the SR selector; there is no register to write.
        il.append(il.intrinsic([at], "xsr",
                               [il.reg(4, at), il.const(4, insn.sr)]))
        return insn.length
    sz = _sr_size(sr)
    tmp = il.reg(4, at)
    sr_val = il.reg(sz, sr) if sz == 4 else il.zero_extend(4, il.reg(sz, sr))
    il.append(il.set_reg(4, at, sr_val))
    if sz == 4:
        il.append(il.set_reg(4, sr, tmp))
    else:
        il.append(il.set_reg(sz, sr, il.low_part(sz, tmp)))
    return insn.length

def _lift_RUR(insn, addr, il):
    if insn.get_ur_index() == 231:   # THREADPTR
        il.append(il.set_reg(4, _reg_name(insn, "ar"), il.reg(4, "threadptr")))
    else:
        il.append(il.intrinsic([_reg_name(insn, "ar")], "rur", []))
    return insn.length

def _lift_WUR(insn, addr, il):
    if insn.get_ur_index() == 231:   # THREADPTR
        il.append(il.set_reg(4, "threadptr", il.reg(4, _reg_name(insn, "at"))))
    else:
        il.append(il.intrinsic([], "wur", [il.reg(4, _reg_name(insn, "at"))]))
    return insn.length

def _intrinsic_only(name):
    def inner(insn, addr, il):
        il.append(il.intrinsic([], name, []))
        return insn.length
    return inner

_lift_DSYNC = _intrinsic_only("dsync")
_lift_ESYNC = _intrinsic_only("esync")
_lift_RSYNC = _intrinsic_only("rsync")
_lift_EXTW = _intrinsic_only("extw")
_lift_EXCW = _intrinsic_only("excw")

def _lift_WAITI(insn, addr, il):
    il.append(il.intrinsic([], "waiti", [il.const(4, insn.s)]))
    return insn.length

def _lift_RSIL(insn, addr, il):
    il.append(il.intrinsic([_reg_name(insn, "at")], "rsil", [il.const(4, insn.s)]))
    return insn.length

def _lift_BREAK(insn, addr, il):
    il.append(il.breakpoint())
    return insn.length

_lift_BREAK_N = _lift_BREAK

def _lift_RFE(insn, addr, il):
    il.append(il.ret(il.reg(4, "epc1")))
    return insn.length

def _lift_RFI(insn, addr, il):
    il.append(il.ret(il.reg(4, "a0")))
    return insn.length

_lift_RFUI = _lift_RFDE = _lift_RFME = _lift_RFI
_lift_ILL_N = _lift_ILL


# =====================================================================
# Floating-point load/store (coprocessor). Immediate offset is imm8<<2; the
# "U" (update) forms write the effective address back to AR[s].
# =====================================================================
def _lift_LSI(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, insn.imm8 << 2))
    il.append(il.set_reg(4, _reg_name(insn, "ft"), il.load(4, va)))
    return insn.length

def _lift_LSIU(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, insn.imm8 << 2))
    il.append(il.set_reg(4, _reg_name(insn, "ft"), il.load(4, va)))
    il.append(il.set_reg(4, _reg_name(insn, "as"), va))
    return insn.length

def _lift_SSI(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, insn.imm8 << 2))
    il.append(il.store(4, va, il.reg(4, _reg_name(insn, "ft"))))
    return insn.length

def _lift_SSIU(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, insn.imm8 << 2))
    il.append(il.store(4, va, il.reg(4, _reg_name(insn, "ft"))))
    il.append(il.set_reg(4, _reg_name(insn, "as"), va))
    return insn.length

def _lift_LSX(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")))
    il.append(il.set_reg(4, _reg_name(insn, "fr"), il.load(4, va)))
    return insn.length

def _lift_LSXU(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")))
    il.append(il.set_reg(4, _reg_name(insn, "fr"), il.load(4, va)))
    il.append(il.set_reg(4, _reg_name(insn, "as"), va))
    return insn.length

def _lift_SSX(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")))
    il.append(il.store(4, va, il.reg(4, _reg_name(insn, "fr"))))
    return insn.length

def _lift_SSXU(insn, addr, il):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")))
    il.append(il.store(4, va, il.reg(4, _reg_name(insn, "fr"))))
    il.append(il.set_reg(4, _reg_name(insn, "as"), va))
    return insn.length


# =====================================================================
# External register access (privileged)
# =====================================================================
def _lift_RER(insn, addr, il):
    il.append(il.intrinsic([_reg_name(insn, "at")], "rer",
                           [il.reg(4, _reg_name(insn, "as"))]))
    return insn.length

def _lift_WER(insn, addr, il):
    il.append(il.intrinsic([], "wer",
                           [il.reg(4, _reg_name(insn, "as")),
                            il.reg(4, _reg_name(insn, "at"))]))
    return insn.length


# =====================================================================
# Privileged MMU/cache ops: no register dataflow that matters for app-level
# decompilation. Cache prefetch/writeback/invalidate -> nop; TLB and
# instruction-cache-test ops -> opaque intrinsics; boolean reductions -> opaque.
# All of these still disassemble with correct operands.
# =====================================================================
def _nop_lift(insn, addr, il):
    il.append(il.nop())
    return insn.length

# Data-cache and prefetch hints (RRI8 and RRI4 forms)
_lift_DPFR = _lift_DPFW = _lift_DPFRO = _lift_DPFWO = _nop_lift
_lift_DHWB = _lift_DHWBI = _lift_DHI = _lift_DII = _nop_lift
_lift_IPF = _lift_IHI = _lift_III = _nop_lift
_lift_DPFL = _lift_DHU = _lift_DIU = _lift_DIWB = _lift_DIWBI = _nop_lift
_lift_IPFL = _lift_IHU = _lift_IIU = _nop_lift

def _tlb_lift(insn, addr, il):
    il.append(il.intrinsic([], "tlb", [il.reg(4, _reg_name(insn, "as"))]))
    return insn.length

_lift_RITLB0 = _lift_RITLB1 = _lift_IITLB = _lift_PITLB = _lift_WITLB = _tlb_lift
_lift_RDTLB0 = _lift_RDTLB1 = _lift_IDTLB = _lift_PDTLB = _lift_WDTLB = _tlb_lift

def _icache_lift(insn, addr, il):
    il.append(il.intrinsic([], "icache", []))
    return insn.length

_lift_LICT = _lift_SICT = _lift_LICW = _lift_SICW = _icache_lift
_lift_LDCT = _lift_SDCT = _icache_lift

def _bcombine_lift(insn, addr, il):
    il.append(il.intrinsic([_reg_name(insn, "bt")], "bcombine",
                           [il.reg(1, _reg_name(insn, "bs"))]))
    return insn.length

_lift_ANY4 = _lift_ALL4 = _lift_ANY8 = _lift_ALL8 = _bcombine_lift


# =====================================================================
# Zero-overhead loop. The hardware back-edge at LEND is not representable in
# flat LLIL; we model the conditional skip (LOOPNEZ/LOOPGTZ) and record the loop
# count so dataflow sees it. LOOP always enters (no skip).
# =====================================================================
def _lift_LOOP(insn, addr, il):
    il.append(il.set_reg(4, "lcount",
                         il.sub(4, il.reg(4, _reg_name(insn, "as")), il.const(4, 1))))
    return insn.length

def _lift_LOOPNEZ(insn, addr, il):
    il.append(il.set_reg(4, "lcount",
                         il.sub(4, il.reg(4, _reg_name(insn, "as")), il.const(4, 1))))
    # Skip the loop body if AR[s] == 0
    cond = il.compare_equal(4, il.reg(4, _reg_name(insn, "as")), il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_LOOPGTZ(insn, addr, il):
    il.append(il.set_reg(4, "lcount",
                         il.sub(4, il.reg(4, _reg_name(insn, "as")), il.const(4, 1))))
    # Skip the loop body if AR[s] <= 0
    cond = il.compare_signed_less_equal(4, il.reg(4, _reg_name(insn, "as")),
                                        il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)


# =====================================================================
# MAC16 multiply/accumulate (dispatched from lift() via insn.mac16_kind).
# acc is the 40-bit accumulator (modeled as 8 bytes). The 40-bit truncation is
# not modeled, but the dataflow (which registers feed the accumulator) is.
# =====================================================================
def _mac16_half(il, reg_expr, high, signed):
    if high:
        h = il.low_part(2, il.logical_shift_right(4, reg_expr, il.const(1, 16)))
    else:
        h = il.low_part(2, reg_expr)
    return il.sign_extend(8, h) if signed else il.zero_extend(8, h)

def _lift_mac16(insn, addr, il):
    kind = insn.mac16_kind

    # Plain loads (LDINC / LDDEC): mw <- mem[as]; as +/-= 4
    if kind == "l":
        mw = "m" + str(insn.mac16_mw())
        as_name = _reg_name(insn, "as")
        il.append(il.set_reg(4, mw, il.load(4, il.reg(4, as_name))))
        delta = 4 if insn.mac16_ld == "ldinc" else -4
        il.append(il.set_reg(4, as_name,
                             il.add(4, il.reg(4, as_name), il.const(4, delta))))
        return insn.length

    signed = (insn.mac16_op != "umul")
    hi_x = insn.mac16_half in (1, 3)   # first letter of LL/HL/LH/HH selects x half
    hi_y = insn.mac16_half in (2, 3)   # second letter selects y half

    # Resolve x and y source register expressions per operand kind.
    base = kind[3:] if kind.startswith("al_") else kind
    if base == "aa":
        x = il.reg(4, _reg_name(insn, "as")); y = il.reg(4, _reg_name(insn, "at"))
    elif base == "ad":
        x = il.reg(4, _reg_name(insn, "as")); y = il.reg(4, "m" + str(insn.mac16_my()))
    elif base == "da":
        x = il.reg(4, "m" + str(insn.mac16_mx())); y = il.reg(4, _reg_name(insn, "at"))
    else:  # dd
        x = il.reg(4, "m" + str(insn.mac16_mx())); y = il.reg(4, "m" + str(insn.mac16_my()))

    prod = il.mult(8, _mac16_half(il, x, hi_x, signed),
                   _mac16_half(il, y, hi_y, signed))

    if insn.mac16_op in ("mul", "umul"):
        il.append(il.set_reg(8, "acc", prod))
    elif insn.mac16_op == "mula":
        il.append(il.set_reg(8, "acc", il.add(8, il.reg(8, "acc"), prod)))
    else:  # muls
        il.append(il.set_reg(8, "acc", il.sub(8, il.reg(8, "acc"), prod)))

    # Combined auto-load forms also load mw and bump the pointer.
    if kind.startswith("al_"):
        mw = "m" + str(insn.mac16_mw())
        as_name = _reg_name(insn, "as")
        il.append(il.set_reg(4, mw, il.load(4, il.reg(4, as_name))))
        delta = 4 if insn.mac16_ld == "ldinc" else -4
        il.append(il.set_reg(4, as_name,
                             il.add(4, il.reg(4, as_name), il.const(4, delta))))
    return insn.length
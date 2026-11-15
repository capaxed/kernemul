#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>

typedef std::uint64_t ZyanU64;
typedef std::uint32_t ZyanStatus;

#define ZYAN_STATUS_SUCCESS 0u
#define ZYAN_STATUS_FAILED  0x80000000u
#define ZYAN_SUCCESS(st) (((st) & 0x80000000u) == 0u)
#define ZYAN_FAILED(st)  (((st) & 0x80000000u) != 0u)

#define ZYDIS_MAX_OPERAND_COUNT 10

enum ZydisRegister : std::uint16_t
{
    ZYDIS_REGISTER_NONE = 0,
    // 8-bit low
    ZYDIS_REGISTER_AL, ZYDIS_REGISTER_CL, ZYDIS_REGISTER_DL, ZYDIS_REGISTER_BL,
    ZYDIS_REGISTER_SPL, ZYDIS_REGISTER_BPL, ZYDIS_REGISTER_SIL, ZYDIS_REGISTER_DIL,
    ZYDIS_REGISTER_R8B, ZYDIS_REGISTER_R9B, ZYDIS_REGISTER_R10B, ZYDIS_REGISTER_R11B,
    ZYDIS_REGISTER_R12B, ZYDIS_REGISTER_R13B, ZYDIS_REGISTER_R14B, ZYDIS_REGISTER_R15B,
    // 8-bit high
    ZYDIS_REGISTER_AH, ZYDIS_REGISTER_CH, ZYDIS_REGISTER_DH, ZYDIS_REGISTER_BH,
    // 16-bit
    ZYDIS_REGISTER_AX, ZYDIS_REGISTER_CX, ZYDIS_REGISTER_DX, ZYDIS_REGISTER_BX,
    ZYDIS_REGISTER_SP, ZYDIS_REGISTER_BP, ZYDIS_REGISTER_SI, ZYDIS_REGISTER_DI,
    ZYDIS_REGISTER_R8W, ZYDIS_REGISTER_R9W, ZYDIS_REGISTER_R10W, ZYDIS_REGISTER_R11W,
    ZYDIS_REGISTER_R12W, ZYDIS_REGISTER_R13W, ZYDIS_REGISTER_R14W, ZYDIS_REGISTER_R15W,
    // 32-bit
    ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_ECX, ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_EBX,
    ZYDIS_REGISTER_ESP, ZYDIS_REGISTER_EBP, ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_EDI,
    ZYDIS_REGISTER_R8D, ZYDIS_REGISTER_R9D, ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R11D,
    ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R13D, ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R15D,
    // 64-bit
    ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RBX,
    ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
    ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11,
    ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15,
    // IP & flags
    ZYDIS_REGISTER_IP, ZYDIS_REGISTER_EIP, ZYDIS_REGISTER_RIP,
    ZYDIS_REGISTER_RFLAGS,
    // Segments
    ZYDIS_REGISTER_ES, ZYDIS_REGISTER_CS, ZYDIS_REGISTER_SS,
    ZYDIS_REGISTER_DS, ZYDIS_REGISTER_FS, ZYDIS_REGISTER_GS,
    ZYDIS_REGISTER_MAX_VALUE
};

enum ZydisMachineMode : std::uint8_t
{
    ZYDIS_MACHINE_MODE_LONG_64 = 0,
    ZYDIS_MACHINE_MODE_LEGACY_32 = 1,
    ZYDIS_MACHINE_MODE_REAL_16 = 2
};

enum ZydisStackWidth : std::uint8_t
{
    ZYDIS_STACK_WIDTH_64 = 0,
    ZYDIS_STACK_WIDTH_32 = 1,
    ZYDIS_STACK_WIDTH_16 = 2
};

enum ZydisOperandType : std::uint8_t
{
    ZYDIS_OPERAND_TYPE_UNUSED = 0,
    ZYDIS_OPERAND_TYPE_REGISTER,
    ZYDIS_OPERAND_TYPE_MEMORY,
    ZYDIS_OPERAND_TYPE_POINTER,
    ZYDIS_OPERAND_TYPE_IMMEDIATE
};

enum ZydisInstructionCategory : std::uint8_t
{
    ZYDIS_CATEGORY_MISC = 0,
    ZYDIS_CATEGORY_COND_BR,
    ZYDIS_CATEGORY_UNCOND_BR,
    ZYDIS_CATEGORY_CALL,
    ZYDIS_CATEGORY_RET,
    ZYDIS_CATEGORY_INTERRUPT,
    ZYDIS_CATEGORY_SYSCALL
};

struct ZydisDecodedOperand
{
    ZydisOperandType type = ZYDIS_OPERAND_TYPE_UNUSED;
    struct {
        ZydisRegister value = ZYDIS_REGISTER_NONE;
    } reg;
    struct {
        ZydisRegister segment = ZYDIS_REGISTER_NONE;
        ZydisRegister base = ZYDIS_REGISTER_NONE;
        ZydisRegister index = ZYDIS_REGISTER_NONE;
        std::uint8_t scale = 0;
        struct {
            bool has_displacement = false;
            std::int64_t value = 0;
        } disp;
    } mem;
    struct {
        bool is_signed = false;
        bool is_relative = false;
        union {
            std::uint64_t u = 0;
            std::int64_t s;
        } value;
    } imm;
};

struct ZydisDecodedInstruction
{
    std::uint8_t length = 0;
    std::uint8_t operand_count = 0;
    std::uint8_t operand_count_visible = 0;
    struct {
        ZydisInstructionCategory category = ZYDIS_CATEGORY_MISC;
    } meta;
};

struct ZydisDecoder
{
    ZydisMachineMode mode = ZYDIS_MACHINE_MODE_LONG_64;
    ZydisStackWidth stack_width = ZYDIS_STACK_WIDTH_64;
};

struct ZydisDecoderContext
{
    std::uint8_t dummy = 0;
};

struct ZydisRegisterContext
{
    std::uint64_t values[ZYDIS_REGISTER_MAX_VALUE] = {};
};

inline constexpr ZydisRegister ZydisRegisterGetLargestEnclosing(ZydisMachineMode, ZydisRegister reg) noexcept
{
    if (reg >= ZYDIS_REGISTER_AL && reg <= ZYDIS_REGISTER_R15B)
        return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + (reg - ZYDIS_REGISTER_AL));
    if (reg >= ZYDIS_REGISTER_AH && reg <= ZYDIS_REGISTER_BH)
        return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + (reg - ZYDIS_REGISTER_AH));
    if (reg >= ZYDIS_REGISTER_AX && reg <= ZYDIS_REGISTER_R15W)
        return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + (reg - ZYDIS_REGISTER_AX));
    if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D)
        return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + (reg - ZYDIS_REGISTER_EAX));
    if (reg == ZYDIS_REGISTER_IP || reg == ZYDIS_REGISTER_EIP)
        return ZYDIS_REGISTER_RIP;
    return reg;
}

inline ZyanStatus ZydisDecoderInit(ZydisDecoder* decoder, ZydisMachineMode mode, ZydisStackWidth stack_width) noexcept
{
    if (!decoder) return ZYAN_STATUS_FAILED;
    decoder->mode = mode;
    decoder->stack_width = stack_width;
    return ZYAN_STATUS_SUCCESS;
}

extern "C" unsigned int hde64_disasm(const void* code, void* hs);

#pragma pack(push, 1)
struct zydis_hde64s {
    std::uint8_t len;
    std::uint8_t p_rep;
    std::uint8_t p_lock;
    std::uint8_t p_seg;
    std::uint8_t p_66;
    std::uint8_t p_67;
    std::uint8_t rex;
    std::uint8_t rex_w;
    std::uint8_t rex_r;
    std::uint8_t rex_x;
    std::uint8_t rex_b;
    std::uint8_t opcode;
    std::uint8_t opcode2;
    std::uint8_t modrm;
    std::uint8_t modrm_mod;
    std::uint8_t modrm_reg;
    std::uint8_t modrm_rm;
    std::uint8_t sib;
    std::uint8_t sib_scale;
    std::uint8_t sib_index;
    std::uint8_t sib_base;
    union {
        std::uint8_t imm8;
        std::uint16_t imm16;
        std::uint32_t imm32;
        std::uint64_t imm64;
    } imm;
    union {
        std::uint8_t disp8;
        std::uint16_t disp16;
        std::uint32_t disp32;
    } disp;
    std::uint32_t flags;
};
#pragma pack(pop)

#define Z_F_MODRM   0x00000001u
#define Z_F_SIB     0x00000002u
#define Z_F_DISP8   0x00000040u
#define Z_F_DISP16  0x00000080u
#define Z_F_DISP32  0x00000100u
#define Z_F_ERROR   0x00001000u

inline ZyanStatus ZydisDecoderDecodeFull(
    const ZydisDecoder* decoder,
    const void* buffer,
    std::size_t length,
    ZydisDecodedInstruction* instruction,
    ZydisDecodedOperand* operands) noexcept
{
    if (!decoder || !buffer || length == 0 || !instruction) return ZYAN_STATUS_FAILED;
    zydis_hde64s hs{};
    unsigned int len = hde64_disasm(buffer, &hs);
    if (len == 0 || len > length || (hs.flags & Z_F_ERROR)) return ZYAN_STATUS_FAILED;

    *instruction = ZydisDecodedInstruction{};
    instruction->length = static_cast<std::uint8_t>(len);
    instruction->meta.category = ZYDIS_CATEGORY_MISC;

    const std::uint8_t op = hs.opcode;
    const std::uint8_t op2 = hs.opcode2;
    if (op >= 0x70 && op <= 0x7F) instruction->meta.category = ZYDIS_CATEGORY_COND_BR;
    else if (op == 0x0F && op2 >= 0x80 && op2 <= 0x8F) instruction->meta.category = ZYDIS_CATEGORY_COND_BR;
    else if (op == 0xEB || op == 0xE9 || op == 0xEA) instruction->meta.category = ZYDIS_CATEGORY_UNCOND_BR;
    else if (op == 0xE8 || op == 0x9A) instruction->meta.category = ZYDIS_CATEGORY_CALL;
    else if (op == 0xC2 || op == 0xC3 || op == 0xCA || op == 0xCB) instruction->meta.category = ZYDIS_CATEGORY_RET;
    else if (op == 0xCC || op == 0xCD || op == 0xCE) instruction->meta.category = ZYDIS_CATEGORY_INTERRUPT;
    else if (op == 0x0F && (op2 == 0x05 || op2 == 0x34)) instruction->meta.category = ZYDIS_CATEGORY_SYSCALL;
    else if (op == 0xFF && (hs.flags & Z_F_MODRM))
    {
        if (hs.modrm_reg == 2 || hs.modrm_reg == 3) instruction->meta.category = ZYDIS_CATEGORY_CALL;
        else if (hs.modrm_reg == 4 || hs.modrm_reg == 5) instruction->meta.category = ZYDIS_CATEGORY_UNCOND_BR;
    }

    if (operands)
    {
        for (int i = 0; i < ZYDIS_MAX_OPERAND_COUNT; i++) operands[i] = ZydisDecodedOperand{};
        ZydisRegister seg = ZYDIS_REGISTER_DS;
        if (hs.p_seg == 0x26) seg = ZYDIS_REGISTER_ES;
        else if (hs.p_seg == 0x2E) seg = ZYDIS_REGISTER_CS;
        else if (hs.p_seg == 0x36) seg = ZYDIS_REGISTER_SS;
        else if (hs.p_seg == 0x3E) seg = ZYDIS_REGISTER_DS;
        else if (hs.p_seg == 0x64) seg = ZYDIS_REGISTER_FS;
        else if (hs.p_seg == 0x65) seg = ZYDIS_REGISTER_GS;

        if ((hs.flags & Z_F_MODRM) && hs.modrm_mod != 3)
        {
            ZydisDecodedOperand& mop = operands[0];
            mop.type = ZYDIS_OPERAND_TYPE_MEMORY;
            mop.mem.segment = seg;

            auto gpr64 = [](std::uint8_t idx) -> ZydisRegister {
                return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + (idx & 15));
            };

            if (hs.flags & Z_F_SIB)
            {
                std::uint8_t base_idx = hs.sib_base | (hs.rex_b ? 8 : 0);
                std::uint8_t index_idx = hs.sib_index | (hs.rex_x ? 8 : 0);
                if (hs.modrm_mod == 0 && hs.sib_base == 5)
                    mop.mem.base = ZYDIS_REGISTER_NONE;
                else
                    mop.mem.base = gpr64(base_idx);

                if (index_idx != 4)
                {
                    mop.mem.index = gpr64(index_idx);
                    mop.mem.scale = static_cast<std::uint8_t>(1u << hs.sib_scale);
                }
            }
            else if (hs.modrm_mod == 0 && hs.modrm_rm == 5)
            {
                mop.mem.base = ZYDIS_REGISTER_RIP;
            }
            else
            {
                std::uint8_t rm_idx = hs.modrm_rm | (hs.rex_b ? 8 : 0);
                mop.mem.base = gpr64(rm_idx);
            }

            if (mop.mem.base == ZYDIS_REGISTER_RSP || mop.mem.base == ZYDIS_REGISTER_RBP)
            {
                if (hs.p_seg == 0) mop.mem.segment = ZYDIS_REGISTER_SS;
            }

            if (hs.flags & Z_F_DISP8)
            {
                mop.mem.disp.has_displacement = true;
                mop.mem.disp.value = static_cast<std::int8_t>(hs.disp.disp8);
            }
            else if (hs.flags & Z_F_DISP16)
            {
                mop.mem.disp.has_displacement = true;
                mop.mem.disp.value = static_cast<std::int16_t>(hs.disp.disp16);
            }
            else if (hs.flags & Z_F_DISP32)
            {
                mop.mem.disp.has_displacement = true;
                mop.mem.disp.value = static_cast<std::int32_t>(hs.disp.disp32);
            }

            instruction->operand_count = 1;
            instruction->operand_count_visible = 1;
        }
    }

    return ZYAN_STATUS_SUCCESS;
}

inline ZyanStatus ZydisDecoderDecodeInstruction(
    const ZydisDecoder* decoder,
    ZydisDecoderContext*,
    const void* buffer,
    std::size_t length,
    ZydisDecodedInstruction* instruction) noexcept
{
    return ZydisDecoderDecodeFull(decoder, buffer, length, instruction, nullptr);
}

inline ZyanStatus ZydisCalcAbsoluteAddressEx(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operand,
    ZyanU64 runtime_address,
    const ZydisRegisterContext* register_context,
    ZyanU64* result_address) noexcept
{
    if (!instruction || !operand || !register_context || !result_address) return ZYAN_STATUS_FAILED;
    if (operand->type != ZYDIS_OPERAND_TYPE_MEMORY) return ZYAN_STATUS_FAILED;

    std::uint64_t addr = 0;
    if (operand->mem.base == ZYDIS_REGISTER_RIP)
    {
        addr = runtime_address + instruction->length;
    }
    else if (operand->mem.base != ZYDIS_REGISTER_NONE && operand->mem.base < ZYDIS_REGISTER_MAX_VALUE)
    {
        addr = register_context->values[operand->mem.base];
    }

    if (operand->mem.index != ZYDIS_REGISTER_NONE && operand->mem.index < ZYDIS_REGISTER_MAX_VALUE && operand->mem.scale > 0)
    {
        addr += register_context->values[operand->mem.index] * operand->mem.scale;
    }

    if (operand->mem.disp.has_displacement)
    {
        addr = static_cast<std::uint64_t>(static_cast<std::int64_t>(addr) + operand->mem.disp.value);
    }

    *result_address = addr;
    return ZYAN_STATUS_SUCCESS;
}

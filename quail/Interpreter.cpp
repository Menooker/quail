
#include "Zydis/Zydis.h"
#include "stdio.h"
#include <ucontext.h>

static ZydisDecoder decoder;
static ZydisFormatter formatter;
typedef void* PVOID;

#define INTER_CHECK(status) \
    do \
    { \
        InterStatus status_32432423= status; \
        if (status_32432423!=InterSuccess) \
        { \
            return status_32432423; \
        } \
    } while (0)

enum InterStatus
{
	InterSuccess,
	InterNotImplemented,
	InterDecodeFailed,
};
void InitInterpreter()
{
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);

	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

inline uint64_t GetHigherByte(uint64_t v)
{
	return (v >> 8) & 0xff;
}
#define GETREG(c,v) (c->uc_mcontext.gregs[v])
static InterStatus GetRegisterValue(ZydisRegister reg, ucontext* context, uint64_t & outvalue, uint64_t* & poutvalue)
{
#define SET_OUT(r) (poutvalue=(uint64_t*)&GETREG(context, r))
	if (reg == ZYDIS_REGISTER_NONE)
		return InterDecodeFailed;
	uint64_t mask = 0;
	ZydisRegister decode_index = ZYDIS_REGISTER_NONE;
	if (reg < ZYDIS_REGISTER_AX)
	{
		if (reg < ZYDIS_REGISTER_AH)
		{
			mask = 0xff;
			decode_index = reg - ZYDIS_REGISTER_AL + ZYDIS_REGISTER_AX;
		}
		switch (reg)
		{
		case ZYDIS_REGISTER_AH: SET_OUT(REG_RAX); break;
		case ZYDIS_REGISTER_BH: SET_OUT(REG_RBX); break;
		case ZYDIS_REGISTER_CH: SET_OUT(REG_RCX); break;
		case ZYDIS_REGISTER_DH: SET_OUT(REG_RDX); break;
		default:
			decode_index = reg - ZYDIS_REGISTER_AH + ZYDIS_REGISTER_AX;
		}
		if (decode_index == ZYDIS_REGISTER_NONE)
		{
			outvalue = GetHigherByte(*poutvalue);
			poutvalue = (uint64_t*)((char*)poutvalue + 1);
			return InterSuccess;
		}
	}
	else if (reg < ZYDIS_REGISTER_EAX)
	{
		mask = 0xffff;
		decode_index = reg;
	}
	else if (reg < ZYDIS_REGISTER_RAX)
	{
		mask = 0xffffffff;
		decode_index = reg - ZYDIS_REGISTER_EAX + ZYDIS_REGISTER_AX;
	}
	else if (reg <= ZYDIS_REGISTER_R15)
	{

		mask = 0xffffffffffffffff;
		decode_index = reg - ZYDIS_REGISTER_RAX + ZYDIS_REGISTER_AX;
	}
	else
	{
		return InterNotImplemented;
	}
	switch (decode_index)
	{
	case ZYDIS_REGISTER_AX: SET_OUT(REG_RAX); break;
	case ZYDIS_REGISTER_CX: SET_OUT(REG_RCX); break;
	case ZYDIS_REGISTER_DX: SET_OUT(REG_RDX); break;
	case ZYDIS_REGISTER_BX: SET_OUT(REG_RBX); break;
	case ZYDIS_REGISTER_SP: SET_OUT(REG_RSP); break;
	case ZYDIS_REGISTER_BP: SET_OUT(REG_RBP); break;
	case ZYDIS_REGISTER_SI: SET_OUT(REG_RSI); break;
	case ZYDIS_REGISTER_DI: SET_OUT(REG_RDI); break;
	case ZYDIS_REGISTER_R8W: SET_OUT(REG_R8); break;
	case ZYDIS_REGISTER_R9W: SET_OUT(REG_R9); break;
	case ZYDIS_REGISTER_R10W: SET_OUT(REG_R10); break;
	case ZYDIS_REGISTER_R11W: SET_OUT(REG_R11); break;
	case ZYDIS_REGISTER_R12W: SET_OUT(REG_R12); break;
	case ZYDIS_REGISTER_R13W: SET_OUT(REG_R13); break;
	case ZYDIS_REGISTER_R14W: SET_OUT(REG_R14); break;
	case ZYDIS_REGISTER_R15W: SET_OUT(REG_R15); break;
	}
#undef SET_OUT
	outvalue = *poutvalue & mask;
	return InterSuccess;
}
static int GetMemorySize(ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operand,uint64_t rcx)
{
	int typecast = 0;
	switch (instruction->mnemonic) {
	case ZYDIS_MNEMONIC_MOVSB:
	case ZYDIS_MNEMONIC_STOSB:
		return 8;
	case ZYDIS_MNEMONIC_MOVSQ:
	case ZYDIS_MNEMONIC_STOSQ:
		return 64;
	case ZYDIS_MNEMONIC_MOVSD:
	case ZYDIS_MNEMONIC_STOSD:
		return 32;
	}
	/*for (int i = 0; i < instruction->operandCount; i++)
	{
		if (instruction->operands[i].size > typecast)
		{
			typecast = instruction->operands[i].size;
		}
	}*/
	if ((operand->type == ZYDIS_OPERAND_TYPE_MEMORY) &&
		(operand->mem.type == ZYDIS_MEMOP_TYPE_MEM))
	{
		switch (operand->id)
		{
		case 0:
			typecast =
				((instruction->operands[1].type == ZYDIS_OPERAND_TYPE_UNUSED) ||
				(instruction->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ||
					(instruction->operands[0].size != instruction->operands[1].size)) ?
				instruction->operands[0].size : 0;

			if (!typecast &&
				(instruction->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) &&
				(instruction->operands[1].reg.value == ZYDIS_REGISTER_CL))
			{
				switch (instruction->mnemonic)
				{
				case ZYDIS_MNEMONIC_RCL:
				case ZYDIS_MNEMONIC_ROL:
				case ZYDIS_MNEMONIC_ROR:
				case ZYDIS_MNEMONIC_RCR:
				case ZYDIS_MNEMONIC_SHL:
				case ZYDIS_MNEMONIC_SHR:
				case ZYDIS_MNEMONIC_SAR:
					typecast = instruction->operands[0].size;
				default:
					typecast = 8;
				}
			}
			else if (!typecast &&
				instruction->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
			{
				typecast = instruction->operands[1].size;
			}
			else if (!typecast)
			{
				//fprintf(stderr, "IS %d\n", instruction->operands[1].size);
			}
			break;
		case 1:
		case 2:
			typecast =
				(instruction->operands[operand->id - 1].size !=
					instruction->operands[operand->id].size) ?
				instruction->operands[operand->id].size : 0;
			break;
		default:
			break;
		}
	}
	return typecast;
}

static InterStatus ParseMemoryOperand(ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operand,ucontext* context, uintptr_t& outptr)
{
	switch (operand->mem.segment)
	{
	case ZYDIS_REGISTER_ES:
	case ZYDIS_REGISTER_CS:
	case ZYDIS_REGISTER_FS:
	case ZYDIS_REGISTER_GS:
		fprintf(stderr, "segment register not implemented\n");
		return InterNotImplemented;
	case ZYDIS_REGISTER_SS:
	case ZYDIS_REGISTER_DS:
		break;
	}


	if (operand->mem.disp.hasDisplacement && (
		(operand->mem.base == ZYDIS_REGISTER_NONE) ||
		(operand->mem.base == ZYDIS_REGISTER_EIP) ||
		(operand->mem.base == ZYDIS_REGISTER_RIP)) &&
		(operand->mem.index == ZYDIS_REGISTER_NONE) && (operand->mem.scale == 0))
	{
		// EIP/RIP-relative or absolute-displacement address operand
		ZydisU64 address;
		if (!ZYDIS_SUCCESS(ZydisCalcAbsoluteAddress(instruction, operand, &address)))
			return InterDecodeFailed;
		outptr = address;
	}	
	else
	{
		uint64_t val=0;
		uint64_t*  dummy;
		// Regular memory operand
		if (operand->mem.base != ZYDIS_REGISTER_NONE)
		{
			INTER_CHECK(GetRegisterValue(operand->mem.base, context,val, dummy));
		}
		if ((operand->mem.index != ZYDIS_REGISTER_NONE) &&
			(operand->mem.type != ZYDIS_MEMOP_TYPE_MIB))
		{
			uint64_t val2;
			INTER_CHECK(GetRegisterValue(operand->mem.index, context, val2, dummy));
			if (operand->mem.scale)
			{
				val2 *= operand->mem.scale;
			}
			val += val2;
		}
		//ZYDIS_CHECK(formatter->funcPrintDisp(formatter, string, instruction, operand, userData));
		if (operand->mem.disp.hasDisplacement)
		{
			if (operand->mem.disp.hasDisplacement && ((operand->mem.disp.value) ||
				((operand->mem.base == ZYDIS_REGISTER_NONE) &&
				(operand->mem.index == ZYDIS_REGISTER_NONE))))
			{
				if ((operand->mem.disp.value < 0) && (
					(operand->mem.base != ZYDIS_REGISTER_NONE) ||
					(operand->mem.index != ZYDIS_REGISTER_NONE)))
				{
					val += operand->mem.disp.value;
				}
				else
				{
					val += (ZydisU64)operand->mem.disp.value;
				}
			}
		}
		outptr = val;
	}

	return InterSuccess;
}

static InterStatus ParseOperand0(ZydisDecodedInstruction* instruction, ucontext* context, int& outsize, uint64_t& outptr)
{
	switch (instruction->operands[0].type)
	{
	case ZYDIS_OPERAND_TYPE_REGISTER:
		//fprintf(stderr, "reg\n");
		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		outsize = GetMemorySize(instruction, &instruction->operands[0],context->uc_mcontext.gregs[REG_RCX]);
		if (outsize == 0)
			return InterNotImplemented;
		INTER_CHECK(ParseMemoryOperand(instruction, &instruction->operands[0], context, outptr));
		return InterSuccess;
		break;
	case ZYDIS_OPERAND_TYPE_POINTER:
		//fprintf(stderr, "%ptr\n");
		break;
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		//fprintf(stderr, "imm\n");
		break;
	}
	return InterNotImplemented;
}

static InterStatus ParseOperand1(ZydisDecodedInstruction* instruction, ucontext* context, uint64_t& outptr)
{
	switch (instruction->operands[1].type)
	{
	case ZYDIS_OPERAND_TYPE_REGISTER:
		uint64_t dummy;
		uint64_t* ptr;
		INTER_CHECK(GetRegisterValue(instruction->operands[1].reg.value, context, dummy, ptr));
		outptr = (uint64_t)ptr;
		return InterSuccess;
		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		INTER_CHECK(ParseMemoryOperand(instruction, &instruction->operands[1], context, outptr));
		return InterSuccess;
		break;
	case ZYDIS_OPERAND_TYPE_POINTER:
		//fprintf(stderr, "%ptr\n");
		break;
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		outptr = (uint64_t) &(instruction->operands[1].imm.value.u);
		return InterSuccess;
		break;
	}
	return InterNotImplemented;
}

int DoInterprete(uint8_t * instr, ucontext* context, PVOID& outfrom, PVOID& outto, int& outsize)
{
	char buffer[512 / 8];
	int size;
	// Loop over the instructions in our buffer.
	uint64_t instructionPointer = (uint64_t)instr;
	uint8_t* readPointer = instr;
	ZydisDecodedInstruction instruction;
	if (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, readPointer, 128, instructionPointer, &instruction)))
	{
		// Print current instruction pointer.
		fprintf(stderr,"%016x  ", instructionPointer);

		// Format & print the binary instruction 
		// structure to human readable format.
		char buffer[256];
		ZydisFormatterFormatInstruction(
			&formatter, &instruction, buffer, sizeof(buffer));
		fprintf(stderr, "%s\n",buffer);
		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
		{
			int size;
			uint64_t ptr;
			InterStatus status;
			if ( (status=ParseOperand0(&instruction, context, size, ptr)) != InterSuccess)
			{
				fprintf(stderr, "Parse Operand 0 fail %d\n", status);
				return -1;
			}
			else
			{
				uint64_t ptr_from;
				fprintf(stderr, "addr = %x, size = %d\n", ptr,size);
				if ((status = ParseOperand1(&instruction, context, ptr_from)) != InterSuccess)
				{
					fprintf(stderr, "Parse Operand 1 fail %d\n", status);
					return -1;
				}
				else
				{
					outfrom = (PVOID)ptr_from;
					outto = (PVOID)ptr;
					outsize = size / 8;
				}
			}
			return instruction.length;
		}
	}
	else
	{
		return -1;
	}
	return -1;
}

void PrintInstruction(uint8_t * instr)
{
	uint64_t instructionPointer = (uint64_t)instr;
	uint8_t* readPointer = instr;
	ZydisDecodedInstruction instruction;
	if (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, readPointer, 128, instructionPointer, &instruction)))
	{
		// Print current instruction pointer.
		fprintf(stderr, "%016x  ", instructionPointer);

		// Format & print the binary instruction 
		// structure to human readable format.
		char buffer[256];
		ZydisFormatterFormatInstruction(
			&formatter, &instruction, buffer, sizeof(buffer));
		fprintf(stderr, "%s\n", buffer);
	}
}

int DoInterpreteSize(uint8_t * instr, int& outsize,uint64_t rcx)
{
	int size;
	// Loop over the instructions in our buffer.
	uint64_t instructionPointer = (uint64_t)instr;
	uint8_t* readPointer = instr;
	ZydisDecodedInstruction instruction;
	if (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, readPointer, 128, instructionPointer, &instruction)))
	{
		outsize = GetMemorySize(&instruction, &instruction.operands[0],rcx);
		return instruction.length;
	}
	else
	{
		return -1;
	}
	return -1;
}
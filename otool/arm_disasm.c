/*
 * Copyright (c) 2007 seto <griepl@gni.ch>
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "stuff/target_arch.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/ppc/reloc.h>
#include "stuff/bytesex.h"
#include "stuff/symbol.h"
#include "otool.h"
#include "ofile_print.h"

typedef enum bool bool_t;

enum data_type {
	TYPE_POINTER,
	TYPE_SINGLE,
	TYPE_DOUBLE,
};

struct objc_string_object {
    struct objc_class *isa;
    char *characters;
    unsigned int _length;
};
typedef struct objc_string_object NXConstantString;

#define CFSTRING_SECT "__cfstring"

// in bytes
static const unsigned int INSTRUCTION_SIZE = sizeof(unsigned long);
static const unsigned int NUM_REGS = 16;
static const char *BASE_REGS[] = { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc" };
// [14] = al (always), usually not written
static const char *COND_CODES[] = { "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "nv" };
static const char *FIELD_MASKS[] = { "", "c", "x", "cx", "s", "cs", "xs", "cxs", "f", "cf", "xf", "cxf", "sf", "csf", "xsf", "cxsf" };
static const char *DATA_OPERATIONS[] = { "and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn" };
static const char *SHIFT_MODES[] = { "lsl", "lsr", "asr", "ror" };
static const char *LDM_ADDR_MODES[] = { "da", "ia", "db", "ib" };
static const char *LD_ST_TYPE[] = { "st", "ld" };
static const char *MUL_MLA_TYPE[] = { "mul", "mla" };
static const char *SIGNED_TYPE[] = { "u", "s" };
static const char *SET_FLAGS[] = { "", "s" };
static const char *LINK_FLAGS[] = { "", "l" };
static const char *BYTE_FLAGS[] = { "", "b" };
static const char *SIGN_CHARS[] = { "-", "" };
static const char *UPDATE_CHARS[] = { "", "!" };
static const char *USERMODE_CHARS[] = { "", "^" };
static const char *SB_SH_TYPE[] = { "sb", "sh" };
static const char *MCR_MRC_TYPE[] = { "mcr", "mrc" };
static const char *MCRR_MRRC_TYPE[] = { "mcrr", "mrrc" };
static const char *VFP_SDX_TYPE[] = { "s", "d", "x" };
static const char *VFP_REG_TYPE[] = { "s", "d", "d" };
static const char *VFP_DATA_OPERATIONS[] = { "fmac", "fnmac", "fmsc", "fnmsc", "fmul", "fnmul", "fadd", "fsub", "fdiv", "", "", "", "", "", "", "" };
// fcvt (index 15) can be fcvtsd or fcvtds, depending on the source
// must be printed correctly
static const char *VFP_EXT_DATA_OPERATIONS[] = { "fcpy", "fabs", "fneg", "fsqrt", 0, 0, 0, 0, "fcmp", "fcmpe", "fcmpz", "fcmpez", 0, 0, 0, "fcvt", "fuito", "fsito", 0, 0, 0, 0, 0, 0, "ftoui", "ftouiz", "ftosi", "ftosiz", 0, 0, 0, 0 };
// the index is a binary concatenation of opcode and bit 0 of cp_num
static const char *VFP_MCR_OPERATIONS[] = { "fmsr", "fmdlr", 0, "fmdhr", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "fmxr", 0 };
static const char *VFP_MRC_OPERATIONS[] = { "fmrs", "fmrdl", 0, "fmrdh", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "fmrx", 0 };
static const char *VFP_STATUS_REGS[] = { "fpsid", "fpscr", 0, 0, 0, 0, 0, 0, "fpexc", 0, 0, 0, 0, 0, 0, 0 };

static const char *arm_symbol_name(
	unsigned long addr,
	enum byte_sex object_byte_sex,
	nlist_t *symbols, unsigned long nsymbols,
	struct symbol *sorted_symbols, unsigned long nsorted_symbols,
	char *strings, unsigned long strings_size,
	unsigned long *indirect_symbols, unsigned long nindirect_symbols,
	mach_header_t *mh,
	struct load_command *load_commands,
	enum bool verbose
);
static struct section *arm_find_addr(unsigned long addr, struct load_command *load_commands, unsigned long nload_commands);
static char *arm_redirect_mem_string(
	unsigned long addr,
	enum byte_sex object_byte_sex,
	nlist_t *symbols, unsigned long nsymbols,
	struct symbol *sorted_symbols, unsigned long nsorted_symbols,
	char *strings, unsigned long strings_size,
	unsigned long *indirect_symbols, unsigned long nindirect_symbols,
	mach_header_t *mh,
	struct load_command *load_commands
);
static void print_verbose_mem(
	int imm,
	enum data_type type,
	char *sect,
	unsigned long left,
	unsigned long addr,
	unsigned long sect_addr,
	enum byte_sex object_byte_sex,
	nlist_t *symbols, unsigned long nsymbols,
	struct symbol *sorted_symbols, unsigned long nsorted_symbols,
	char *strings, unsigned long strings_size,
	unsigned long *indirect_symbols, unsigned long nindirect_symbols,
	mach_header_t *mh,
	struct load_command *load_commands
);

unsigned long arm_disassemble(
	char *sect,
	unsigned long left,
	unsigned long addr,
	unsigned long sect_addr,
	enum byte_sex object_byte_sex,
	struct relocation_info *relocs, unsigned long nrelocs,
	nlist_t *symbols, unsigned long nsymbols,
	struct symbol *sorted_symbols, unsigned long nsorted_symbols,
	char *strings, unsigned long strings_size,
	unsigned long *indirect_symbols, unsigned long nindirect_symbols,
	mach_header_t *mh,
	struct load_command *load_commands,
	bool_t verbose
) {
    enum byte_sex host_byte_sex;
    bool_t swapped;
    unsigned long opcode;
    unsigned long sect_offset;
    const char *symbol_name;
	unsigned int cond, rd, rm, rn, rs, mask, dataop, s, mode, rot, sint, l, b, w, u, p, a, n, h, regs;
	unsigned int cp, crd, crm, crn, dataop2;
	unsigned int vfpsdx, d, m;
	bool_t regok;
	int imm;
	unsigned int i;

	host_byte_sex = get_host_byte_sex();
	swapped = host_byte_sex != object_byte_sex;
	sect_offset = addr - sect_addr;

	if (left < INSTRUCTION_SIZE) {
		if (left != 0) {
			memcpy(&opcode, sect, left);
			if(swapped) {
				opcode = SWAP_LONG(opcode);
			}
			printf(".long\t0x%08x\n", (unsigned int)opcode);
		}
		printf("(end of section)\n");
		return(left);
	}

	memcpy(&opcode, sect, INSTRUCTION_SIZE);
	if (swapped) {
	    opcode = SWAP_LONG(opcode);
	}

	if (verbose) {
		// This is non-default behavior for otool, but on the ARM, it makes a lot of sense (i.e. local constants)
		printf("%08lx\t", opcode);
	}
	
	cond = (opcode & 0xf0000000) >> 28;
	// Handle cond=1111 (iNValid, or extended instruction) separately
	switch (cond) {
	case 0xf:
		printf(".long 0x%08x\t;Extended instruction space\n", (unsigned int)opcode);
		break;
	default:
		switch(opcode & 0x0e000000) {
		case 0x00000000:
			switch(opcode & 0x00000010) {
			case 0x00000000:
				switch(opcode & 0x01900000) {
				case 0x01000000:
					switch(opcode & 0x00000080) {
					case 0x00000000:
						switch(opcode & 0x00200000) {
						case 0x00000000:
							//printf("Move status regiser to register: 0x%08x\n", (unsigned int)opcode);
							rd = (opcode & 0x0000f000) >> 12;
							switch (opcode & 0x04000000) {
							case 0x00000000:
								printf("mrs%s %s, cpsr\n", COND_CODES[cond], BASE_REGS[rd]);
								break;
							case 0x04000000:
								printf("mrs%s %s, spsr\n", COND_CODES[cond], BASE_REGS[rd]);
								break;
							}
							break;
						case 0x00200000:
							//printf("Move register to status regiser: 0x%08x\n", (unsigned int)opcode);
							rm = (opcode & 0x0000000f);
							mask = (opcode & 0x000f0000) >> 16;
							switch (opcode & 0x04000000) {
							case 0x00000000:
								printf("msr%s cpsr_%s, %s\n", COND_CODES[cond], FIELD_MASKS[mask], BASE_REGS[rm]);
								break;
							case 0x04000000:
								printf("msr%s spsr_%s, %s\n", COND_CODES[cond], FIELD_MASKS[mask], BASE_REGS[rm]);
								break;
							}
							break;
						}
						break;
					case 0x00000080:
						printf(".long 0x%08x\t;Enhanced DSP multiplies\n", (unsigned int)opcode);
						break;
					}
					break;
				default:
					//printf("Data processing immediate shift: 0x%08x\n", (unsigned int)opcode);
					dataop = (opcode & 0x01e00000) >> 21;
					s = (opcode & 0x00100000) >> 20;
					rn = (opcode & 0x000f0000) >> 16;
					rd = (opcode & 0x0000f000) >> 12;
					rm = (opcode & 0x0000000f);
					mode = (opcode & 0x00000060) >> 5;
					imm = (opcode & 0x00000f80) >> 7;
					if (dataop == 0xd || dataop == 0xf) {
						// mov/mvn
						if (rn == 0x0) {
							printf("%s%s%s %s, %s", DATA_OPERATIONS[dataop], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], BASE_REGS[rm]);
						} else {
							printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
						}
					} else if (dataop >= 0x8 && dataop <= 0xb) {
						// tst/teq/cmp/cmn
						if (rd == 0x0) {
							if (s) {
								printf("%s%s %s, %s", DATA_OPERATIONS[dataop], COND_CODES[cond], BASE_REGS[rn], BASE_REGS[rm]);
							} else {
								printf(".long 0x%08x\t;Extended instruction\n", (unsigned int)opcode);
							}
						} else {
							printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
						}
					} else {
						printf("%s%s%s %s, %s, %s", DATA_OPERATIONS[dataop], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], BASE_REGS[rn], BASE_REGS[rm]);
					}
					if (imm == 0x00) {
						if (mode == 0x3) {
							printf(", rrx");
						} else if (mode != 0x0) {
							printf(", %s #32", SHIFT_MODES[mode]);
						}
					} else {
						printf(", %s #%u", SHIFT_MODES[mode], imm);
					}
					printf("\n");
					break;
				}
				break;
			case 0x00000010:
				switch(opcode & 0x00000080) {
				case 0x00000000:
					switch(opcode & 0x01900000) {
					case 0x01000000:
						//printf("Miscellaneous: 0x%08x\n", (unsigned int)opcode);
						switch (opcode & 0x00000060) {
						case 0x00000000:
							switch (opcode & 0x00600000) {
							case 0x00200000:
								//printf("Branch/exchange instruction set: 0x%08x\n", (unsigned int)opcode);
								rm = (opcode & 0x0000000f);
								printf("bx%s %s\n", COND_CODES[cond], BASE_REGS[rm]);
								break;
							case 0x00600000:
								//printf("Count leading zeroes: 0x%08x\n", (unsigned int)opcode);
								rm = (opcode & 0x0000000f);
								rd = (opcode & 0x0000f000) >> 12;
								printf("clz%s %s, %s\n", COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rm]);
								break;
							default:
								printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
							}
							break;
						case 0x00000020:
							switch (opcode & 0x00600000) {
							case 0x00200000:
								//printf("Branch and link/exchange instruction set: 0x%08x\n", (unsigned int)opcode);
								rm = (opcode & 0x0000000f);
								printf("blx%s %s\n", COND_CODES[cond], BASE_REGS[rm]);
								break;
							default:
								printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
							}
							break;
						case 0x00000040:
							printf(".long 0x%08x\t;Enhanced DSP add/subtracts\n", (unsigned int)opcode);
							break;
						case 0x00000060:
							//printf("Software breakpoint: 0x%08x\n", (unsigned int)opcode);
							imm = ((opcode & 0x000fff00) >> 4) | (opcode & 0x0000000f);
							printf("bkpt 0x%04x\n", imm);
							break;
						}
						break;
					default:
						//printf("Data processing register shift: 0x%08x\n", (unsigned int)opcode);
						rn = (opcode & 0x000f0000) >> 16;
						rd = (opcode & 0x0000f000) >> 12;
						rs = (opcode & 0x00000f00) >> 8;
						rm = (opcode & 0x0000000f);
						if (rd == 0xf || rs == 0xf || rm == 0xf) {
							printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
						} else {
							dataop = (opcode & 0x01e00000) >> 21;
							s = (opcode & 0x00100000) >> 20;
							mode = (opcode & 0x00000060) >> 5;
							if (dataop == 0xd || dataop == 0xf) {
								// mov/mvn don't have an rn operand
								if (rn == 0x0) {
									printf("%s%s%s %s, %s, %s %s\n", DATA_OPERATIONS[dataop], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], BASE_REGS[rm], SHIFT_MODES[mode], BASE_REGS[rs]);
								} else {
									printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
								}
							} else if (dataop >= 0x8 && dataop <= 0xb) {
								// tst/teq/cmp/cmn
								if (rd == 0x0) {
									if (s) {
										printf("%s%s %s, %s, %s %s\n", DATA_OPERATIONS[dataop], COND_CODES[cond], BASE_REGS[rn], BASE_REGS[rm], SHIFT_MODES[mode], BASE_REGS[rs]);
									} else {
										printf(".long 0x%08x\t;Extended instruction\n", (unsigned int)opcode);
									}
								} else {
									printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
								}
							} else {
								printf("%s%s%s %s, %s, %s, %s %s\n", DATA_OPERATIONS[dataop], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], BASE_REGS[rn], BASE_REGS[rm], SHIFT_MODES[mode], BASE_REGS[rs]);
							}
						}
						break;
					}
					break;
				case 0x00000080:
					//printf("Multiplies/extra load/stores: 0x%08x\n", (unsigned int)opcode);
					switch (opcode & 0x00000040) {
					case 0x00000000:
						switch (opcode & 0x00000020) {
						case 0x00000000:
							switch (opcode & 0x01800000) {
							case 0x00000000:
								//printf("Multiply (accumulate): 0x%08x\n", (unsigned int)opcode);
								a = (opcode & 0x00200000) >> 21;
								s = (opcode & 0x00100000) >> 20;
								rd = (opcode & 0x000f0000) >> 16;
								rs = (opcode & 0x00000f00) >> 8;
								rm = (opcode & 0x0000000f);
								printf("%s%s%s %s, %s, %s\n", MUL_MLA_TYPE[a], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], BASE_REGS[rm], BASE_REGS[rs]);
								break;
							case 0x00800000:
								//printf("Multiply (accumulate) long: 0x%08x\n", (unsigned int)opcode);
								u = (opcode & 0x00400000) >> 22;
								a = (opcode & 0x00200000) >> 21;
								s = (opcode & 0x00100000) >> 20;
								rd = (opcode & 0x000f0000) >> 16;
								rn = (opcode & 0x0000f000) >> 12;
								rs = (opcode & 0x00000f00) >> 8;
								rm = (opcode & 0x0000000f);
								printf("%s%s%s%s %s, %s, %s, %s\n", SIGNED_TYPE[u], MUL_MLA_TYPE[a], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], BASE_REGS[rn], BASE_REGS[rm], BASE_REGS[rs]);
								break;
							case 0x01000000:
								switch (opcode & 0x00300000) {
								case 0x00000000:
									//printf("Swap/swap byte: 0x%08x\n", (unsigned int)opcode);
									b = (opcode & 0x00400000) >> 22;
									rn = (opcode & 0x000f0000) >> 16;
									rd = (opcode & 0x0000f000) >> 12;
									rm = (opcode & 0x0000000f);
									printf("swp%s%s %s, %s, [%s]\n", COND_CODES[cond], BYTE_FLAGS[b], BASE_REGS[rd], BASE_REGS[rm], BASE_REGS[rn]);
									break;
								default:
									printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
									break;
								}
								break;
							default:
								printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
								break;
							}
							break;
						case 0x00000020:
							p = (opcode & 0x01000000) >> 24;
							u = (opcode & 0x00800000) >> 23;
							w = (opcode & 0x00200000) >> 21;
							l = (opcode & 0x00100000) >> 20;
							rn = (opcode & 0x000f0000) >> 16;
							rd = (opcode & 0x0000f000) >> 12;
							switch (opcode & 0x00400000) {
							case 0x00000000:
								//printf("Load/store halfword register offset: 0x%08x\n", (unsigned int)opcode);
								rm = (opcode & 0x0000000f);
								printf("%sr%sh %s, [%s", LD_ST_TYPE[l], COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rn]);
								if (p) {
									if (w) {
										//pre-indexed
										printf(", %s%s]!\n", SIGN_CHARS[u], BASE_REGS[rm]);
									} else {
										//offset
										printf(", %s%s]\n", SIGN_CHARS[u], BASE_REGS[rm]);
									}
								} else {
									if (w) {
										//invalid
										printf("]\t;Unknown addressing mode\n");
									} else {
										//post-indexed
										printf("], %s%s\n", SIGN_CHARS[u], BASE_REGS[rm]);
									}
								}
								break;
							case 0x00400000:
								//printf("Load/store halfword immediate offset: 0x%08x\n", (unsigned int)opcode);
								imm = ((opcode & 0x0000000f) >> 4) | (opcode & 0x0000000f);
								printf("%sr%sh %s, [%s", LD_ST_TYPE[l], COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rn]);
								if (imm) {
									if (p) {
										if (w) {
											//pre-indexed
											printf(", #%s%d]!", SIGN_CHARS[u], imm);
										} else {
											//offset
											printf(", #%s%d]", SIGN_CHARS[u], imm);
										}
										if (verbose && rn == 0xf) {
											print_verbose_mem(
												imm,
												TYPE_POINTER,
												sect, left, addr, sect_addr,
												object_byte_sex,
												symbols, nsymbols,
												sorted_symbols, nsorted_symbols,
												strings, strings_size,
												indirect_symbols, nindirect_symbols,
												mh, load_commands
											);
										}
										printf("\n");
									} else {
										if (w) {
											//invalid
											printf("]\t;Unknown addressing mode\n");
										} else {
											//post-indexed
											printf("], #%s%d\n", SIGN_CHARS[u], imm);
										}
									}
								} else {
									printf("]\n");
								}
								break;
							}
							break;
						}
						break;
					case 0x00000040:
						p = (opcode & 0x01000000) >> 24;
						u = (opcode & 0x00800000) >> 23;
						w = (opcode & 0x00200000) >> 21;
						// h is also s for the two-word modes
						h = (opcode & 0x00000020) >> 5;
						// invert bit 0 (Store -> Load)
						l = h ^ 0x1;
						rn = (opcode & 0x000f0000) >> 16;
						rd = (opcode & 0x0000f000) >> 12;
						switch(opcode & 0x00500000) {
						case 0x00000000:
							//printf(".long 0x%08x\t;Load/store two words register offset\n", (unsigned int)opcode);
							if ((rd & 1) || rd > 15) {
								printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
							} else {
								rm = (opcode & 0x0000000f);
								printf("%sr%sd {%s, %s}, [%s", LD_ST_TYPE[l], COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rd + 1], BASE_REGS[rn]);
								if (p) {
									if (w) {
										//pre-indexed
										printf(", %s%s]!\n", SIGN_CHARS[u], BASE_REGS[rm]);
									} else {
										//offset
										printf(", %s%s]\n", SIGN_CHARS[u], BASE_REGS[rm]);
									}
								} else {
									if (w) {
										//invalid
										printf("]\t;Unknown addressing mode\n");
									} else {
										//post-indexed
										printf("], %s%s\n", SIGN_CHARS[u], BASE_REGS[rm]);
									}
								}
							}
							break;
						case 0x00100000:
							//printf(".long 0x%08x\t;Load/store signed halfword/byte register offset\n", (unsigned int)opcode);
							rm = (opcode & 0x0000000f);
							printf("%sr%sd {%s, %s}, [%s", LD_ST_TYPE[l], COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rd + 1], BASE_REGS[rn]);
							if (p) {
								if (w) {
									//pre-indexed
									printf(", %s%s]!\n", SIGN_CHARS[u], BASE_REGS[rm]);
								} else {
									//offset
									printf(", %s%s]\n", SIGN_CHARS[u], BASE_REGS[rm]);
								}
							} else {
								if (w) {
									//invalid
									printf("]\t;Unknown addressing mode\n");
								} else {
									//post-indexed
									printf("], %s%s\n", SIGN_CHARS[u], BASE_REGS[rm]);
								}
							}
							break;
						case 0x00400000:
							//printf(".long 0x%08x\t;Load/store two words immediate offset\n", (unsigned int)opcode);
							if ((rd & 1) || rd > 15) {
								printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
							} else {
								imm = ((opcode & 0x0000000f) >> 4) | (opcode & 0x0000000f);
								printf("%sr%sd %s, [%s", LD_ST_TYPE[l], COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rn]);
								if (imm) {
									if (p) {
										if (w) {
											//pre-indexed
											printf(", #%s%d]!", SIGN_CHARS[u], imm);
										} else {
											//offset
											printf(", #%s%d]", SIGN_CHARS[u], imm);
										}
										if (verbose && rn == 0xf) {
											print_verbose_mem(
												imm,
												TYPE_POINTER,
												sect, left, addr, sect_addr,
												object_byte_sex,
												symbols, nsymbols,
												sorted_symbols, nsorted_symbols,
												strings, strings_size,
												indirect_symbols, nindirect_symbols,
												mh, load_commands
											);
										}
										printf("\n");
									} else {
										if (w) {
											//invalid
											printf("]\t;Unknown addressing mode\n");
										} else {
											//post-indexed
											printf("], #%s%d\n", SIGN_CHARS[u], imm);
										}
									}
								} else {
									printf("]\n");
								}
							}
							break;
						case 0x00500000:
							//printf(".long 0x%08x\t;Load/store signed halfword/byte immediate offset\n", (unsigned int)opcode);
							imm = ((opcode & 0x0000000f) >> 4) | (opcode & 0x0000000f);
							printf("%sr%s%s %s, [%s", LD_ST_TYPE[l], SB_SH_TYPE[h], COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rn]);
							if (imm) {
								if (p) {
									if (w) {
										//pre-indexed
										printf(", #%s%d]!", SIGN_CHARS[u], imm);
									} else {
										//offset
										printf(", #%s%d]", SIGN_CHARS[u], imm);
									}
									if (verbose && rn == 0xf) {
										print_verbose_mem(
											imm,
											TYPE_POINTER,
											sect, left, addr, sect_addr,
											object_byte_sex,
											symbols, nsymbols,
											sorted_symbols, nsorted_symbols,
											strings, strings_size,
											indirect_symbols, nindirect_symbols,
											mh, load_commands
										);
									}
									printf("\n");
								} else {
									if (w) {
										//invalid
										printf("]\t;Unknown addressing mode\n");
									} else {
										//post-indexed
										printf("], #%s%d\n", SIGN_CHARS[u], imm);
									}
								}
							} else {
								printf("]\n");
							}
							break;
						}
						break;
					}
					break;
				}
				break;
			}
			break;
		case 0x02000000:
			//printf("Data processing immediate: 0x%08x\n", (unsigned int)opcode);
			rn = (opcode & 0x000f0000) >> 16;
			rd = (opcode & 0x0000f000) >> 12;
			dataop = (opcode & 0x01e00000) >> 21;
			s = (opcode & 0x00100000) >> 20;
			// actually >> 8, but the value used in the cpu (and thus written in assembly) is rot << 1
			rot = (opcode & 0x00000f00) >> 7;
			imm = (opcode & 0x000000ff);
			// mov/mvn don't have a second operand
			if (dataop == 0xd || dataop == 0xf) {
				if (rn) {
					printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
				} else {
					if (rot) {
						printf("%s%s%s %s, #0x%x, %u\n", DATA_OPERATIONS[dataop], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], imm, rot);
					} else {
						printf("%s%s%s %s, #0x%x\n", DATA_OPERATIONS[dataop], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], imm);
					}
				}
			} else if (dataop >= 0x8 && dataop <= 0xb) {
				// tst/teq/cmp/cmn
				if (rd) {
					printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
				} else {
					if (s) {
						if (rot) {
							printf("%s%s %s, #0x%x, %u\n", DATA_OPERATIONS[dataop], COND_CODES[cond], BASE_REGS[rn], imm, rot);
						} else {
							printf("%s%s %s, #0x%x\n", DATA_OPERATIONS[dataop], COND_CODES[cond], BASE_REGS[rn], imm);
						}
					} else {
						printf(".long 0x%08x\t;Extended instruction\n", (unsigned int)opcode);
					}
				}
			} else {
				if (rot) {
					printf("%s%s%s %s, %s, #0x%x, %u\n", DATA_OPERATIONS[dataop], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], BASE_REGS[rn], imm, rot);
				} else {
					printf("%s%s%s %s, %s, #0x%x\n", DATA_OPERATIONS[dataop], COND_CODES[cond], SET_FLAGS[s], BASE_REGS[rd], BASE_REGS[rn], imm);
				}
			}
			break;
		case 0x04000000:
			//printf("Load/store immediate offset: 0x%08x\n", (unsigned int)opcode);
			rd = (opcode & 0x0000f000) >> 12;
			rn = (opcode & 0x000f0000) >> 16;
			l = (opcode & 0x00100000) >> 20;
			w = (opcode & 0x00200000) >> 21;
			b = (opcode & 0x00400000) >> 22;
			u = (opcode & 0x00800000) >> 23;
			p = (opcode & 0x01000000) >> 24;
			imm = (opcode & 0x00000fff);
			// apply sign bit
			if (!u) {
				imm = -imm;
			}
			printf("%sr%s%s", LD_ST_TYPE[l], COND_CODES[cond], BYTE_FLAGS[b]);
			if (p) {
				if (w) {
					//pre-indexed
					printf(" %s, [%s, #%d]!", BASE_REGS[rd], BASE_REGS[rn], imm);
				} else {
					//offset
					printf(" %s, [%s, #%d]", BASE_REGS[rd], BASE_REGS[rn], imm);
				}
				if (verbose && rn == 0xf) {
					print_verbose_mem(
						imm,
						TYPE_POINTER,
						sect, left, addr, sect_addr,
						object_byte_sex,
						symbols, nsymbols,
						sorted_symbols, nsorted_symbols,
						strings, strings_size,
						indirect_symbols, nindirect_symbols,
						mh, load_commands
					);
				}
				printf("\n");
			} else {
				if (w) {
					//post-indexed translation
					printf("t %s, [%s], #%d\n", BASE_REGS[rd], BASE_REGS[rn], imm);
				} else {
					//post-indexed
					printf(" %s, [%s], #%d\n", BASE_REGS[rd], BASE_REGS[rn], imm);
				}
			}
			break;
		case 0x06000000:
			//printf("Load/store register offset: 0x%08x\n", (unsigned int)opcode);
			rm = (opcode & 0x0000000f);
			rd = (opcode & 0x0000f000) >> 12;
			rn = (opcode & 0x000f0000) >> 16;
			l = (opcode & 0x00100000) >> 20;
			w = (opcode & 0x00200000) >> 21;
			b = (opcode & 0x00400000) >> 22;
			u = (opcode & 0x00800000) >> 23;
			p = (opcode & 0x01000000) >> 24;
			mode = (opcode & 0x00000060) >> 5;
			imm = (opcode & 0x00000f80) >> 7;
			printf("%sr%s%s", LD_ST_TYPE[l], COND_CODES[cond], BYTE_FLAGS[b]);
			if (p) {
				printf(" %s, [%s, ", BASE_REGS[rd], BASE_REGS[rn]);
			} else {
				if (w) {
					printf("t ");
				}
				printf("%s, [%s], ", BASE_REGS[rd], BASE_REGS[rn]);
			}
			printf("%s%s", SIGN_CHARS[u], BASE_REGS[rm]);
			if (imm == 0x00) {
				if (mode != 0x0) {
					printf(", %s #32", SHIFT_MODES[mode]);
				}
			} else {
				printf(", %s #%u", SHIFT_MODES[mode], imm);
			}
			if (p) {
				if (w) {
					printf("]!");
				} else {
					printf("]");
				}
			}
			printf("\n");
			break;
		case 0x08000000:
			//printf("Load/store multiple: 0x%08x\n", (unsigned int)opcode);
			rn = (opcode & 0x000f0000) >> 16;
			l = (opcode & 0x00100000) >> 20;
			w = (opcode & 0x00200000) >> 21;
			s = (opcode & 0x00400000) >> 22;
			regs = (opcode & 0x0000ffff);
			mode = (opcode & 0x01800000) >> 23;
			printf("%sm%s%s %s%s, {", LD_ST_TYPE[l], COND_CODES[cond], LDM_ADDR_MODES[mode], BASE_REGS[rn], UPDATE_CHARS[w]);
			for (i = 0; i < NUM_REGS; i++) {
				if (regs & (1 << i)) {
					printf(BASE_REGS[i]);
					// check for remaining bits
					if (regs & (0xffff << (i + 1))) {
						printf(", ");
					}
				}
			}
			printf("}%s\n", USERMODE_CHARS[s]);
			break;
		case 0x0a000000:
			//printf("Branch: 0x%08x\n", (unsigned int)opcode);
			l = (opcode & 0x01000000) > 24;
			imm = (opcode & 0x00ffffff);
			// negative 24bit?)
			if (imm & 0x00800000) {
				// 1-expand
				imm |= 0xff000000;
			}
			imm <<= 2;
			imm += addr + 8;
			printf("b%s%s ", LINK_FLAGS[l], COND_CODES[cond]);
			if (verbose) {
				symbol_name = arm_symbol_name(
					imm,
					object_byte_sex,
					symbols, nsymbols,
					sorted_symbols, nsorted_symbols,
					strings, strings_size,
					indirect_symbols, nindirect_symbols,
					mh,
					load_commands,
					verbose
				);
				if (symbol_name) {
					printf("%s", symbol_name);
				} else {
					printf("0x%08x", imm);
				}
			} else {
				printf("0x%08x", imm);
			}
			printf("\n");
			break;
		case 0x0c000000:
			//printf(".long 0x%08x\t;Coprocessor load/store\n", (unsigned int)opcode);
			imm = (opcode & 0x000000ff);
			cp = (opcode & 0x00000f00) >> 8;
			crd = (opcode & 0x0000f000) >> 12;
			rn = (opcode & 0x000f0000) >> 16;
			l = (opcode & 0x00100000) >> 20;
			w = (opcode & 0x00200000) >> 21;
			n = (opcode & 0x00400000) >> 22;
			u = (opcode & 0x00800000) >> 23;
			p = (opcode & 0x01000000) >> 24;
			switch (cp) {
			case 10:
			case 11:
				// handle VFP instructions
				// S or D type
				vfpsdx = cp & 0x1;
				if (vfpsdx == 0) {
					// single float, D bit = N flag
					crd = (crd << 1) | n;
				}
				// the addressing modes for VFP are a bit different than for generic coprocessors
				switch ((p << 2) | (u << 1) | w) {
				case 0x0:
				case 0x1:
					// ARMv5TE coprocessor extensions: FMxRR/FMRRx
					rd = (opcode & 0x0000f000) >> 12;
					crm = (opcode & 0x0000000f);
					if (vfpsdx == 0) {
						// single float
						m = (opcode & 0x00000020) >> 5;
						crm = (crm << 1) | m;
					}
					if ((opcode & 0x000000d0) == 0x00000010) {
						if (l) {
							// FMRRx
							switch (vfpsdx) {
							case 0:
								printf("fmrrs%s %s, %s, s%u, s%u\n", COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rn], crd, crd + 1);
								break;
							case 1:
								printf("fmrrd%s %s, %s, d%u\n", COND_CODES[cond], BASE_REGS[rd], BASE_REGS[rn], crd);
								break;
							}
						} else {
							// FMxRR
							switch (vfpsdx) {
							case 0:
								printf("fmrrs%s s%u, s%u, %s, %s\n", COND_CODES[cond], crd, crd + 1, BASE_REGS[rd], BASE_REGS[rn]);
								break;
							case 1:
								printf("fmrrd%s d%u, %s, %s\n", COND_CODES[cond], crd, BASE_REGS[rd], BASE_REGS[rn]);
								break;
							}
						}
					} else {
						printf(".long 0x%08x\t;Invalid VFP load/store extension instruction\n", (unsigned int)opcode);
					}
					break;
				case 0x7:
					printf(".long 0x%08x\t;Invalid VFP load/store instruction\n", (unsigned int)opcode);
					break;
				case 0x2:
					// unindexed multiple
				case 0x3:
					// increment multiple
				case 0x5:
					// decrement multiple
					if (imm & 0x1) {
						// eXtended mode
						vfpsdx = 2;
					}
					// check for invalid ranges
					regok = TRUE;
					switch (vfpsdx) {
					case 0:
						if (imm == 0 || crd + imm > 32) {
							regok = FALSE;
						}
						break;
					case 1:
					case 2:
						if (imm == 0 || crd + (imm >> 1) > 16) {
							regok = FALSE;
						}
						break;
					}
					if (regok) {
						printf("f%sm%s%s%s %s%s, {", LD_ST_TYPE[l], LDM_ADDR_MODES[(p << 1) | u], VFP_SDX_TYPE[vfpsdx], COND_CODES[cond], BASE_REGS[rn], UPDATE_CHARS[w]);
						for (i = 0; i < imm - 1; i++) {
							printf("%s%u, ", VFP_REG_TYPE[vfpsdx], crd + i);
						}
						printf("%s%u}\n", VFP_REG_TYPE[vfpsdx], crd + i);
					} else {
						printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
					}
					break;
				case 0x4:
				case 0x6:
					// negative/positive offset single
					printf("f%s%s%s %s%u, [%s", LD_ST_TYPE[l], VFP_SDX_TYPE[vfpsdx], COND_CODES[cond], VFP_REG_TYPE[vfpsdx], crd, BASE_REGS[rn]);
					if (imm) {
						printf(", #%s%u", SIGN_CHARS[u], imm << 2);
					}
					printf("]");
					if (verbose && rn == 0xf) {
						switch(vfpsdx) {
						case 0:
							print_verbose_mem(
								u ? (imm << 2) : -(imm << 2),
								TYPE_SINGLE,
								sect, left, addr, sect_addr,
								object_byte_sex,
								symbols, nsymbols,
								sorted_symbols, nsorted_symbols,
								strings, strings_size,
								indirect_symbols, nindirect_symbols,
								mh, load_commands
							);
							break;
						case 1:
							print_verbose_mem(
								u ? (imm << 2) : -(imm << 2),
								TYPE_DOUBLE,
								sect, left, addr, sect_addr,
								object_byte_sex,
								symbols, nsymbols,
								sorted_symbols, nsorted_symbols,
								strings, strings_size,
								indirect_symbols, nindirect_symbols,
								mh, load_commands
							);
							break;
						}
					}
					printf("\n");
					break;
				}
				break;
			default:
				// handle all other coprocessors
				if ((opcode & 0x0fe00000) == 0x0c400000) {
					// mcrr/mrrc
					dataop = (opcode & 0x00000f0) >> 4;
					crm = (opcode & 0x0000000f);
					printf("%s%s p%u, %u, %s, %s, c%u", MCRR_MRRC_TYPE[l], COND_CODES[cond], cp, dataop, BASE_REGS[crd], BASE_REGS[rn], crm);
				} else {
					printf("%sc%s%s p%u, c%u, ", LD_ST_TYPE[l], COND_CODES[cond], LINK_FLAGS[n], cp, crd);
					if (p) {
						printf("[%s, #%s%u]", BASE_REGS[rn], SIGN_CHARS[u], imm << 2);
						if (w) {
							printf("!");
						}
					} else {
						printf("[%s], ", BASE_REGS[rn]);
						if (w) {
							printf("#%s%u", SIGN_CHARS[u], imm << 2);
						} else {
							printf("0x%02x", imm);
						}
					}
					printf("\n");
				}
				break;
			}
			break;
		case 0x0e000000:
			switch(opcode & 0x01000000) {
			case 0x00000000:
				switch (opcode & 0x00000010) {
				case 0x00000000:
					//printf(".long 0x%08x\t;Coprocessor data processing\n", (unsigned int)opcode);
					cp = (opcode & 0x00000f00) >> 8;
					switch (cp) {
					case 10:
					case 11:
						// handle VFP instructions
						crm = (opcode & 0x0000000f);
						cp = (opcode & 0x00000f00) >> 8;
						crd = (opcode & 0x0000f000) >> 12;
						crn = (opcode & 0x000f0000) >> 16;
						n = (opcode & 0x00000080) >> 7;
						// p, q, r, s are quite scattered...
						dataop = ((opcode & 0x00800000) >> 20) | ((opcode & 0x00300000) >> 19) | ((opcode & 0x00000040) >> 6);
						vfpsdx = cp & 0x1;
						if (vfpsdx == 0) {
							// single float
							d = (opcode & 0x00400000) >> 22;
							crd = (crd << 1) | d;
							m = (opcode & 0x00000020) >> 5;
							crm = (crm << 1) | m;
						}
						if (dataop > 0x9) {
							if (dataop == 0xf) {
								// op without Fn
								// Fn|N = operation #
								dataop2 = (crn << 1) | n;
								if (dataop2 == 15) {
									// special case fcvt
									switch (vfpsdx) {
									case 0:
										// single float
										printf("fcvtds%s d%u, s%u\n", COND_CODES[cond], crd, crm);
										break;
									case 1:
										// double float
										printf("fcvtsd%s s%u, d%u\n", COND_CODES[cond], crd, crm);
										break;
									}
								} else {
									// invalid instructions are a null pointer in the list
									if (VFP_EXT_DATA_OPERATIONS[dataop2]) {
										printf("%s%s%s %s%u, %s%u\n", VFP_EXT_DATA_OPERATIONS[dataop2], VFP_SDX_TYPE[vfpsdx], COND_CODES[cond], VFP_REG_TYPE[vfpsdx], crd, VFP_REG_TYPE[vfpsdx], crm);
									} else {
										printf(".long 0x%08x\t;Invalid extended VFP processing instruction op=0x%x\n", (unsigned int)opcode, dataop);
									}
								}
							} else {
								printf(".long 0x%08x\t;Invalid VFP processing instruction op=0x%x\n", (unsigned int)opcode, dataop);
							}
						} else {
							if (vfpsdx == 0) {
								// single float
								crn = (crn << 1) | n;
							}
							printf("%s%s%s %s%u, %s%u, %s%u\n", VFP_DATA_OPERATIONS[dataop], VFP_SDX_TYPE[vfpsdx], COND_CODES[cond], VFP_REG_TYPE[vfpsdx], crd, VFP_REG_TYPE[vfpsdx], crn, VFP_REG_TYPE[vfpsdx], crm);
						}
						break;
					default:
						// handle all other coprocessors
						crm = (opcode & 0x0000000f);
						cp = (opcode & 0x00000f00) >> 8;
						crd = (opcode & 0x0000f000) >> 12;
						crn = (opcode & 0x000f0000) >> 16;
						dataop = (opcode & 0x00f00000) >> 20;
						dataop2 = (opcode & 0x000000e0) >> 5;
						printf("cdp%s p%u, %u, c%u, c%u, c%u, %u\n", COND_CODES[cond], cp, dataop, crd, crn, crm, dataop2);
						break;
					}
					break;
				case 0x00000010:
					//printf(".long 0x%08x\t;Coprocessor register transfer\n", (unsigned int)opcode);
					cp = (opcode & 0x00000f00) >> 8;
					rd = (opcode & 0x0000f000) >> 12;
					crn = (opcode & 0x000f0000) >> 16;
					dataop = (opcode & 0x00e00000) >> 21;
					l = (opcode & 0x00100000) >> 20;
					switch (cp) {
					case 10:
					case 11:
						// handle VFP instructions
						if ((opcode & 0x0000007f) == 0x10) {
							vfpsdx = cp & 0x1;
							dataop = (dataop << 1) | vfpsdx;
							if (VFP_MRC_OPERATIONS[dataop]) {
								if (dataop == 14) {
									// status register transfer
									if (VFP_STATUS_REGS[crn]) {
										if (l) {
											if (rd == 15) {
												printf("fmstat%s\n", COND_CODES[cond]);
											} else {
												printf("%s%s %s, %s\n", VFP_MRC_OPERATIONS[dataop], COND_CODES[cond], BASE_REGS[rd], VFP_STATUS_REGS[crn]);
											}
										} else {
											printf("%s%s %s, %s\n", VFP_MCR_OPERATIONS[dataop], COND_CODES[cond], VFP_STATUS_REGS[crn], BASE_REGS[rd]);
										}
									} else {
										printf(".long 0x%08x\t;Invalid VFP status register %u\n", (unsigned int)opcode, crn);
									}
								} else {
									if (vfpsdx == 0) {
										// single float
										n = (opcode & 0x00000080) >> 7;
										crn = (crn << 1) | n;
									}
									if (l) {
										printf("%s%s %s, %s%u\n", VFP_MRC_OPERATIONS[dataop], COND_CODES[cond], BASE_REGS[rd], VFP_REG_TYPE[vfpsdx], crn);
									} else {
										printf("%s%s %s%u, %s\n", VFP_MCR_OPERATIONS[dataop], COND_CODES[cond], VFP_REG_TYPE[vfpsdx], crn, BASE_REGS[rd]);
									}
								}
							} else {
								// invalid operation
								printf(".long 0x%08x\t;Invalid VFP register transfer instruction op=0x%x\n", (unsigned int)opcode, dataop);
							}
						} else {
							printf(".long 0x%08x\t;Invalid VFP register transfer instruction\n", (unsigned int)opcode);
						}
						break;
					default:
						// handle all other coprocessors
						crm = (opcode & 0x0000000f);
						dataop2 = (opcode & 0x000000e0) >> 5;
						printf("%s%s cp%u, %u, %s, c%u, c%u", MCR_MRC_TYPE[l], COND_CODES[cond], cp, dataop, BASE_REGS[rd], crn, crm);
						if (dataop2) {
							printf(", %u", dataop2);
						}
						printf("\n");
						break;
					}
					break;
				}
				break;
			case 0x01000000:
				sint = (opcode & 0x00ffffff);
				printf("swi %u\n", sint);
				break;
			}
			break;
		default:
			printf(".long 0x%08x\t;Invalid instruction\n", (unsigned int)opcode);
			break;
		}
		break;
	}
	return(INSTRUCTION_SIZE);
}

// Simple symbol resolver
// If the given address can be found in the indirect symbol pool,
// the name of the corresponding symbol is returned.
// If not, a search through the direct symbols (labels) is performed.
// If no symbol can be found there either, NULL is returned.
// This function is reentrant, because the returned string resides
// in the constant symbol pool of the decoded binary and is never modified.
static const char *arm_symbol_name(
	unsigned long addr,
	enum byte_sex object_byte_sex,
	nlist_t *symbols, unsigned long nsymbols,
	struct symbol *sorted_symbols, unsigned long nsorted_symbols,
	char *strings, unsigned long strings_size,
	unsigned long *indirect_symbols, unsigned long nindirect_symbols,
	mach_header_t *mh,
	struct load_command *load_commands,
	bool_t verbose
) {
	const char *symbol_name;
	symbol_name = guess_indirect_symbol(
		addr,
		mh,
		load_commands,
		object_byte_sex,
		indirect_symbols, nindirect_symbols,
		symbols, nsymbols,
		strings, strings_size
	);
	if (!symbol_name) {
		symbol_name = guess_symbol(
			addr,
			sorted_symbols, nsorted_symbols,
			verbose
		);
	}
	return symbol_name;
}

// Return the information structure for the section containing the given address
// or NULL if it's not in the file
static struct section *arm_find_addr(unsigned long addr, struct load_command *load_commands, unsigned long nload_commands) {
	int i;
	struct load_command *current;
	for (i = 0, current = load_commands; i < nload_commands; i++, current = ((void *) current) + current->cmdsize) {
		if (current->cmd == LC_SEGMENT) {
			struct segment_command *cmd = (struct segment_command *) current;
			int j;
			for (j = 0; j < cmd->nsects; j++) {
				struct section *sect = &(((struct section *) (((void *) cmd) + sizeof(struct segment_command)))[j]);
				if (addr >= sect->addr && addr < sect->addr + sect->size) {
					return sect;
				}
			}
		}
	}
	return NULL;
}

// ARM specific string dereferencing
// The given address will be looked for in the list of sections.
// If it can be found, the offset of the data will be calculated, and the data
// retrieved by means of using the mach_header as pointer to offset 0 of the
// object file.
// The returned string is malloc'd and must be free'd after use.
// The following formats will be used for the respective section data types:
// Address out of range: <NULL> (a null pointer is returned) 
// S_REGULAR: @ 0x%08lx (is this a good or bad idea?)
// S_CSTRING_LITERALS: * "%s"
// S_4BYTE_LITERALS: * 0x%08lx
// S_8BYTE_LITERALS: * 0x%016Lx
// S_LITERAL_POINTERS: *{n} %s (arm_redirect_mem_string will be called recursively until
// something else than a LITERAL_POINTER is found; each round adds a "*")
static char *arm_redirect_mem_string(
	unsigned long addr,
	enum byte_sex object_byte_sex,
	nlist_t *symbols, unsigned long nsymbols,
	struct symbol *sorted_symbols, unsigned long nsorted_symbols,
	char *strings, unsigned long strings_size,
	unsigned long *indirect_symbols, unsigned long nindirect_symbols,
	mach_header_t *mh,
	struct load_command *load_commands
) {
	char *ret, *temp;
	unsigned long off;
	void *data;
	struct section *sect;
    enum byte_sex host_byte_sex;
    bool_t swapped;
	unsigned long redir;

	host_byte_sex = get_host_byte_sex();
	swapped = host_byte_sex != object_byte_sex;
	
	sect = arm_find_addr(addr, load_commands, mh->ncmds);
	if (sect) {
		//printf("\n<%s::%s>\n", sect->segname, sect->sectname);
		off = sect->offset + addr - sect->addr;
		data = (void *) mh + off;
		if (!strncmp(sect->sectname, CFSTRING_SECT, sizeof(CFSTRING_SECT))) {
			if (swapped) {
				redir = SWAP_LONG(((unsigned long *)data)[2]);
			} else {
				redir = ((unsigned long *)data)[2];
			}
			ret = arm_redirect_mem_string(
				redir,
				object_byte_sex,
				symbols, nsymbols,
				sorted_symbols, nsorted_symbols,
				strings, strings_size,
				indirect_symbols, nindirect_symbols,
				mh,
				load_commands
			);
			if (ret) {
				asprintf(&temp, "@%s", ret);
				free(ret);
				ret = temp;
			} else {
				asprintf(&ret, "@ 0x%08lx", redir);
			}
		} else {
			switch(sect->flags & 0xf) {
			case S_CSTRING_LITERALS:
				asprintf(&ret, "* \"%s\"", (const char *)data);
				break;
			case S_REGULAR:
			case S_4BYTE_LITERALS:
				asprintf(&ret, "* 0x%08lx", *(unsigned long *)data);
				break;
			case S_8BYTE_LITERALS:
				asprintf(&ret, "* 0x%016Lx", *(unsigned long long *)data);
				break;
			case S_LITERAL_POINTERS:
				if (swapped) {
					redir = SWAP_LONG(*(unsigned long *)data);
				} else {
					redir = *(unsigned long *)data;
				}
				ret = arm_redirect_mem_string(
					redir,
					object_byte_sex,
					symbols, nsymbols,
					sorted_symbols, nsorted_symbols,
					strings, strings_size,
					indirect_symbols, nindirect_symbols,
					mh,
					load_commands
				);
				if (ret) {
					asprintf(&temp, "*%s", ret);
					free(ret);
					ret = temp;
				} else {
					asprintf(&ret, "* 0x%08lx", redir);
				}
				break;
			default:
				sect = NULL;
			}
		}
	}
	if (!sect) {
		ret = NULL;
	}
	return ret;
}

static void print_verbose_mem(
	int imm,
	enum data_type type,
	char *sect,
	unsigned long left,
	unsigned long addr,
	unsigned long sect_addr,
	enum byte_sex object_byte_sex,
	nlist_t *symbols, unsigned long nsymbols,
	struct symbol *sorted_symbols, unsigned long nsorted_symbols,
	char *strings, unsigned long strings_size,
	unsigned long *indirect_symbols, unsigned long nindirect_symbols,
	mach_header_t *mh,
	struct load_command *load_commands
) {
	unsigned int size, imm_addr, redir_imm;
	unsigned long sect_offset;
	int imm_offset;
    const char *symbol_name;
	char *mem_string;
    enum byte_sex host_byte_sex;
    bool_t swapped;
	float f;
	double d;

	host_byte_sex = get_host_byte_sex();
	swapped = host_byte_sex != object_byte_sex;
	sect_offset = addr - sect_addr;

	imm_addr = imm + addr + 8;
	printf("\t;[0x%08x]", imm_addr);
	
	// Is the address inside the current section?
	// TODO: Let's hope we can access the section contents before addr like this...
	imm_offset = imm_addr - sect_addr;
	switch (type) {
	case TYPE_SINGLE:
		size = sizeof(float);
		break;
	case TYPE_DOUBLE:
		size = sizeof(double);
		break;
	case TYPE_POINTER:
	default:
		size = INSTRUCTION_SIZE;
		break;
	}
	if (imm_offset >= 0 && imm_offset + size < sect_offset + left) {
		switch (type) {
		case TYPE_POINTER:
			memcpy(&redir_imm, sect + imm + 8, size);
			if (swapped) {
				redir_imm = SWAP_LONG(redir_imm);
			}
			symbol_name = arm_symbol_name(
				redir_imm,
				object_byte_sex,
				symbols, nsymbols,
				sorted_symbols, nsorted_symbols,
				strings, strings_size,
				indirect_symbols, nindirect_symbols,
				mh,
				load_commands,
				TRUE
			);
			if (symbol_name) {
				printf(" = %s", symbol_name);
			} else {
				printf(" = 0x%08x", redir_imm);
			}
			mem_string = arm_redirect_mem_string(
				redir_imm,
				object_byte_sex,
				symbols, nsymbols,
				sorted_symbols, nsorted_symbols,
				strings, strings_size,
				indirect_symbols, nindirect_symbols,
				mh,
				load_commands
			);
			if (mem_string) {
				printf(" (%s)", mem_string);
				free(mem_string);
			}
			break;
		case TYPE_SINGLE:
			memcpy((char *) &f, sect + imm + 8, sizeof(float));
			if (swapped) {
				f = SWAP_FLOAT(f);
			}
			printf(" = %f", f);
			break;
		case TYPE_DOUBLE:
			memcpy((char *) &d, sect + imm + 8, sizeof(double));
			if (swapped) {
				d = SWAP_DOUBLE(d);
			}
			printf(" = %lf", d);
			break;
		}
	}
}
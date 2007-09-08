/* ----------------------------------------------------------------------------
 *   ARM1176/iPhone support for Apple GAS.                 v0.20 - 09/03/2007
 *
 *   Copyright (c) 2007 Patrick Walton <pcwalton@uchicago.edu> and
 *   contributors but freely redistributable under the terms of the GNU
 *   General Public License v2.
 * ------------------------------------------------------------------------- */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/machine.h>
#include <stuff/bytesex.h>

#include "arm.h"
#include "army.h"
#include "frags.h"
#include "fixes.h"
#include "messages.h"
#include "read.h"
#include "write_object.h"

int parsing_op = 0;

/* Keep this in asciibetical order - it's going to be bsearch'd! */
struct arm_reserved_word_info arm_reserved_word_info[] = {
    { "a1",     OPRD_REG,           0       },
    { "a2",     OPRD_REG,           1       },
    { "a3",     OPRD_REG,           2       },
    { "a4",     OPRD_REG,           3       },
    { "asl",    OPRD_LSL_LIKE,      0       },
    { "asr",    OPRD_LSL_LIKE,      1 << 6  },
    { "be",     OPRD_ENDIANNESS,    1 << 9  },
    { "c0",     OPRD_CR,            0       },
    { "c1",     OPRD_CR,            1       },
    { "c10",    OPRD_CR,            10      },
    { "c11",    OPRD_CR,            11      },
    { "c12",    OPRD_CR,            12      },
    { "c13",    OPRD_CR,            13      },
    { "c14",    OPRD_CR,            14      },
    { "c15",    OPRD_CR,            15      },
    { "c2",     OPRD_CR,            2       },
    { "c3",     OPRD_CR,            3       },
    { "c4",     OPRD_CR,            4       },
    { "c5",     OPRD_CR,            5       },
    { "c6",     OPRD_CR,            6       },
    { "c7",     OPRD_CR,            7       },
    { "c8",     OPRD_CR,            8       },
    { "c9",     OPRD_CR,            9       },
    { "cpsr",   OPRD_PSR,           0 << 22 },
    { "cr0",    OPRD_COPRO_REG,     0       },
    { "cr1",    OPRD_COPRO_REG,     1       },
    { "cr10",   OPRD_COPRO_REG,     10      },
    { "cr11",   OPRD_COPRO_REG,     11      },
    { "cr12",   OPRD_COPRO_REG,     12      },
    { "cr13",   OPRD_COPRO_REG,     13      },
    { "cr14",   OPRD_COPRO_REG,     14      },
    { "cr15",   OPRD_COPRO_REG,     15      },
    { "cr2",    OPRD_COPRO_REG,     2       },
    { "cr3",    OPRD_COPRO_REG,     3       },
    { "cr4",    OPRD_COPRO_REG,     4       },
    { "cr5",    OPRD_COPRO_REG,     5       },
    { "cr6",    OPRD_COPRO_REG,     6       },
    { "cr7",    OPRD_COPRO_REG,     7       },
    { "cr8",    OPRD_COPRO_REG,     8       },
    { "cr9",    OPRD_COPRO_REG,     9       },
    { "d0",     OPRD_REG_D,         0       },
    { "d1",     OPRD_REG_D,         1       },
    { "d10",    OPRD_REG_D,         10      },
    { "d11",    OPRD_REG_D,         11      },
    { "d12",    OPRD_REG_D,         12      },
    { "d13",    OPRD_REG_D,         13      },
    { "d14",    OPRD_REG_D,         14      },
    { "d15",    OPRD_REG_D,         15      },
    { "d2",     OPRD_REG_D,         2       },
    { "d3",     OPRD_REG_D,         3       },
    { "d4",     OPRD_REG_D,         4       },
    { "d5",     OPRD_REG_D,         5       },
    { "d6",     OPRD_REG_D,         6       },
    { "d7",     OPRD_REG_D,         7       },
    { "d8",     OPRD_REG_D,         8       },
    { "d9",     OPRD_REG_D,         9       },
    { "fp",     OPRD_REG,           11      },
    { "fpexc",  OPRD_REG_VFP_SYS,   0x8     },
    { "fpscr",  OPRD_REG_VFP_SYS,   0x1     },
    { "fpsid",  OPRD_REG_VFP_SYS,   0x0     },
    { "ip",     OPRD_REG,           12      },
    { "le",     OPRD_ENDIANNESS,    0 << 9  },
    { "lr",     OPRD_REG,           14      },
    { "lsl",    OPRD_LSL_LIKE,      0       },
    { "lsr",    OPRD_LSL_LIKE,      1 << 5  },
    { "p0",     OPRD_COPROC,        0       },
    { "p1",     OPRD_COPROC,        1       },
    { "p10",    OPRD_COPROC,        10      },
    { "p11",    OPRD_COPROC,        11      },
    { "p12",    OPRD_COPROC,        12      },
    { "p13",    OPRD_COPROC,        13      },
    { "p14",    OPRD_COPROC,        14      },
    { "p15",    OPRD_COPROC,        15      },
    { "p2",     OPRD_COPROC,        2       },
    { "p3",     OPRD_COPROC,        3       },
    { "p4",     OPRD_COPROC,        4       },
    { "p5",     OPRD_COPROC,        5       },
    { "p6",     OPRD_COPROC,        6       },
    { "p7",     OPRD_COPROC,        7       },
    { "p8",     OPRD_COPROC,        8       },
    { "p9",     OPRD_COPROC,        9       },
    { "pc",     OPRD_REG,           15      },
    { "r0",     OPRD_REG,           0       },
    { "r1",     OPRD_REG,           1       },
    { "r10",    OPRD_REG,           10      },
    { "r11",    OPRD_REG,           11      },
    { "r12",    OPRD_REG,           12      },
    { "r13",    OPRD_REG,           13      },
    { "r14",    OPRD_REG,           14      },
    { "r15",    OPRD_REG,           15      },
    { "r2",     OPRD_REG,           2       },
    { "r3",     OPRD_REG,           3       },
    { "r4",     OPRD_REG,           4       },
    { "r5",     OPRD_REG,           5       },
    { "r6",     OPRD_REG,           6       },
    { "r7",     OPRD_REG,           7       },
    { "r8",     OPRD_REG,           8       },
    { "r9",     OPRD_REG,           9       },
    { "ror",    OPRD_LSL_LIKE,      3 << 5  },
    { "rrx",    OPRD_RRX,           3 << 5  },
    { "s0",     OPRD_REG_S,         0       },
    { "s1",     OPRD_REG_S,         1       },
    { "s10",    OPRD_REG_S,         10      },
    { "s11",    OPRD_REG_S,         11      },
    { "s12",    OPRD_REG_S,         12      },
    { "s13",    OPRD_REG_S,         13      },
    { "s14",    OPRD_REG_S,         14      },
    { "s15",    OPRD_REG_S,         15      },
    { "s16",    OPRD_REG_S,         16      },
    { "s17",    OPRD_REG_S,         17      },
    { "s18",    OPRD_REG_S,         18      },
    { "s19",    OPRD_REG_S,         19      },
    { "s2",     OPRD_REG_S,         2       },
    { "s20",    OPRD_REG_S,         20      },
    { "s21",    OPRD_REG_S,         21      },
    { "s22",    OPRD_REG_S,         22      },
    { "s23",    OPRD_REG_S,         23      },
    { "s24",    OPRD_REG_S,         24      },
    { "s25",    OPRD_REG_S,         25      },
    { "s26",    OPRD_REG_S,         26      },
    { "s27",    OPRD_REG_S,         27      },
    { "s28",    OPRD_REG_S,         28      },
    { "s29",    OPRD_REG_S,         29      },
    { "s3",     OPRD_REG_S,         3       },
    { "s30",    OPRD_REG_S,         30      },
    { "s31",    OPRD_REG_S,         31      },
    { "s3",     OPRD_REG_S,         3       },
    { "s4",     OPRD_REG_S,         4       },
    { "s5",     OPRD_REG_S,         5       },
    { "s6",     OPRD_REG_S,         6       },
    { "s7",     OPRD_REG_S,         7       },
    { "s8",     OPRD_REG_S,         8       },
    { "s9",     OPRD_REG_S,         9       },
    { "sb",     OPRD_REG,           9       },
    { "sl",     OPRD_REG,           10      },
    { "sp",     OPRD_REG,           13      },
    { "spsr",   OPRD_PSR,           1 << 22 },
    { "v1",     OPRD_REG,           4       },
    { "v2",     OPRD_REG,           5       },
    { "v3",     OPRD_REG,           6       },
    { "v4",     OPRD_REG,           7       },
    { "v5",     OPRD_REG,           8       },
    { "v6",     OPRD_REG,           9       },
    { "v7",     OPRD_REG,           10      },
    { "v8",     OPRD_REG,           11      },
    { "wr",     OPRD_REG,           7       }
};

int arm_reserved_word_count = sizeof(arm_reserved_word_info) /
    sizeof(struct arm_reserved_word_info);

/* ----------------------------------------------------------------------------
 *   Uninteresting machine-dependent boilerplate code 
 * ------------------------------------------------------------------------- */

const cpu_type_t md_cputype = CPU_TYPE_ARM;
const cpu_type_t md_cpusubtype = 6;
const enum byte_sex md_target_byte_sex = LITTLE_ENDIAN_BYTE_SEX;

const char md_comment_chars[] = "@";
const char md_line_comment_chars[] = "#";
const char md_EXP_CHARS[] = "eE";
const char md_FLT_CHARS[] = "dDfF";

const pseudo_typeS md_pseudo_table[] = {
    { "arm", s_ignore, 0 },         /* we don't support Thumb */
    { "code", s_ignore, 0 },        /* ditto */
    { NULL, 0, 0 }
};

const relax_typeS md_relax_table[0];

int md_parse_option(char **argP, int *cntP, char ***vecP)
{
    return 0;
}

void md_begin()
{
}

void md_end()
{
}

char *md_atof(int type, char *litP, int *sizeP)
{
    return "md_atof: TODO";
}

int md_estimate_size_before_relax(fragS *fragP, int segment_type)
{
    as_fatal("relaxation shouldn't occur right now on the ARM");
    return 0;
}

void md_convert_frag(fragS *fragP)
{
    as_fatal("relaxation shouldn't occur right now on the ARM");
}

/* Simply writes out a number in little endian form. */
void md_number_to_chars(char *buf, signed_expr_t val, int n)
{
    number_to_chars_littleendian(buf, val, n);
}

/* ----------------------------------------------------------------------------
 *   Utility routines
 * ------------------------------------------------------------------------- */

/* Pass NULL for the 'error' pointer in order to have the assembler complain if
 * the immediate didn't fit. */
unsigned int generate_shifted_immediate(unsigned int n, unsigned int *error)
{
    unsigned int k = 0, m;

    if (error)
        *error = 0;

    for (k = 0; k < 32; k += 2) {
        m = ROTL(n, k);

#if 0
        if (k != 0)
            fprintf(stderr, "rotating %d by %d to make %d\n", n, k, m);
#endif

        if (m <= 0xff)
            return (((k / 2) << 8) | m);
    }

    if (error)
        *error = 1;
    else
        as_bad("immediate value (%d) too large", n);

    return 0;
}

unsigned int vfp_encode_reg_list(unsigned int list, int precision)
{
    unsigned int enc = 0, reg_count = 0, first_reg = 0;

    if (!list) {
        as_bad("Register list must specify at least one register");
        return 0;
    }

    /* Shift the list until we find the first reg. */
    while ((list & 1) == 0) {
        list >>= 1;
        first_reg++;
    }

    /* Shift until we get to a zero. */
    while (list & 1) {
        list >>= 1;
        reg_count++;
    }

    /* Make sure the rest are zero. */
    if (list) {
        as_bad("Register list must describe a consecutive sequence");
        return 0;
    }

    switch (precision) {
        case VFP_SINGLE:
            enc |= ((first_reg >> 1) << 12);
            enc |= ((first_reg & 1) << 22);
            enc |= reg_count;
            break;
        case VFP_DOUBLE:
            enc |= (first_reg << 12);
            enc |= (reg_count * 2);
    }

    return enc;
}

/* ----------------------------------------------------------------------------
 *   Lexical analysis 
 * ------------------------------------------------------------------------- */

int arm_op_info_compare(const void *strp, const void *infop)
{
    char *str;
    struct arm_op_info *info;

    str = (char *)strp; info = (struct arm_op_info *)infop;

    return strcasecmp(str, info->name);
}

int arm_reserved_word_info_compare(const void *strp, const void *infop)
{
    char *str;
    struct arm_reserved_word_info *info;

    str = (char *)strp; info = (struct arm_reserved_word_info *)infop;

    return strcasecmp(str, info->name);
}

int yylex()
{
    char *ptr, *tok, *tok2;
    int bail, flags[3], i;
    long long n;
    size_t sz;
    struct arm_op_info *info;
    struct arm_reserved_word_info *rinfo, *rinfo2;

    /* eat initial whitespace */
    while (isspace(*input_line_pointer) && *input_line_pointer != '\n')
        input_line_pointer++;

    ptr = input_line_pointer;
    if (!*ptr)
        return 0;

    if (parsing_op) {
        while (isalnum(*ptr))
            *ptr++;

        sz = ptr - input_line_pointer;
        tok = (char *)malloc(sz + 1);
        strncpy(tok, input_line_pointer, sz);
        tok[sz] = '\0';

        if (!(info = bsearch(tok, arm_op_info, arm_op_count, sizeof(struct
            arm_op_info), arm_op_info_compare))) {
            as_bad("Unknown instruction '%s'", tok);
            free(tok);
            return 0;
        }

        free(tok);
        parsing_op = 0;
        input_line_pointer = (*ptr ? ptr + 1 : ptr);

        yylval.nval = info->encoding;
        return info->token;
    }

    /* Lex the operand. */

    /* If it's a number, return OPRD_IMM. */
    if (isdigit(*ptr) || *ptr == '+' || *ptr == '-') {
        n = strtoll(input_line_pointer, &ptr, 0);

        /* '+' and '-' are actually special cases. They have a separate meaning
         * when by themselves (e.g. in '..., -r1'). If they are by themselves,
         * strtoll(3) will fail and we will catch them below. */
        if (ptr != input_line_pointer) {
            /* If 'f' or 'b' immediately follows, it's a local label, not a
             * number. Hand it off to the expression parser. */
            if (*ptr == 'f' || *ptr == 'b') {
                yylval.eval = calloc(sizeof(expressionS), 1);
                expression(yylval.eval);
                return OPRD_EXP;
            }

            if (n < 0)
                yylval.ival = (int)n;
            else
                yylval.nval = (unsigned int)n;

            input_line_pointer = ptr;
            return OPRD_IMM;
        }
    }

    /* If it's a special punctuation mark, return it. */ 
    if (strchr("#[]{},!+-|^", *ptr))
        return *(input_line_pointer++);

    /* If it's an identifier, check whether it's a reserved word. */
    if (isalpha(*ptr) || *ptr == '_') {
        while (isalnum(*ptr) || *ptr == '_')
            *ptr++;

        sz = ptr - input_line_pointer;
        tok = (char *)malloc(sz + 1);
        strncpy(tok, input_line_pointer, sz);
        tok[sz] = '\0';

        if ((rinfo = bsearch(tok, arm_reserved_word_info,
            arm_reserved_word_count, sizeof(struct arm_reserved_word_info),
            arm_reserved_word_info_compare))) {
            free(tok);
            input_line_pointer = ptr;

            yylval.nval = rinfo->lval;
            return rinfo->token;
        }

        /* Identifiers that consist of just the characters "aif" in any order
         * and with at most one of each are reserved words (specifically, ARMv6
         * coprocessor iflags). */
        if (sz <= 3) {
            bail = 0;
            memset(flags, '\0', sizeof(flags));

            for (i = 0; i < sz; i++)
                switch (tok[i]) {
                    case 'a': case 'A': flags[0]++; break;
                    case 'f': case 'F': flags[1]++; break;
                    case 'i': case 'I': flags[2]++; break;
                    default:            bail = 1;   break;
                }

            if (!bail && flags[0] <= 1 && flags[1] <= 1 && flags[2] <= 1) {
                input_line_pointer += sz;
                yylval.nval = ((flags[0] << 8) | (flags[1] << 7) | (flags[2] <<
                    6));
                return OPRD_IFLAGS;
            }
        }

        /* Identifiers that consist of "[cs]psr_[cxsf]+" are reserved words,
         * used in ARMv3 MSR instructions. */
        if (!strncasecmp(tok, "cpsr_", 5) || !strncasecmp(tok, "spsr_", 5)) {
            n = 0;

            tok2 = tok + 5;
            if (!strcasecmp(tok2, "all"))
                n = ((1 << 16) | (1 << 17) | (1 << 18) | (1 << 19));
            else
                while (*tok2) {
                    switch (*tok2) {
                        case 'c': case 'C': n |= (1 << 16); break;
                        case 'x': case 'X': n |= (1 << 17); break;
                        case 's': case 'S': n |= (1 << 18); break;
                        case 'f': case 'F': n |= (1 << 19);
                    }
                    tok2++;
                }

            if (tok[0] == 's' || tok[0] == 'S')
                n |= (1 << 22);

            free(tok);

            input_line_pointer = ptr;
            yylval.nval = n;
            return OPRD_PSR;
        }

        /* The "LSLK hack": constructions like "asl r0" are collapsed by
         * the dumb GAS parser into "aslr0". We need to parse these as their
         * constituent reserved words, not as one identifier. */
        /* FIXME: this shit is deprecated now that we've fixed app: remove
         * this */
        if (sz == 5 || sz == 6) {
            tok2 = strdup(tok + 3);
            tok[3] = '\0';
        
            if ((rinfo = bsearch(tok, arm_reserved_word_info,
                arm_reserved_word_count, sizeof(struct arm_reserved_word_info),
                arm_reserved_word_info_compare)) &&
                (rinfo2 = bsearch(tok2, arm_reserved_word_info,
                arm_reserved_word_count, sizeof(struct arm_reserved_word_info),
                arm_reserved_word_info_compare)) &&
                (rinfo->token == OPRD_LSL_LIKE || rinfo->token ==
                    OPRD_RRX) &&
                rinfo2->token == OPRD_REG) {
                free(tok);
                free(tok2);

                input_line_pointer += 3;    /* scan the register next */

                yylval.nval = rinfo->lval;
                return OPRD_LSL_LIKE;
            }

            free(tok2);
        }

        free(tok);
    }

    /* We don't know what it is. Give it to the expression parser and let it
     * sort it out. */
    yylval.eval = calloc(sizeof(expressionS), 1);
    expression(yylval.eval);
    return OPRD_EXP;
}

/* ----------------------------------------------------------------------------
 *   Tokenizing and parsing 
 * ------------------------------------------------------------------------- */

struct fix_info this_fix;

void register_reloc_type(int type, int size, int pcrel)
{
    this_fix.type = type;
    this_fix.size = size;
    this_fix.pcrel = pcrel;

    this_fix.needed = 1;
}

void register_expression(expressionS *expr)
{
    this_fix.expr = expr;
    this_fix.needed = 1;
}

int yyerror(char *err)
{
    as_bad("%s", err);
    return 0;
}

void md_assemble(char *str)
{
    unsigned int encoded;
    char *this_frag;

    memset(&this_fix, '\0', sizeof(struct fix_info));

#if 0
    fprintf(stderr, "assembling: %s\n", str); 
    yydebug = 1;
#endif

    input_line_pointer = str;
    parsing_op = 1;
    encoded = yyparse();

    this_frag = frag_more(4);
    md_number_to_chars(this_frag, instruction, 4);

    if (this_fix.needed) {
        /* fprintf(stderr, "generating fix: %d\n", this_fix.type); */
        fix_new(frag_now, this_frag - frag_now->fr_literal, 4,
            this_fix.expr->X_add_symbol, this_fix.expr->X_subtract_symbol,
            this_fix.expr->X_add_number, this_fix.pcrel,
            ARM_RELOC_IS_EXPORTABLE(this_fix.type), this_fix.type);
    }
}

/* ----------------------------------------------------------------------------
 *   Relocation 
 * ------------------------------------------------------------------------- */

/* Assumes 32-bit n. */
void fill_reloc_value(unsigned char *buf, unsigned int n, unsigned int mask)
{
    mask = ~mask;

    buf[0] = (buf[0] & mask);
    buf[1] = (buf[1] & (mask >> 8));
    buf[2] = (buf[2] & (mask >> 16));
    buf[3] = (buf[3] & (mask >> 24));

    buf[0] = (buf[0] | n);
    buf[1] = (buf[1] | (n >> 8)); 
    buf[2] = (buf[2] | (n >> 16)); 
    buf[3] = (buf[3] | (n >> 24)); 
} 

void md_number_to_imm(unsigned char *buf, signed_expr_t val, int size, fixS *
    fixP, int nsect)
{
    unsigned int n = 0;

    switch (fixP->fx_r_type) {
        case ARM_RELOC_VANILLA:
        case NO_RELOC:
            switch (size) {
                case 4:
                    *(buf++) = val;
                    *(buf++) = (val >> 8);
                    *(buf++) = (val >> 16);
                    *(buf++) = (val >> 24);
                    break;
                case 2:
                    *(buf++) = val;
                    *(buf++) = (val >> 8);
                    break;
                case 1:
                    *(buf++) = val;
            }
            break;

        case ARM_RELOC_PCREL_DATA_IMM12:
            val -= 4;
            if (val < 0)
                val = -val;
            else
                n = (1 << 23);  /* set U bit */
            assert(val < (1 << 12) && val > 0);
            n |= val;
            fill_reloc_value(buf, n, (1 << 23) | ((1 << 12) - 1));
            break;

        case ARM_RELOC_PCREL_VFP_IMM8_TIMES_4:
            val -= 4;
            val /= 4;
            if (val < 0)
                val = -val;
            else
                n = (1 << 23);  /* set U bit */
            assert(val < (1 << 8) && val > 0);
            n |= val;
            fill_reloc_value(buf, n, (1 << 23) | ((1 << 8) - 1));
            break;

        case ARM_RELOC_PCREL_IMM24:
            val -= 4;
            val >>= 2;
            n = ((unsigned int)val) & 0x00ffffff;
            fill_reloc_value(buf, n, 0x00ffffff);
            break;

        case ARM_RELOC_SHIFT_IMM12:
            n = generate_shifted_immediate(val, NULL);
            fill_reloc_value(buf, (unsigned int)n, 0x00000fff); 
            break;

        case ARM_RELOC_SHIFT_IMM:
            if (val == 32)
                val = 0;
            n = ((unsigned int)val) & 31;
            fill_reloc_value(buf, n << 7, 31 << 7);
            break;

        default:
            fprintf(stderr, "reloc type %d\n", fixP->fx_r_type);
            as_fatal("md_number_to_imm: reloc unimplemented");
    }
}


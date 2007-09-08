#ifndef ARM_H
#define ARM_H

#include <stdio.h>

#include "expr.h"
#include "struc-symbol.h"
#include "mach-o/arm/reloc.h"

#define VFP_SINGLE  1
#define VFP_DOUBLE  2

#define ROTL(n, k)  (((n) << (k)) | ((n) >> (32 - (k))))

struct fix_info {
    int needed;

    int type;
    int size;
    int pcrel;

    expressionS *expr;
};

struct arm_op_info {
    char *name;
    int token;
    unsigned int encoding;
};

struct arm_reserved_word_info {
    char *name;
    int token;
    unsigned int lval;
};

extern char *cur_ptr;
extern unsigned int instruction;
extern int yydebug;

extern int arm_op_count;
extern struct arm_op_info arm_op_info[]; 

unsigned int vfp_encode_reg_list(unsigned int list, int precision);

unsigned int generate_shifted_immediate(unsigned int n, unsigned int *error);
void register_reloc_type(int type, int size, int pcrel);
void register_expression(expressionS *expr);

int yyparse();
int yyerror(char *err);
int yylex();
void yyrestart(FILE *f);

#endif


%{
/* ----------------------------------------------------------------------------
 *   iphone-binutils: development tools for the Apple iPhone       07/18/2007
 *   Copyright (c) 2007 Patrick Walton <pcwalton@uchicago.edu> but freely
 *   redistributable under the terms of the GNU General Public License v2.
 *
 *   army.y - the parser for ARM assembly
 * ------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/arm/reloc.h>

#include "arm.h"
#include "messages.h"
#include "struc-symbol.h"

#define YYDEBUG         1
#define YYERROR_VERBOSE 1

unsigned int instruction;
%}

%union {
    unsigned int nval;
    signed int ival; 
    expressionS *eval;
}

%token <nval> OPRD_REG
%token <ival> OPRD_IMM
%token <nval> OP_BRANCH OP_DATA_PROC_1 OP_DATA_PROC_2 OP_DATA_PROC_3 OP_MUL
%token <nval> OP_MLA OP_SMLAL OP_CLZ OP_LDR OP_LDRH OP_LDM OP_SWI OP_BKPT
%token <nval> OP_CPS_EFFECT OP_CPS OP_LDREX OP_MCRR2 OP_PKHBT OP_QADD16 OP_REV
%token <nval> OP_RFE OP_SXTAH OP_SEL OP_SETEND OP_SMLAD OP_SMLALD OP_SMMUL
%token <nval> OP_SRS OP_SSAT OP_SSAT16 OP_STREX OP_SXTH OP_USAD8 OP_USADA8
%token <nval> OP_BX OP_PKHTB OP_USAT OP_USAT16 OP_BLX OP_SMLA_XY OP_SMLAL_XY 
%token <nval> OP_SMUL_XY OP_QADD OP_NOP OP_VFP_DP_S OP_VFP_DP_D OP_VFP_DPX_S
%token <nval> OP_VFP_DPX_D OP_VFP_STM_S OP_VFP_STM_D OP_VFP_STM_X OP_VFP_ST_S
%token <nval> OP_VFP_ST_D OP_VFP_MSR OP_VFP_MRS OP_VFP_MDXR OP_VFP_MRDX
%token <nval> OP_VFP_MXR OP_VFP_MRX OP_VFP_FMSTAT OP_VFP_DPX1_S OP_VFP_DPX1_D
%token <nval> OP_VFP_FMDRR OP_VFP_FMRRD OP_VFP_FMSRR OP_VFP_FMRRS OP_VFP_DPX_SD
%token <nval> OP_VFP_DPX_DS OP_MSR OP_MRS OP_LDC
%token <nval> OPRD_LSL_LIKE OPRD_RRX OPRD_IFLAGS OPRD_COPROC OPRD_CR OPRD_REG_S
%token <nval> OPRD_REG_D OPRD_REG_VFP_SYS OPRD_ENDIANNESS OPRD_PSR
%token <nval> OPRD_COPRO_REG
%token <eval> OPRD_EXP
%type  <ival> expr
%type  <nval> inst branch_inst data_inst load_inst load_mult_inst maybe_bang 
%type  <nval> reg_list src_reg dest_reg shifter_operand load_am branch_am
%type  <nval> exception_inst multiply_inst maybe_am_lsl_subclause
%type  <nval> load_am_indexed reg_lists reg_list_atom reg_list_contents
%type  <nval> maybe_hat maybe_imm_rotation misc_ls_am imm_with_u_bit
%type  <nval> misc_ls_am_index shifter_imm shifter_operand_lsl_clause
%type  <nval> shifter_operand_lsl_arg load_am_sign fundamental_inst armv6_inst
%type  <nval> cps_class_inst ldrex_class_inst mcrr2_class_inst pkhbt_class_inst
%type  <nval> qadd16_class_inst rev_class_inst rfe_class_inst sxtah_class_inst
%type  <nval> sel_class_inst setend_class_inst smlad_class_inst
%type  <nval> smlald_class_inst smmul_class_inst srs_class_inst ssat_class_inst
%type  <nval> strex_class_inst sxth_class_inst usad8_class_inst armv4t_inst
%type  <nval> bx_class_inst armv5_inst blx_class_inst smla_xy_class_inst
%type  <nval> smlal_xy_class_inst smul_xy_class_inst qadd_class_inst
%type  <nval> mnemonic_inst vfp_inst vfp_Sd vfp_Sn vfp_Sm vfp_Dd vfp_Dn vfp_Dm
%type  <nval> vfp_store_multiple_inst vfp_register_transfer_inst
%type  <nval> vfp_maybe_imm_offset generic_reg vfp_data_proc_inst
%type  <nval> vfp_store_inst vfp_misc_inst vfp2_inst vfp_imm_offset_with_u_bit
%type  <nval> vfp_store_am armv3_inst clz_class_inst armv2_inst
%type  <nval> load_store_copro_am imm_div_4_with_u_bit

%%

inst:
      fundamental_inst  { instruction = $1; }
    | armv2_inst        { instruction = $1; }
    | armv3_inst        { instruction = $1; }
    | armv4t_inst       { instruction = $1; }
    | armv5_inst        { instruction = $1; }
    | armv6_inst        { instruction = $1; }
    | vfp_inst          { instruction = $1; }
    | vfp2_inst         { instruction = $1; }
    ;

fundamental_inst:
      branch_inst       { $$ = $1; }
    | data_inst         { $$ = $1; }
    | load_inst         { $$ = $1; }
    | load_mult_inst    { $$ = $1; }
    | exception_inst    { $$ = $1; }
    | multiply_inst     { $$ = $1; }
    | mnemonic_inst     { $$ = $1; }
    ;

branch_inst:
      OP_BRANCH branch_am   { $$ = ($1 | $2); }
    ;

data_inst:
      OP_DATA_PROC_1 dest_reg ',' shifter_operand   { $$ = ($1 | $2 | $4); }
    | OP_DATA_PROC_2 src_reg ',' shifter_operand
        { $$ = ($1 | $2 | $4 | (1 << 20)); }
    | OP_DATA_PROC_3 dest_reg ',' src_reg ',' shifter_operand
        { $$ = ($1 | $2 | $4 | $6); }
    ;

load_inst:
      OP_LDR dest_reg ',' load_am
        {
            unsigned int n;
            n = ($1 | (1 << 26) | $2 | $4);
            if ($1 && ((n >> 24) & 0xf) == 0x5 && (n & 0x0fff) == 0) {
                /* if T is set and immediate operand is 0, then convert into
                 * a post-indexed instruction */
                n &= ~(1 << 24);    /* clear 24th bit */
                n |= (1 << 23);     /* set U bit */
            }
            $$ = n;
        }
    | OP_LDRH dest_reg ',' misc_ls_am   { $$ = ($1 | $2 | $4); }
    ; 

load_mult_inst:
      OP_LDM src_reg maybe_bang ',' reg_lists maybe_hat
        { $$ = ((1 << 27) | $1 | $2 | $3 | $5 | $6); }
    ;

exception_inst:
      OP_BKPT OPRD_IMM  { $$ = ($1 | (($2 & 0xfff0) << 8) | ($2 & 0x000f)); }
    | OP_SWI OPRD_IMM   { $$ = ($1 | $2); }
    ;

multiply_inst:
      OP_MUL OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 16) | $4 | ($6 << 8)); }
    | OP_MLA OPRD_REG ',' OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 16) | $4 | ($6 << 8) | ($8 << 12)); }
    | OP_SMLAL OPRD_REG ',' OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 12) | ($4 << 16) | $6 | ($8 << 8)); }
    ;

mnemonic_inst:
      OP_NOP    { $$ = $1; }
    ; 

maybe_hat:
      /* empty */   { $$ = 0;           }
    | '^'           { $$ = (1 << 22);   }
    ;

maybe_bang:
    /* empty */     { $$ = 0; }
    | '!'           { $$ = (0x1 << 21); }
    ;

reg_lists:
      reg_list                                  { $$ = $1;          }
    | reg_lists plus_or_bar reg_list            { $$ = ($1 | $3);   }
    ;

plus_or_bar:
      '+'
    | '|'
    ;

reg_list:
      '{' reg_list_contents '}'     { $$ = $2; }
    | OPRD_IMM                      { $$ = $1; }

reg_list_contents:
      /* empty */                           { $$ = 0;           }
    | reg_list_atom                         { $$ = $1;          }
    | reg_list_contents ',' reg_list_atom   { $$ = ($1 | $3);   }
    ;

reg_list_atom:
      generic_reg                   { $$ = (1 << $1);   }
    | generic_reg '-' generic_reg   {
                                        int i;
                                        unsigned int n = 0;
                                        for (i = $1; i <= $3; i++)
                                            n |= (1 << i);
                                        $$ = n;
                                    }
    ;

generic_reg:
      OPRD_REG      { $$ = $1; }
    | OPRD_REG_S    { $$ = $1; }
    | OPRD_REG_D    { $$ = $1; }
    ;

src_reg:
      OPRD_REG      { $$ = ($1 << 16); }
    ;

dest_reg:
      OPRD_REG      { $$ = ($1 << 12); }
    ;

shifter_operand:
      '#' shifter_imm   { $$ = $2; }
    | OPRD_REG ',' shifter_operand_lsl_clause   { $$ = ($1 | $3); }
    | OPRD_REG  { $$ = $1; }
    ;

shifter_operand_lsl_clause:
      OPRD_LSL_LIKE shifter_operand_lsl_arg { $$ = ($1 | $2); }
    | OPRD_RRX { $$ = $1; }
    ;

shifter_operand_lsl_arg:
      '#' OPRD_IMM
        {
            unsigned int n = $2;
            if (n == 32)
                n = 0;
            if (n >= (1 << 5))
                as_bad("immediate value (%d) too large", $2);
            $$ = (n << 7); 
        }
    | '#' expr
        {
            register_reloc_type(ARM_RELOC_SHIFT_IMM, 4, 0);
            $$ = 0;
        }
    | OPRD_REG  { $$ = ((1 << 4) | ($1 << 8)); }
    ;

shifter_imm:
      OPRD_IMM maybe_imm_rotation
        {
            unsigned int err = 0;

            if ($1 > 0xff || $1 < 0) {
                $$ = ((0x1 << 25) | generate_shifted_immediate($1, &err));
                if (err) {
                    $$ = ((0x1 << 25) | generate_shifted_immediate(~$1, &err)
                        | (0x3 << 21));
                    if (!err)
                        as_warn("Immediate value is out of range: converting "
                            "automatically to a MVN instruction, but if this "
                            "was not a MOV instruction then this is unsafe!");
                    else
                        as_bad("Immediate value out of range");
                }
            } else
                $$ = ((0x1 << 25) | $1 | $2);
        }
    | expr
        {
            register_reloc_type(ARM_RELOC_SHIFT_IMM12, 4, 0);
            $$ = ((0x1 << 25) | $1);
        }
    ;

maybe_imm_rotation:
      /* empty */       { $$ = 0;               }
    | ',' OPRD_IMM      { $$ = (($2 / 2) << 8); }
    ;

misc_ls_am:
      '[' src_reg ',' misc_ls_am_index ']' maybe_bang
        { $$ = ((1 << 24) | (1 << 7) | (1 << 4) | $2 | $4 | $6); }
    | '[' src_reg ']' ',' misc_ls_am_index
        { $$ = ($2 | $5); }
    | '[' src_reg ']'
        { $$ = ((1 << 24) | (1 << 22) | (1 << 23) | $2); }
    ;

misc_ls_am_index:
      '#' imm_with_u_bit
        {
            $$ = ((1 << 22) | ((($2 & 0xf0) >> 4) << 8) | ($2 & 0x0f) |
                ($2 & (1 << 23)));
        }
    | load_am_sign OPRD_REG
        { $$ = ((1 << 7) | (1 << 4) | $1 | $2); }
    ;

load_am_sign:
      /* empty */   { $$ = (1 << 23); }
    | '+'           { $$ = (1 << 23); }
    | '-'           { $$ = (0 << 23); }
    ;

imm_with_u_bit:
      OPRD_IMM      { $$ = ($1 < 0 ? -$1 : ((1 << 23) | $1)); }
    ;

load_am:
      expr
        {
            /* assumes PC-relative addressing */
            int n;
            n = $1 - 8;
            register_reloc_type(ARM_RELOC_PCREL_DATA_IMM12, 4, 1);
            $$ = ((1 << 26) | (1 << 24) | (15 << 16) |
                (n < 0 ? -n : (n | (1 << 23)))); 
        }
    | '[' OPRD_REG ',' load_am_indexed ']' maybe_bang
        {
            $$ = ((1 << 26) | (1 << 24) | ($2 << 16) | $4 | $6);
        }
    | '[' OPRD_REG ']' ',' load_am_indexed
        {
            $$ = ((1 << 26) | ($2 << 16) | $5);
        }
    | '[' OPRD_REG ']'
        {
            $$ = ((1 << 26) | (1 << 24) | (1 << 23) | ($2 << 16));
        }
    ;

load_am_indexed:
      '#' OPRD_IMM { $$ = ($2 < 0 ? -$2 : ($2 | (1 << 23))); }
    | load_am_sign OPRD_REG maybe_am_lsl_subclause
        {
            $$ = ($1 | $2 | $3 | (1 << 25));
        }
    ;

maybe_am_lsl_subclause:
      /* empty */                       {   $$ = 0;                 }
    | ',' OPRD_LSL_LIKE '#' OPRD_IMM
        {
            unsigned int n = $4;
            if (n == 32)
                n = 0;
            if (n >= (1 << 5))
                as_bad("immediate value (%d) too large", $4);
            $$ = ($2 | (n << 7));
        }
    | ',' OPRD_LSL_LIKE '#' expr
        {
            register_reloc_type(ARM_RELOC_SHIFT_IMM, 4, 0);
            $$ = $2;
        }
    ;

branch_am:
      expr
        {
            register_reloc_type(ARM_RELOC_PCREL_IMM24, 4, 1);
            $$ = $1;
        }
    ;

expr:
      OPRD_EXP  { register_expression($1); $$ = $1->X_add_number;  }
    ;

armv2_inst:
      OP_LDC OPRD_COPROC ',' OPRD_COPRO_REG ',' load_store_copro_am
        { $$ = ($1 | ($2 << 8) | ($4 << 12) | $6); }
    ;

armv3_inst:
      OP_MSR OPRD_PSR ',' '#' shifter_imm  { $$ = ($1 | $2 | $5 | (1 << 25)); }
    | OP_MSR OPRD_PSR ',' OPRD_REG  { $$ = ($1 | $2 | $4); }
    | OP_MRS dest_reg ',' OPRD_PSR  { $$ = ($1 | $2 | $4); }
    ;

armv4t_inst:
      bx_class_inst     { $$ = $1; }
    ;

bx_class_inst:
      OP_BX OPRD_REG    { $$ = ($1 | $2); }
    ;

armv5_inst:
      blx_class_inst        { $$ = $1; }
    | smla_xy_class_inst    { $$ = $1; }
    | smlal_xy_class_inst   { $$ = $1; }
    | smul_xy_class_inst    { $$ = $1; }
    | qadd_class_inst       { $$ = $1; }
    | clz_class_inst        { $$ = $1; }
    ;

clz_class_inst:
      OP_CLZ OPRD_REG ',' OPRD_REG  { $$ = ($1 | ($2 << 12) | $4); }
    ;

blx_class_inst:
      OP_BLX branch_am  { $$ = ((0x7d << 25) | $2); }
    | OP_BLX OPRD_REG   { $$ = ($1 | (0x12 << 20) | (0xfff3 << 4) | $2); }
    ;

smla_xy_class_inst:
      OP_SMLA_XY OPRD_REG ',' OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 16) | $4 | ($6 << 8) | ($8 << 12)); }
    ;

smlal_xy_class_inst:
      OP_SMLAL_XY OPRD_REG ',' OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 12) | ($4 << 16) | $6 | ($8 << 8)); }
    ;

smul_xy_class_inst:
      OP_SMUL_XY OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 16) | $4 | ($6 << 8)); }
    ;

qadd_class_inst:
      OP_QADD dest_reg ',' OPRD_REG ',' src_reg
        { $$ = ($1 | $2 | $4 | $6); }
    ;

armv6_inst:
      cps_class_inst    { $$ = $1; }
    | ldrex_class_inst  { $$ = $1; }
    | mcrr2_class_inst  { $$ = $1; }
    | pkhbt_class_inst  { $$ = $1; }
    | qadd16_class_inst { $$ = $1; }
    | rev_class_inst    { $$ = $1; }
    | rfe_class_inst    { $$ = $1; }
    | sxtah_class_inst  { $$ = $1; }
    | sel_class_inst    { $$ = $1; }
    | setend_class_inst { $$ = $1; }
    | smlad_class_inst  { $$ = $1; }
    | smlald_class_inst { $$ = $1; }
    | smmul_class_inst  { $$ = $1; }
    | srs_class_inst    { $$ = $1; }
    | ssat_class_inst   { $$ = $1; }
    | strex_class_inst  { $$ = $1; }
    | sxth_class_inst   { $$ = $1; }
    | usad8_class_inst  { $$ = $1; }
    ; 

cps_class_inst:
      OP_CPS_EFFECT OPRD_IFLAGS ',' '#' OPRD_IMM
        { $$ = ($1 | $2 | (1 << 17) | $5); }
    | OP_CPS_EFFECT OPRD_IFLAGS     { $$ = ($1 | $2); }
    | OP_CPS '#' OPRD_IMM   { $$ = ($1 | (1 << 17) | $3); }
    ;

ldrex_class_inst:
      OP_LDREX dest_reg ',' '[' src_reg ']' { $$ = ($1 | $2 | $5); }
    ;

mcrr2_class_inst:
      OP_MCRR2 OPRD_COPROC ',' OPRD_IMM ',' dest_reg ',' src_reg ',' OPRD_CR
        { $$ = ($1 | ($2 << 8) | ($4 << 4) | $6 | $8 | $10); }
    ;

pkhbt_class_inst:
      OP_PKHBT dest_reg ',' src_reg ',' OPRD_REG ',' OPRD_LSL_LIKE '#' OPRD_IMM
        { $$ = ($1 | $2 | $4 | $6 | ($10 << 7)); }
    | OP_PKHTB dest_reg ',' OPRD_REG ',' OPRD_REG ',' OPRD_LSL_LIKE '#' OPRD_IMM
        { $$ = ($1 | $2 | ($4 << 16) | $6 | ($10 << 7)); }
    | OP_PKHBT dest_reg ',' src_reg ',' OPRD_REG
        { $$ = ($1 | $2 | $4 | $6); }
    | OP_PKHTB dest_reg ',' OPRD_REG ',' OPRD_REG
        { $$ = (($1 & ~(1 << 6)) | $2 | $4 | ($6 << 16)); }
    ;

qadd16_class_inst:
      OP_QADD16 dest_reg ',' src_reg ',' OPRD_REG
        { $$ = ($1 | $2 | $4 | $6); }
    ;

rev_class_inst:
      OP_REV dest_reg ',' OPRD_REG  { $$ = ($1 | $2 | $4); }
    ;

rfe_class_inst:
      OP_RFE src_reg '!'    { $$ = ($1 | $2 | (1 << 21)); }
    | OP_RFE src_reg        { $$ = ($1 | $2 | (0 << 21)); }
    ;

sxtah_class_inst:
      OP_SXTAH dest_reg ',' src_reg ',' OPRD_REG ',' OPRD_LSL_LIKE '#' OPRD_IMM
        { $$ = ($1 | $2 | $4 | $6 | (($10 / 8) << 10)); }
    | OP_SXTAH dest_reg ',' src_reg ',' OPRD_REG
        { $$ = ($1 | $2 | $4 | $6); }
    ;

sel_class_inst:
      OP_SEL dest_reg ',' src_reg ',' OPRD_REG  { $$ = ($1 | $2 | $4 | $6); }
    ;

setend_class_inst:
      OP_SETEND OPRD_ENDIANNESS { $$ = ($1 | $2); }
    ;

smlad_class_inst:
      OP_SMLAD OPRD_REG ',' OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 16) | $4 | ($6 << 8) | ($8 << 12)); }
    ;

smlald_class_inst:
      OP_SMLALD OPRD_REG ',' OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 12) | ($4 << 16) | $6 | ($8 << 8)); }
    ;

smmul_class_inst:
      OP_SMMUL OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 16) | $4 | ($6 << 8)); }
    ;

srs_class_inst:
      OP_SRS '#' OPRD_IMM '!'   { $$ = ($1 | $3 | (1 << 21)); }
    | OP_SRS '#' OPRD_IMM   { $$ = ($1 | $3); }
    ;

ssat_class_inst:
      OP_SSAT dest_reg ',' '#' OPRD_IMM ',' OPRD_REG ',' OPRD_LSL_LIKE '#'
        OPRD_IMM
        { $$ = ($1 | $2 | (($5 - 1) << 16) | $7 | $9 | ($11 << 7)); }
    | OP_SSAT dest_reg ',' '#' OPRD_IMM ',' OPRD_REG
        { $$ = ($1 | $2 | (($5 - 1) << 16) | $7); }
    | OP_SSAT16 dest_reg ',' '#' OPRD_IMM ',' OPRD_REG
        { $$ = ($1 | $2 | (($5 - 1) << 16) | $7); }
    | OP_USAT dest_reg ',' '#' OPRD_IMM ',' OPRD_REG ',' OPRD_LSL_LIKE '#'
        OPRD_IMM
        { $$ = ($1 | $2 | (($5 - 0) << 16) | $7 | $9 | ($11 << 7)); }
    | OP_USAT dest_reg ',' '#' OPRD_IMM ',' OPRD_REG
        { $$ = ($1 | $2 | (($5 - 0) << 16) | $7); }
    | OP_USAT16 dest_reg ',' '#' OPRD_IMM ',' OPRD_REG
        { $$ = ($1 | $2 | (($5 - 0) << 16) | $7); }
    ;

strex_class_inst:
      OP_STREX dest_reg ',' OPRD_REG ',' '[' src_reg ']'
        { $$ = ($1 | $2 | $4 | $7); }
    ;

sxth_class_inst:
      OP_SXTH dest_reg ',' OPRD_REG ',' OPRD_LSL_LIKE '#' OPRD_IMM 
        { $$ = ($1 | $2 | $4 | (($8 / 8) << 10)); }
    | OP_SXTH dest_reg ',' OPRD_REG { $$ = ($1 | $2 | $4); }
    ;

usad8_class_inst:
      OP_USAD8 OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 16) | $4 | ($6 << 8)); }
    | OP_USADA8 OPRD_REG ',' OPRD_REG ',' OPRD_REG ',' OPRD_REG
        { $$ = ($1 | ($2 << 16) | $4 | ($6 << 8) | ($8 << 12)); }
    ;

load_store_copro_am:
      '[' OPRD_REG ',' '#' imm_div_4_with_u_bit ']' maybe_bang
        { $$ = ((1 << 24) | ($2 << 16) | $5 | $7); }
    | '[' OPRD_REG ']' ',' '#' imm_div_4_with_u_bit
        { $$ = ((0 << 24) | (1 << 21) | ($2 << 16) | $6); }
    | '[' OPRD_REG ']' ',' '{' OPRD_IMM '}'
        { $$ = ((0 << 24) | (1 << 23) | (0 << 21) | ($2 << 16) | $6); }
    ;

imm_div_4_with_u_bit:
      OPRD_IMM      { $$ = ($1 < 0 ? -($1 / 4) : ((1 << 23) | ($1 / 4))); }
    ;

vfp_inst:
      vfp_data_proc_inst            { $$ = $1; }
    | vfp_store_multiple_inst       { $$ = $1; }
    | vfp_store_inst                { $$ = $1; }
    | vfp_register_transfer_inst    { $$ = $1; }
    | vfp_misc_inst                 { $$ = $1; }
    ;

vfp_data_proc_inst:
      OP_VFP_DP_S vfp_Sd ',' vfp_Sn ',' vfp_Sm  { $$ = ($1 | $2 | $4 | $6); }
    | OP_VFP_DP_D vfp_Dd ',' vfp_Dn ',' vfp_Dm  { $$ = ($1 | $2 | $4 | $6); }
    | OP_VFP_DPX_S vfp_Sd ',' vfp_Sm            { $$ = ($1 | $2 | $4);      }
    | OP_VFP_DPX_D vfp_Dd ',' vfp_Dm            { $$ = ($1 | $2 | $4);      }
    | OP_VFP_DPX_SD vfp_Sd ',' vfp_Dm           { $$ = ($1 | $2 | $4);      }
    | OP_VFP_DPX_DS vfp_Dd ',' vfp_Sm           { $$ = ($1 | $2 | $4);      }
    | OP_VFP_DPX1_S vfp_Sd                      { $$ = ($1 | $2);           }
    | OP_VFP_DPX1_D vfp_Dd                      { $$ = ($1 | $2);           }
    ;

vfp_Sd:
      OPRD_REG_S    { $$ = (((($1 & ~1) >> 1) << 12) | (($1 & 1) << 22)); }
    ;

vfp_Sn:
      OPRD_REG_S    { $$ = (((($1 & ~1) >> 1) << 16) | (($1 & 1) << 7)); }
    ;

vfp_Sm:
      OPRD_REG_S    { $$ = ((($1 & ~1) >> 1) | (($1 & 1) << 5)); }
    ;

vfp_Dd:
      OPRD_REG_D    { $$ = ($1 << 12); }
    ;

vfp_Dn:
      OPRD_REG_D    { $$ = ($1 << 16); }
    ;

vfp_Dm:
      OPRD_REG_D    { $$ = $1; }
    ;

vfp_store_multiple_inst:
      OP_VFP_STM_S src_reg maybe_bang ',' reg_list
        { $$ = ($1 | $2 | $3 | vfp_encode_reg_list($5, VFP_SINGLE)); }
    | OP_VFP_STM_D src_reg maybe_bang ',' reg_list
        { $$ = ($1 | $2 | $3 | vfp_encode_reg_list($5, VFP_DOUBLE)); }
    | OP_VFP_STM_X src_reg maybe_bang ',' reg_list
        { $$ = ($1 | $2 | $3 | (vfp_encode_reg_list($5, VFP_DOUBLE) + 1)); }
    ;

vfp_store_inst:
      OP_VFP_ST_S vfp_Sd ',' vfp_store_am 
        { $$ = ($1 | $2 | $4); }
    | OP_VFP_ST_D vfp_Dd ',' vfp_store_am 
        { $$ = ($1 | $2 | $4); }
    ;

vfp_store_am:
      expr
        {
            /* assumes PC-relative addressing */
            int n;
            n = ($1 - 8) / 4;
            register_reloc_type(ARM_RELOC_PCREL_VFP_IMM8_TIMES_4, 4, 1);
            $$ = ((15 << 16) | (n < 0 ? -n : (n | (1 << 23))));
        }
    | '[' src_reg vfp_maybe_imm_offset ']'  { $$ = ($2 | $3); }
    ;

vfp_maybe_imm_offset:
      /* empty */                       { $$ = 0; }
    | ',' '#' vfp_imm_offset_with_u_bit { $$ = $3; }
    ;

vfp_imm_offset_with_u_bit:
      OPRD_IMM      { $$ = ($1 < 0 ? -($1 / 4) : ((1 << 23) | ($1 / 4))); }
    ;

vfp_register_transfer_inst:
      OP_VFP_MSR vfp_Sn ',' dest_reg    { $$ = ($1 | $2 | $4); }
    | OP_VFP_MRS dest_reg ',' vfp_Sn    { $$ = ($1 | $2 | $4); }
    | OP_VFP_MDXR vfp_Dn ',' dest_reg   { $$ = ($1 | $2 | $4); }
    | OP_VFP_MRDX dest_reg ',' vfp_Dn   { $$ = ($1 | $2 | $4); }
    | OP_VFP_MXR OPRD_REG_VFP_SYS ',' dest_reg { $$ = ($1 | ($2 << 16) | $4); }
    | OP_VFP_MRX dest_reg ',' OPRD_REG_VFP_SYS { $$ = ($1 | $2 | ($4 << 16)); }
    ;

vfp_misc_inst:
      OP_VFP_FMSTAT { $$ = $1; }
    ;

vfp2_inst:
      OP_VFP_FMDRR vfp_Dm ',' dest_reg ',' src_reg
        { $$ = ($1 | $2 | $4 | $6); }
    | OP_VFP_FMRRD dest_reg ',' src_reg ',' vfp_Dm
        { $$ = ($1 | $2 | $4 | $6); }
    | OP_VFP_FMSRR '{' vfp_Sm ',' vfp_Sm '}' ',' dest_reg ',' src_reg
        { $$ = ($1 | $3 | $8 | $10); /* TODO: verify that Sm1 = Sm+1 */ }
    | OP_VFP_FMRRS dest_reg ',' src_reg ',' '{' vfp_Sm ',' vfp_Sm '}'
        { $$ = ($1 | $2 | $4 | $7);  /* TODO: ditto */                  }
    ;

%%


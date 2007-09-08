/* ----------------------------------------------------------------------------
 *   iphone-binutils: development tools for the Apple iPhone       07/18/2007
 *   Copyright (c) 2007 Patrick Walton <pcwalton@uchicago.edu> but freely
 *   redistributable under the terms of the GNU General Public License v2.
 *
 *   mach-o/arm/reloc.h - relocation information for the ARM 
 * ------------------------------------------------------------------------- */

#ifndef MACH_O_ARM_H
#define MACH_O_ARM_H 

enum reloc_type_arm
{
    ARM_RELOC_VANILLA,          /* generic relocation */
    ARM_RELOC_PAIR,             /* second entry of a pair */
    ARM_RELOC_SECTDIFF,
    ARM_RELOC_LOCAL_SECTDIFF,
    ARM_RELOC_PB_LA_PTR,
    ARM_RELOC_PCREL_IMM24,      /* signed branch offset */
    ARM_RELOC_UNKNOWN,
    ARM_RELOC_PCREL_DATA_IMM12, /* Load and Store Word/Immediate Offset, r15 */
    ARM_RELOC_SHIFT_IMM12,      /* Data-processing operands - Immediate */
    ARM_RELOC_PCREL_VFP_IMM8_TIMES_4,   /* VFP Load and Store Word, r15 */
    ARM_RELOC_SHIFT_IMM         /* immediate shifter operand */
};

/* Determines whether a reloc can be exported to object files (1) or whether
 * it's purely for assembler-internal use (0). */
#define ARM_RELOC_IS_EXPORTABLE(n)  ((n) < ARM_RELOC_PCREL_DATA_IMM12)

#endif


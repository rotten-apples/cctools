/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#import <architecture/byte_order.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <mach-o/ranlib.h>

extern void swap_fat_header(
    struct fat_header *fat_header,
    enum NXByteOrder target_byte_order);

extern void swap_fat_arch(
    struct fat_arch *fat_archs,
    unsigned long nfat_arch,
    enum NXByteOrder target_byte_order);

extern void swap_mach_header(
    struct mach_header *mh,
    enum NXByteOrder target_byte_order);

extern void swap_load_command(
    struct load_command *lc,
    enum NXByteOrder target_byte_order);

extern void swap_segment_command(
    struct segment_command *sg,
    enum NXByteOrder target_byte_order);

extern void swap_section(
    struct section *s,
    unsigned long nsects,
    enum NXByteOrder target_byte_order);

extern void swap_symtab_command(
    struct symtab_command *st,
    enum NXByteOrder target_byte_order);

extern void swap_dysymtab_command(
    struct dysymtab_command *dyst,
    enum NXByteOrder target_byte_sex);

extern void swap_symseg_command(
    struct symseg_command *ss,
    enum NXByteOrder target_byte_order);

extern void swap_fvmlib_command(
    struct fvmlib_command *fl,
    enum NXByteOrder target_byte_order);

extern void swap_dylib_command(
    struct dylib_command *dl,
    enum NXByteOrder target_byte_sex);

extern void swap_sub_framework_command(
    struct sub_framework_command *sub,
    enum NXByteOrder target_byte_sex);

extern void swap_sub_umbrella_command(
    struct sub_umbrella_command *usub,
    enum NXByteOrder target_byte_sex);

extern void swap_sub_client_command(
    struct sub_client_command *csub,
    enum NXByteOrder target_byte_sex);

extern void swap_prebound_dylib_command(
    struct prebound_dylib_command *pbdylib,
    enum NXByteOrder target_byte_sex);

extern void swap_dylinker_command(
    struct dylinker_command *dyld,
    enum NXByteOrder target_byte_sex);

extern void swap_fvmfile_command(
    struct fvmfile_command *ff,
    enum NXByteOrder target_byte_order);

extern void swap_thread_command(
    struct thread_command *ut,
    enum NXByteOrder target_byte_order);

extern void swap_ident_command(
    struct ident_command *ident,
    enum NXByteOrder target_byte_order);

extern void swap_nlist(
    struct nlist *symbols,
    unsigned long nsymbols,
    enum NXByteOrder target_byte_order);

extern void swap_ranlib(
    struct ranlib *ranlibs,
    unsigned long nranlibs,
    enum NXByteOrder target_byte_order);

extern void swap_relocation_info(
    struct relocation_info *relocs,
    unsigned long nrelocs,
    enum NXByteOrder target_byte_order);

extern void swap_indirect_symbols(
    unsigned long *indirect_symbols,
    unsigned long nindirect_symbols,
    enum NXByteOrder target_byte_sex);

extern void swap_dylib_reference(
    struct dylib_reference *refs,  
    unsigned long nrefs,
    enum NXByteOrder target_byte_sex);

extern void swap_dylib_module(  
    struct dylib_module *mods,
    unsigned long nmods, 
    enum NXByteOrder target_byte_sex);

extern void swap_dylib_table_of_contents(
    struct dylib_table_of_contents *tocs,
    unsigned long ntocs,
    enum NXByteOrder target_byte_sex);





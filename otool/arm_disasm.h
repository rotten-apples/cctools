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

#include "stuff/target_arch.h"
#import <stuff/bytesex.h>
#import <mach-o/reloc.h>
#import <mach-o/nlist.h>
#import <stuff/bool.h>
#include "stuff/symbol.h"

extern unsigned long arm_disassemble(
    char *sect,
    unsigned long left,
    unsigned long addr,
    unsigned long sect_addr,
    enum byte_sex object_byte_sex,
    struct relocation_info *sorted_relocs,
    unsigned long nsorted_relocs,
    nlist_t *symbols,
    unsigned long nsymbols,
    struct symbol *sorted_symbols,
    unsigned long nsorted_symbols,
    char *strings,
    unsigned long strings_size,
    unsigned long *indirect_symbols,
    unsigned long nindirect_symbols,
    mach_header_t *mh,
    struct load_command *load_commands,
    enum bool verbose);

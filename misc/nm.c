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
/*	$OpenBSD: nm.c,v 1.4 1997/01/15 23:42:59 millert Exp $	*/
/*	$NetBSD: nm.c,v 1.7 1996/01/14 23:04:03 pk Exp $	*/

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Hans Huebner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * The NeXT Computer, Inc. nm(1) program that handles fat files, archives and
 * Mach-O objects files (no BSD a.out files).  A few lines of code were taken
 * and adapted from the BSD release.
 *
 * When processing multiple files which are archives the BSD version of nm
 * would only print the archive member name (without the -o option) of the
 * object files before printing the symbols.  This version of nm will print the
 * archive name with the member name in ()'s in this case which makes it clear
 * which symbols belong to which arguments in the case that multiple arguments
 * are archives and have members of the same name.
 *
 * To allow the "-arch <arch_flag>" command line argument the processing of
 * command line arguments was changed to allow the options to be specified
 * in more than one group of arguments with each group preceded by a '-'.  This
 * change in behavior would only be noticed if a command line of the form
 * "nm -n -Q" was used where the BSD version would open a file of the name
 * "-Q" to process.  To do this with this version of nm the new command line
 * argument "-" would be used to treat all remaining arguments as file names.
 * So the equivalent command would be "nm -n - -Q".  This should not be a
 * problem as the BSD would treat the command "nm -Q" by saying "-Q" is an
 * invalid argument which was slightly inconsistant.
 */
#include <mach/mach.h> /* first so to get rid of a precomp warning */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/stab.h>
#include "stuff/bool.h"
#include "stuff/ofile.h"
#include "stuff/errors.h"
#include "stuff/allocate.h"
#include "stuff/guess_short_name.h"

/* used by error routines as the name of the program */
char *progname = NULL;

/* flags set from the command line arguments */
struct cmd_flags {
    unsigned long nfiles;
    enum bool a;	/* print all symbol table entries including stabs */
    enum bool g;	/* print only global symbols */
    enum bool n;	/* sort numericly rather than alphabetically */
    enum bool o;	/* prepend file or archive element name to each line */
    enum bool p;	/* don't sort; print in symbol table order */
    enum bool r;	/* sort in reverse direction */
    enum bool u;	/* print only undefined symbols */
    enum bool m;	/* print symbol in Mach-O symbol format */
    enum bool x;	/* print the symbol table entry in hex and the name */
    enum bool j;	/* just print the symbol name (no value or type) */
    enum bool s;	/* print only symbol in the following section */
    char *segname,	/*  segment name for -s */
	 *sectname;	/*  section name for -s */
    enum bool l;	/* print a .section_start symbol if none exists (-s) */
    enum bool f;	/* print a dynamic shared library flat */
    enum bool v;	/* sort and print by value diffences ,used with -n -s */
    enum bool b;	/* print only stabs for the following include */
    char *bincl_name;	/*  the begin include name for -b */
    enum bool i;	/* start searching for begin include at -iN index */
    unsigned long index;/*  the index to start searching at */
};
/* These need to be static because of the qsort compare function */
static struct cmd_flags cmd_flags = { 0 };
static char *strings = NULL;
static unsigned long strsize = 0;

/* flags set by processing a specific object file */
struct process_flags {
    unsigned long nsect;	/* The nsect, address and size for the */
    unsigned long sect_addr,	/*  section specified by the -s flag */
	     sect_size;
    enum bool sect_start_symbol;/* For processing the -l flag, set if a */
				/*  symbol with the start address of the */
				/*  section is found */
    unsigned long nsects;	/* For printing the symbol types, the number */
    struct section **sections;	/*  of sections and an array of section ptrs */
    unsigned char text_nsect,	/* For printing symbols types, T, D, and B */
		  data_nsect,	/*  for text, data and bss symbols */
		  bss_nsect;
    unsigned long nlibs;	/* For printing the twolevel namespace */
    char **lib_names;		/*  references types, the number of libraries */
				/*  an array of pointers to library names */
};
struct value_diff {
    unsigned long size;
    struct nlist symbol;
};

static void usage(
    void);
static void nm(
    struct ofile *ofile,
    char *arch_name,
    void *cookie);
static struct nlist *select_symbols(
    struct ofile *ofile,
    struct symtab_command *st,
    struct dysymtab_command *dyst,
    struct cmd_flags *cmd_flags,
    struct process_flags *process_flags,
    unsigned long *nsymbols);
static enum bool select_symbol(
    struct nlist *symbol,
    struct cmd_flags *cmd_flags,
    struct process_flags *process_flags);
static void print_mach_symbols(
    struct ofile *ofile,
    struct nlist *symbols,
    unsigned long nsymbols,
    char *strings,
    unsigned long strsize,
    struct cmd_flags *cmd_flags,
    struct process_flags *process_flags,
    char *arch_name);
static void print_symbols(
    struct ofile *ofile,
    struct nlist *symbols,
    unsigned long nsymbols,
    char *strings,
    unsigned long strsize,
    struct cmd_flags *cmd_flags,
    struct process_flags *process_flags,
    char *arch_name,
    struct value_diff *value_diffs);
static char * stab(
    unsigned char n_type);
static int compare(
    struct nlist *p1,
    struct nlist *p2);
static int value_diff_compare(
    struct value_diff *p1,
    struct value_diff *p2);

int
main(
int argc,
char **argv,
char **envp)
{
    int i;
    unsigned long j;
    struct arch_flag *arch_flags;
    unsigned long narch_flags;
    enum bool all_archs;
    char **files;

	progname = argv[0];

	arch_flags = NULL;
	narch_flags = 0;
	all_archs = FALSE;

	cmd_flags.nfiles = 0;
	cmd_flags.a = FALSE;
	cmd_flags.g = FALSE;
	cmd_flags.n = FALSE;
	cmd_flags.o = FALSE;
	cmd_flags.p = FALSE;
	cmd_flags.r = FALSE;
	cmd_flags.u = FALSE;
	cmd_flags.m = FALSE;
	cmd_flags.x = FALSE;
	cmd_flags.j = FALSE;
	cmd_flags.s = FALSE;
	cmd_flags.segname = NULL;
	cmd_flags.sectname = NULL;
	cmd_flags.l = FALSE;
	cmd_flags.f = FALSE;
	cmd_flags.bincl_name = NULL;

        files = allocate(sizeof(char *) * argc);
	for(i = 1; i < argc; i++){
	    if(argv[i][0] == '-'){
		if(argv[i][1] == '\0'){
		    for( ; i < argc; i++)
			files[cmd_flags.nfiles++] = argv[i];
		    break;
		}
		if(strcmp(argv[i], "-arch") == 0){
		    if(i + 1 == argc){
			error("missing argument(s) to %s option", argv[i]);
			usage();
		    }
		    if(strcmp("all", argv[i+1]) == 0){
			all_archs = TRUE;
		    }
		    else{
			arch_flags = reallocate(arch_flags,
				(narch_flags + 1) * sizeof(struct arch_flag));
			if(get_arch_from_flag(argv[i+1],
					      arch_flags + narch_flags) == 0){
			    error("unknown architecture specification flag: "
				  "%s %s", argv[i], argv[i+1]);
			    arch_usage();
			    usage();
			}
			narch_flags++;
		    }
		    i++;
		}
		else{
		    for(j = 1; argv[i][j] != '\0'; j++){
			switch(argv[i][j]){
			case 'a':
			    cmd_flags.a = TRUE;
			    break;
			case 'g':
			    cmd_flags.g = TRUE;
			    break;
			case 'n':
			    cmd_flags.n = TRUE;
			    break;
			case 'o':
			    cmd_flags.o = TRUE;
			    break;
			case 'p':
			    cmd_flags.p = TRUE;
			    break;
			case 'r':
			    cmd_flags.r = TRUE;
			    break;
			case 'u':
			    cmd_flags.u = TRUE;
			    break;
			case 'm':
			    cmd_flags.m = TRUE;
			    break;
			case 'x':
			    cmd_flags.x = TRUE;
			    break;
			case 'j':
			    cmd_flags.j = TRUE;
			    break;
			case 's':
			    if(cmd_flags.s == TRUE){
				error("more than one -s option specified");
				usage();
			    }
			    cmd_flags.s = TRUE;
			    break;
			case 'b':
			    if(cmd_flags.b == TRUE){
				error("more than one -b option specified");
				usage();
			    }
			    cmd_flags.b = TRUE;
			    break;
			case 'i':
			    if(cmd_flags.i == TRUE){
				error("more than one -i option specified");
				usage();
			    }
			    cmd_flags.i = TRUE;
			    while(isdigit(argv[i][j+1])){
				cmd_flags.index =  cmd_flags.index * 10 +
						   (argv[i][j+1] - '0');
				j++;
			    }
			case 'l':
			    cmd_flags.l = TRUE;
			    break;
			case 'f':
			    cmd_flags.f = TRUE;
			    break;
			case 'v':
			    cmd_flags.v = TRUE;
			    break;
			default:
			    error("invalid argument -%c", argv[i][j]);
			    usage();
			}
		    }
		    if(cmd_flags.s == TRUE && cmd_flags.segname == NULL){
			if(i + 2 == argc){
			    error("missing arguments to -s");
			    usage();
			}
			cmd_flags.segname  = argv[i+1];
			cmd_flags.sectname = argv[i+2];
			i += 2;
		    }
		    if(cmd_flags.b == TRUE && cmd_flags.bincl_name == NULL){
			if(i + 1 == argc){
			    error("missing arguments to -b");
			    usage();
			}
			cmd_flags.bincl_name = argv[i+1];
			i += 1;
		    }
		}
		continue;
	    }
	    files[cmd_flags.nfiles++] = argv[i];
	}

	for(j = 0; j < cmd_flags.nfiles; j++)
	    ofile_process(files[j], arch_flags, narch_flags, all_archs, FALSE,
			  cmd_flags.f, TRUE, nm, &cmd_flags);
	if(cmd_flags.nfiles == 0)
	    ofile_process("a.out",  arch_flags, narch_flags, all_archs, FALSE,
			  cmd_flags.f, TRUE, nm, &cmd_flags);

	if(errors == 0)
	    return(EXIT_SUCCESS);
	else
	    return(EXIT_FAILURE);
}

/*
 * usage() prints the current usage message and exits indicating failure.
 */
static
void
usage(
void)
{
	fprintf(stderr, "Usage: %s [-agnoprumxjl[s segname sectname] [-] "
		"[[-arch <arch_flag>] ...] [file ...]\n", progname);
	exit(EXIT_FAILURE);
}

/*
 * nm() is the routine that gets called by ofile_process() to process single
 * object files.
 */
static
void
nm(
struct ofile *ofile,
char *arch_name,
void *cookie)
{
    struct cmd_flags *cmd_flags;
    struct process_flags process_flags;
    unsigned long i, j, k;
    struct load_command *lc;
    struct symtab_command *st;
    struct dysymtab_command *dyst;
    struct segment_command *sg;
    struct section *s;
    struct dylib_command *dl;

    struct nlist *symbols;
    unsigned long nsymbols;
    struct value_diff *value_diffs;

    char *short_name, *has_suffix;
    enum bool is_framework;

	cmd_flags = (struct cmd_flags *)cookie;

	process_flags.nsect = -1;
	process_flags.sect_addr = 0;
	process_flags.sect_size = 0;
	process_flags.sect_start_symbol = FALSE;
	process_flags.nsects = 0;
	process_flags.sections = NULL;
	process_flags.text_nsect = NO_SECT;
	process_flags.data_nsect = NO_SECT;
	process_flags.bss_nsect = NO_SECT;
	process_flags.nlibs = 0;
	process_flags.lib_names = NULL;

	st = NULL;
	dyst = NULL;
	lc = ofile->load_commands;
	for(i = 0; i < ofile->mh->ncmds; i++){
	    if(st == NULL && lc->cmd == LC_SYMTAB){
		st = (struct symtab_command *)lc;
	    }
	    else if(dyst == NULL && lc->cmd == LC_DYSYMTAB){
		dyst = (struct dysymtab_command *)lc;
	    }
	    else if(lc->cmd == LC_SEGMENT){
		sg = (struct segment_command *)lc;
		process_flags.nsects += sg->nsects;
	    }
	    else if((ofile->mh->flags & MH_TWOLEVEL) == MH_TWOLEVEL &&
		    (lc->cmd == LC_LOAD_DYLIB ||
		     lc->cmd == LC_LOAD_WEAK_DYLIB)){
		process_flags.nlibs++;
	    }
	    lc = (struct load_command *)((char *)lc + lc->cmdsize);
	}
	if(st == NULL || st->nsyms == 0){
	    error("no name list");
	    return;
	}
	if(process_flags.nsects > 0){
	    process_flags.sections = (struct section **)
		       malloc(sizeof(struct section *) * process_flags.nsects);
	    k = 0;
	    lc = ofile->load_commands;
	    for (i = 0; i < ofile->mh->ncmds; i++){
		if(lc->cmd == LC_SEGMENT){
		    sg = (struct segment_command *)lc;
		    s = (struct section *)
			  ((char *)sg + sizeof(struct segment_command));
		    for(j = 0; j < sg->nsects; j++){
			if(strcmp((s + j)->sectname, SECT_TEXT) == 0 &&
			   strcmp((s + j)->segname, SEG_TEXT) == 0)
			    process_flags.text_nsect = k + 1;
			else if(strcmp((s + j)->sectname, SECT_DATA) == 0 &&
				strcmp((s + j)->segname, SEG_DATA) == 0)
			    process_flags.data_nsect = k + 1;
			else if(strcmp((s + j)->sectname, SECT_BSS) == 0 &&
				strcmp((s + j)->segname, SEG_DATA) == 0)
			    process_flags.bss_nsect = k + 1;
			if(cmd_flags->segname != NULL){
			    if(strncmp((s + j)->sectname, cmd_flags->sectname,
				       sizeof(s->sectname)) == 0 &&
			       strncmp((s + j)->segname, cmd_flags->segname,
				       sizeof(s->segname)) == 0){
				process_flags.nsect = k + 1;
				process_flags.sect_addr = (s + j)->addr;
				process_flags.sect_size = (s + j)->size;
			    }
			}
			process_flags.sections[k++] = s + j;
		    }
		}
		lc = (struct load_command *)
		      ((char *)lc + lc->cmdsize);
	    }
	}
	if((ofile->mh->flags & MH_TWOLEVEL) == MH_TWOLEVEL &&
	   process_flags.nlibs > 0){
	    process_flags.lib_names = (char **)
		       malloc(sizeof(char *) * process_flags.nlibs);
	    j = 0;
	    lc = ofile->load_commands;
	    for (i = 0; i < ofile->mh->ncmds; i++){
		if(lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB){
		    dl = (struct dylib_command *)lc;
		    process_flags.lib_names[j] =
			(char *)dl + dl->dylib.name.offset;
		    short_name = guess_short_name(process_flags.lib_names[j],
						  &is_framework, &has_suffix);
		    if(short_name != NULL)
			process_flags.lib_names[j] = short_name;
		    j++;
		}
		lc = (struct load_command *)
		      ((char *)lc + lc->cmdsize);
	    }
	}

	/* select symbols to print */
	symbols = select_symbols(ofile, st, dyst, cmd_flags, &process_flags,
				 &nsymbols);

	/* set names in the symbols to be printed */
	strings = ofile->object_addr + st->stroff;
	strsize = st->strsize;
	if(cmd_flags->x == FALSE){
	    for(i = 0; i < nsymbols; i++){
		if(symbols[i].n_un.n_strx == 0)
		    symbols[i].n_un.n_name = "";
		else if(symbols[i].n_un.n_strx < 0 ||
			(unsigned long)symbols[i].n_un.n_strx > st->strsize)
		    symbols[i].n_un.n_name = "bad string index";
		else
		    symbols[i].n_un.n_name = symbols[i].n_un.n_strx + strings;

		if((symbols[i].n_type & N_STAB) == 0 &&
		   (symbols[i].n_type & N_TYPE) == N_INDR){
		    if(symbols[i].n_value == 0)
			symbols[i].n_value = (long)"";
		    else if(symbols[i].n_value > st->strsize)
			symbols[i].n_value = (long)"bad string index";
		    else
			symbols[i].n_value =
				    (long)(symbols[i].n_value + strings);
		}
	    }
	    if(cmd_flags->l == TRUE &&
	       (long)process_flags.nsect != -1 &&
	       process_flags.sect_start_symbol == FALSE &&
	       process_flags.sect_size != 0){
		symbols = reallocate(symbols,(nsymbols+1)*sizeof(struct nlist));
		symbols[nsymbols].n_un.n_name = ".section_start";
		symbols[nsymbols].n_type = N_SECT;
		symbols[nsymbols].n_sect = process_flags.nsect;
		symbols[nsymbols].n_value = process_flags.sect_addr;
		nsymbols++;
	    }
	}

	/* print header if needed */
	if((ofile->member_ar_hdr != NULL ||
	    ofile->dylib_module_name != NULL ||
	    cmd_flags->nfiles > 1 ||
	    arch_name != NULL) &&
	    cmd_flags->o == FALSE){
	    if(ofile->dylib_module_name != NULL){
		printf("\n%s(%s)", ofile->file_name, ofile->dylib_module_name);
	    }
	    else if(ofile->member_ar_hdr != NULL){
		printf("\n%s(%.*s)", ofile->file_name,
		       (int)ofile->member_name_size, ofile->member_name);
	    }
	    else
		printf("\n%s", ofile->file_name);
	    if(arch_name != NULL)
		printf(" (for architecture %s):\n", arch_name);
	    else
		printf(":\n");
	}

	/* sort the symbols if needed */
	if(cmd_flags->p == FALSE && cmd_flags->b == FALSE)
	    qsort(symbols, nsymbols, sizeof(struct nlist),
		  (int (*)(const void *, const void *))compare);

	value_diffs = NULL;
	if(cmd_flags->v == TRUE && cmd_flags->n == TRUE &&
	   cmd_flags->r == FALSE && cmd_flags->s == TRUE &&
	   nsymbols != 0){
	    value_diffs = allocate(sizeof(struct value_diff) * nsymbols);
	    for(i = 0; i < nsymbols - 1; i++){
		value_diffs[i].symbol = symbols[i];
		value_diffs[i].size = symbols[i+1].n_value - symbols[i].n_value;
	    }
	    value_diffs[i].symbol = symbols[i];
	    value_diffs[i].size =
		process_flags.sect_addr + process_flags.sect_size -
		symbols[i].n_value;
	    qsort(value_diffs, nsymbols, sizeof(struct value_diff), 
		  (int (*)(const void *, const void *))value_diff_compare);
	    for(i = 0; i < nsymbols; i++)
		symbols[i] = value_diffs[i].symbol;
	}

	/* now print the symbols as specified by the flags */
	if(cmd_flags->m == TRUE)
	    print_mach_symbols(ofile, symbols, nsymbols, strings, st->strsize,
			       cmd_flags, &process_flags, arch_name);
	else
	    print_symbols(ofile, symbols, nsymbols, strings, st->strsize,
			  cmd_flags, &process_flags, arch_name, value_diffs);

	free(symbols);
	if(process_flags.sections != NULL)
	    free(process_flags.sections);
}

/*
 * select_symbols returns an allocated array of nlist structs as the symbols
 * that are to be printed based on the flags.  The number of symbols in the
 * array returned in returned indirectly through nsymbols.
 */
static
struct nlist *
select_symbols(
struct ofile *ofile,
struct symtab_command *st,
struct dysymtab_command *dyst,
struct cmd_flags *cmd_flags,
struct process_flags *process_flags,
unsigned long *nsymbols)
{
    unsigned long i, flags, nest;
    struct nlist *all_symbols, *selected_symbols, undefined;
    struct dylib_module m;
    struct dylib_reference *refs;
    enum bool found;

	all_symbols = (struct nlist *)(ofile->object_addr + st->symoff);
	selected_symbols = allocate(sizeof(struct nlist) * st->nsyms);
	*nsymbols = 0;

	if(ofile->object_byte_sex != get_host_byte_sex())
	    swap_nlist(all_symbols, st->nsyms, get_host_byte_sex());

	if(ofile->dylib_module != NULL){
	    m = *ofile->dylib_module;
	    refs = (struct dylib_reference *)(ofile->object_addr +
					      dyst->extrefsymoff);
	    if(ofile->object_byte_sex != get_host_byte_sex()){
		swap_dylib_module(&m, 1, get_host_byte_sex());
		swap_dylib_reference(refs + m.irefsym, m.nrefsym,
				     get_host_byte_sex());
	    }
	    for(i = 0; i < m.nrefsym; i++){
		flags = refs[i + m.irefsym].flags;
		if(flags == REFERENCE_FLAG_UNDEFINED_NON_LAZY ||
		   flags == REFERENCE_FLAG_UNDEFINED_LAZY ||
		   flags == REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY ||
		   flags == REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY){
		    undefined = all_symbols[refs[i + m.irefsym].isym];
		    if(flags == REFERENCE_FLAG_UNDEFINED_NON_LAZY ||
		       flags == REFERENCE_FLAG_UNDEFINED_LAZY ||
		       cmd_flags->m == TRUE)
			undefined.n_type = N_UNDF | N_EXT;
		    else
			undefined.n_type = N_UNDF;
		    undefined.n_desc = (undefined.n_desc &~ REFERENCE_TYPE) |
				       flags;
		    undefined.n_value = 0;
		    if(select_symbol(&undefined, cmd_flags, process_flags))
			selected_symbols[(*nsymbols)++] = undefined;
		}
	    }
	    for(i = 0; i < m.nextdefsym && m.iextdefsym + i < st->nsyms; i++){
		if(select_symbol(all_symbols + (m.iextdefsym + i), cmd_flags,
				 process_flags))
		    selected_symbols[(*nsymbols)++] =
			all_symbols[m.iextdefsym + i];
	    }
	    for(i = 0; i < m.nlocalsym && m.ilocalsym + i < st->nsyms; i++){
		if(select_symbol(all_symbols + (m.ilocalsym + i), cmd_flags,
				 process_flags))
		    selected_symbols[(*nsymbols)++] =
			all_symbols[m.ilocalsym + i];
	    }
	}
	else if(cmd_flags->b == TRUE){
	    found = FALSE;
	    strings = ofile->object_addr + st->stroff;
	    if(cmd_flags->i == TRUE)
		i = cmd_flags->index;
	    else
		i = 0;
	    for( ; i < st->nsyms; i++){
		if(all_symbols[i].n_type == N_BINCL &&
		   all_symbols[i].n_un.n_strx != 0 &&
		   (unsigned long)all_symbols[i].n_un.n_strx < st->strsize &&
		   strcmp(cmd_flags->bincl_name,
			  strings + all_symbols[i].n_un.n_strx) == 0){
		    selected_symbols[(*nsymbols)++] = all_symbols[i];
		    found = TRUE;
		    nest = 0;
		    for(i = i + 1 ; i < st->nsyms; i++){
			if(all_symbols[i].n_type == N_BINCL)
			    nest++;
			else if(all_symbols[i].n_type == N_EINCL){
			    if(nest == 0){
				selected_symbols[(*nsymbols)++] =
						all_symbols[i];
				break;
			    }
			    nest--;
			}
			else if(nest == 0)
			    selected_symbols[(*nsymbols)++] = all_symbols[i];
		    }
		}
		if(found == TRUE)
		    break;
	    }
	}
	else{
	    for(i = 0; i < st->nsyms; i++){
		if(select_symbol(all_symbols + i, cmd_flags, process_flags))
		    selected_symbols[(*nsymbols)++] = all_symbols[i];
	    }
	}
	if(ofile->object_byte_sex != get_host_byte_sex())
	    swap_nlist(all_symbols, st->nsyms, ofile->object_byte_sex);
	/*
	 * Could reallocate selected symbols to the exact size but it is more
	 * of a time waste than a memory savings.
	 */
	return(selected_symbols);
}

/*
 * select_symbol() returns TRUE or FALSE if the specified symbol is to be
 * printed based on the flags.
 */
static
enum bool
select_symbol(
struct nlist *symbol,
struct cmd_flags *cmd_flags,
struct process_flags *process_flags)
{
	if(cmd_flags->u == TRUE){
	    if((symbol->n_type == (N_UNDF | N_EXT) && symbol->n_value == 0) ||
	       symbol->n_type == (N_PBUD | N_EXT))
		return(TRUE);
	    else
		return(FALSE);
	}
	if(cmd_flags->g == TRUE && (symbol->n_type & N_EXT) == 0)
	    return(FALSE);
	if(cmd_flags->s == TRUE){
	    if(((symbol->n_type & N_TYPE) == N_SECT) &&
		(symbol->n_sect == process_flags->nsect)){
		if(cmd_flags->l &&
		   symbol->n_value == process_flags->sect_addr){
		    process_flags->sect_start_symbol = TRUE;
		}
	    }
	    else
		return(FALSE);
	}
	if((symbol->n_type & N_STAB) &&
	   (cmd_flags->a == FALSE || cmd_flags->g == TRUE ||
	    cmd_flags->u == TRUE))
		return(FALSE);
	return(TRUE);
}

/*
 * print_mach_symbols() is called when the -m flag is specified and prints
 * symbols in the extended Mach-O style format.
 */
static
void
print_mach_symbols(
struct ofile *ofile,
struct nlist *symbols,
unsigned long nsymbols,
char *strings,
unsigned long strsize,
struct cmd_flags *cmd_flags,
struct process_flags *process_flags,
char *arch_name)
{
    unsigned long i, library_ordinal;

	for(i = 0; i < nsymbols; i++){
	    if(cmd_flags->x == TRUE){
		printf("%08lx %02x %02x %04x ", symbols[i].n_value,
		       (unsigned int)(symbols[i].n_type & 0xff),
		       (unsigned int)(symbols[i].n_sect & 0xff),
		       (unsigned int)(symbols[i].n_desc & 0xffff));
		if(symbols[i].n_un.n_strx == 0)
		    printf("%08x (null)", (unsigned int)symbols[i].n_un.n_strx);
		else if((unsigned long)symbols[i].n_un.n_strx > strsize)
		    printf("%08x (bad string index)",
			   (unsigned int)symbols[i].n_un.n_strx);
		else
		    printf("%08x %s", (unsigned int)symbols[i].n_un.n_strx,
			   symbols[i].n_un.n_strx + strings);
		if((symbols[i].n_type & N_STAB) == 0 &&
		   (symbols[i].n_type & N_TYPE) == N_INDR){
		    if(symbols[i].n_value == 0)
			printf(" (indirect for %08lx (null))\n",
			       symbols[i].n_value);
		    else if(symbols[i].n_value > strsize)
			printf(" (indirect for %08lx (bad string index))\n",
			       symbols[i].n_value);
		    else
			printf(" (indirect for %08lx %s)\n", symbols[i].n_value,
			       symbols[i].n_value + strings);
		}
		else
		    printf("\n");
		continue;
	    }

	    if(symbols[i].n_type & N_STAB){
		if(cmd_flags->o == TRUE){
		    if(arch_name != NULL)
			printf("(for architecture %s):", arch_name);
		    if(ofile->dylib_module_name != NULL){
			printf("%s:%s:", ofile->file_name,
			       ofile->dylib_module_name);
		    }
		    else if(ofile->member_ar_hdr != NULL){
			printf("%s:%.*s:", ofile->file_name,
			       (int)ofile->member_name_size,
			       ofile->member_name);
		    }
		    else
			printf("%s:", ofile->file_name);
		}
		printf("%08lx - %02x %04x %5.5s %s\n",
		       symbols[i].n_value,
		       (unsigned int)symbols[i].n_sect & 0xff,
		       (unsigned int)symbols[i].n_desc & 0xffff,
		       stab(symbols[i].n_type), symbols[i].n_un.n_name);
		continue;
	    }

	    if(cmd_flags->o == TRUE){
		if(cmd_flags->o == TRUE){
		    if(arch_name != NULL)
			printf("(for architecture %s):", arch_name);
		    if(ofile->dylib_module_name != NULL){
			printf("%s:%s:", ofile->file_name,
			       ofile->dylib_module_name);
		    }
		    else if(ofile->member_ar_hdr != NULL){
			printf("%s:%.*s:", ofile->file_name,
			       (int)ofile->member_name_size,
			       ofile->member_name);
		    }
		    else
			printf("%s:", ofile->file_name);
		}
	    }

	    if(((symbols[i].n_type & N_TYPE) == N_UNDF &&
		 symbols[i].n_value == 0) ||
		 (symbols[i].n_type & N_TYPE) == N_INDR)
		printf("        ");
	    else
		printf("%08lx", symbols[i].n_value);

	    switch(symbols[i].n_type & N_TYPE){
	    case N_UNDF:
	    case N_PBUD:
		if((symbols[i].n_type & N_TYPE) == N_UNDF &&
		   symbols[i].n_value != 0)
		    printf(" (common) ");
		else{
		    if((symbols[i].n_type & N_TYPE) == N_PBUD)
			printf(" (prebound ");
		    else
			printf(" (");
		    if((symbols[i].n_desc & REFERENCE_TYPE) ==
		       REFERENCE_FLAG_UNDEFINED_LAZY)
			printf("undefined [lazy bound]) ");
		    else if((symbols[i].n_desc & REFERENCE_TYPE) ==
			    REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY)
			printf("undefined [private lazy bound]) ");
		    else if((symbols[i].n_desc & REFERENCE_TYPE) ==
			    REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY)
			printf("undefined [private]) ");
		    else
			printf("undefined) ");
		}
		break;
	    case N_ABS:
		printf(" (absolute) ");
		
		break;
	    case N_INDR:
		printf(" (indirect) ");
		break;
	    case N_SECT:
		if(symbols[i].n_sect >= 1 &&
		   symbols[i].n_sect <= process_flags->nsects){
		    printf(" (%.16s,%.16s) ",
		       process_flags->sections[symbols[i].n_sect-1]->segname,
		       process_flags->sections[symbols[i].n_sect-1]->sectname);
		}
		else
		    printf(" (?,?) ");
		break;
	    default:
		    printf(" (?) ");
		    break;
	    }

	    if(symbols[i].n_type & N_EXT){
		if(symbols[i].n_desc & REFERENCED_DYNAMICALLY)
		    printf("[referenced dynamically] ");
		if(symbols[i].n_type & N_PEXT){
		    if((symbols[i].n_desc & N_WEAK_DEF) == N_WEAK_DEF)
			printf("weak private external ");
		    else
			printf("private external ");
		}
		else{
		    if((symbols[i].n_desc & N_WEAK_REF) == N_WEAK_REF ||
		       (symbols[i].n_desc & N_WEAK_DEF) == N_WEAK_DEF)
			printf("weak external ");
		    else
			printf("external ");
		}
	    }
	    else{
		if(symbols[i].n_type & N_PEXT)
		    printf("non-external (was a private external) ");
		else
		    printf("non-external ");
	    }

	    if((symbols[i].n_type & N_TYPE) == N_INDR)
		printf("%s (for %s)", symbols[i].n_un.n_name,
		       (char *)symbols[i].n_value);
	    else
		printf("%s", symbols[i].n_un.n_name);

	    if((ofile->mh->flags & MH_TWOLEVEL) == MH_TWOLEVEL &&
	       (((symbols[i].n_type & N_TYPE) == N_UNDF &&
		 symbols[i].n_value == 0) ||
	        (symbols[i].n_type & N_TYPE) == N_PBUD)){
		library_ordinal = GET_LIBRARY_ORDINAL(symbols[i].n_desc);
		if(library_ordinal != 0){
		    if(library_ordinal == EXECUTABLE_ORDINAL)
			printf(" (from executable)");
		    else if(process_flags->nlibs != DYNAMIC_LOOKUP_ORDINAL &&
			    library_ordinal == DYNAMIC_LOOKUP_ORDINAL)
			printf(" (dynamically looked up)");
		    else if(library_ordinal-1 >= process_flags->nlibs)
			printf(" (from bad library ordinal %lu)",
			       library_ordinal);
		    else
			printf(" (from %s)", process_flags->lib_names[
						library_ordinal-1]);
		}
	    }
	    printf("\n");
	}
}

/*
 * print_symbols() is called with the -m flag is not specified and prints
 * symbols in the standard BSD format.
 */
static
void
print_symbols(
struct ofile *ofile,
struct nlist *symbols,
unsigned long nsymbols,
char *strings,
unsigned long strsize,
struct cmd_flags *cmd_flags,
struct process_flags *process_flags,
char *arch_name,
struct value_diff *value_diffs)
{
    unsigned long i;
    unsigned char c, *p;

	for(i = 0; i < nsymbols; i++){
	    if(cmd_flags->x == TRUE){
		printf("%08lx %02x %02x %04x ", symbols[i].n_value,
		       (unsigned int)(symbols[i].n_type & 0xff),
		       (unsigned int)(symbols[i].n_sect & 0xff),
		       (unsigned int)(symbols[i].n_desc & 0xffff));
		if(symbols[i].n_un.n_strx == 0)
		    printf("%08x (null)", (unsigned int)symbols[i].n_un.n_strx);
		else if((unsigned long)symbols[i].n_un.n_strx > strsize)
		    printf("%08x (bad string index)",
			   (unsigned int)symbols[i].n_un.n_strx);
		else
		    printf("%08x %s", (unsigned int)symbols[i].n_un.n_strx,
			   symbols[i].n_un.n_strx + strings);
		if((symbols[i].n_type & N_STAB) == 0 &&
		   (symbols[i].n_type & N_TYPE) == N_INDR){
		    if(symbols[i].n_value == 0)
			printf(" (indirect for %08lx (null))\n",
			       symbols[i].n_value);
		    else if(symbols[i].n_value > strsize)
			printf(" (indirect for %08lx (bad string index))\n",
			       symbols[i].n_value);
		    else
			printf(" (indirect for %08lx %s)\n", symbols[i].n_value,
			       symbols[i].n_value + strings);
		}
		else
		    printf("\n");
		continue;
	    }
	    c = symbols[i].n_type;
	    if(c & N_STAB){
		if(cmd_flags->o == TRUE){
		    if(arch_name != NULL)
			printf("(for architecture %s):", arch_name);
		    if(ofile->dylib_module_name != NULL){
			printf("%s:%s:", ofile->file_name,
			       ofile->dylib_module_name);
		    }
		    else if(ofile->member_ar_hdr != NULL){
			printf("%s:%.*s:", ofile->file_name,
			       (int)ofile->member_name_size,
			       ofile->member_name);
		    }
		    else
			printf("%s:", ofile->file_name);
		}
		printf("%08lx - %02x %04x %5.5s ",
		       symbols[i].n_value,
		       (unsigned int)symbols[i].n_sect & 0xff,
		       (unsigned int)symbols[i].n_desc & 0xffff,
		       stab(symbols[i].n_type));
		if(cmd_flags->b == TRUE){
		    for(p = symbols[i].n_un.n_name; *p != '\0'; p++){
			printf("%c", *p);
			if(*p == '('){
			    p++;
			    while(isdigit((unsigned char)*p))
				p++;
			    p--;
			}
			if(*p == '.' && p[1] != '\0' && p[1] == '_'){
			    p++; /* one for the '.' */
			    p++; /* and one for the '_' */
			    while(isdigit((unsigned char)*p))
				p++;
			    p--;
			}
		    }
		    printf("\n");
		}
		else{
		    printf("%s\n", symbols[i].n_un.n_name);
		}
		continue;
	    }
	    switch(c & N_TYPE){
	    case N_UNDF:
		c = 'u';
		if(symbols[i].n_value != 0)
		    c = 'c';
		break;
	    case N_PBUD:
		c = 'u';
		break;
	    case N_ABS:
		c = 'a';
		break;
	    case N_SECT:
		if(symbols[i].n_sect == process_flags->text_nsect)
		    c = 't';
		else if(symbols[i].n_sect == process_flags->data_nsect)
		    c = 'd';
		else if(symbols[i].n_sect == process_flags->bss_nsect)
		    c = 'b';
		else
		    c = 's';
		break;
	    case N_INDR:
		c = 'i';
		break;
	    default:
		c = '?';
		break;
	    }
	    if(cmd_flags->u == TRUE && c != 'u')
		continue;
	    if(cmd_flags->o == TRUE){
		if(cmd_flags->o == TRUE){
		    if(arch_name != NULL)
			printf("(for architecture %s):", arch_name);
		    if(ofile->dylib_module_name != NULL){
			printf("%s:%s:", ofile->file_name,
			       ofile->dylib_module_name);
		    }
		    else if(ofile->member_ar_hdr != NULL){
			printf("%s:%.*s:", ofile->file_name,
			       (int)ofile->member_name_size,
			       ofile->member_name);
		    }
		    else
			printf("%s:", ofile->file_name);
		}
	    }
	    if((symbols[i].n_type & N_EXT) && c != '?')
		c = toupper(c);
	    if(cmd_flags->u == FALSE && cmd_flags->j == FALSE){
		if(c == 'u' || c == 'U' || c == 'i' || c == 'I')
		    printf("        ");
		else{
		    if(cmd_flags->v && value_diffs != NULL)
			printf("%08lx ", value_diffs[i].size);
		    printf("%08lx", symbols[i].n_value);
		}
		printf(" %c ", c);
	    }
	    if(cmd_flags->j == FALSE && (symbols[i].n_type & N_TYPE) == N_INDR)
		printf("%s (indirect for %s)\n", symbols[i].n_un.n_name,
		       (char *)symbols[i].n_value);
	    else 
		printf("%s\n", symbols[i].n_un.n_name);
	}
}

struct stabnames {
    unsigned char n_type;
    char *name;
};
static const struct stabnames stabnames[] = {
    { N_GSYM,  "GSYM" },
    { N_FNAME, "FNAME" },
    { N_FUN,   "FUN" },
    { N_STSYM, "STSYM" },
    { N_LCSYM, "LCSYM" },
    { N_BNSYM, "BNSYM" },
    { N_OPT,   "OPT" },
    { N_RSYM,  "RSYM" },
    { N_SLINE, "SLINE" },
    { N_ENSYM, "ENSYM" },
    { N_SSYM,  "SSYM" },
    { N_SO,    "SO" },
    { N_LSYM,  "LSYM" },
    { N_BINCL, "BINCL" },
    { N_SOL,   "SOL" },
    { N_PARAMS,"PARAM" },
    { N_VERSION,"VERS" },
    { N_OLEVEL,"OLEV" },
    { N_PSYM,  "PSYM" },
    { N_EINCL, "EINCL" },
    { N_ENTRY, "ENTRY" },
    { N_LBRAC, "LBRAC" },
    { N_EXCL,  "EXCL" },
    { N_RBRAC, "RBRAC" },
    { N_BCOMM, "BCOMM" },
    { N_ECOMM, "ECOMM" },
    { N_ECOML, "ECOML" },
    { N_LENG,  "LENG" },
    { N_PC,    "PC" },
    { 0, 0 }
};

/*
 * stab() returns the name of the specified stab n_type.
 */
static
char *
stab(
unsigned char n_type)
{
    const struct stabnames *p;
    static char prbuf[32];

	for(p = stabnames; p->name; p++)
	    if(p->n_type == n_type)
		return(p->name);
	sprintf(prbuf, "%02x", (unsigned int)n_type);
	return(prbuf);
}

/*
 * compare is the function used by qsort if any sorting of symbols is to be
 * done.
 */
static
int
compare(
struct nlist *p1,
struct nlist *p2)
{
    int r;

	r = 0;
	if(cmd_flags.n == TRUE){
	    if(p1->n_value > p2->n_value)
		return(cmd_flags.r == FALSE ? 1 : -1);
	    else if(p1->n_value < p2->n_value)
		return(cmd_flags.r == FALSE ? -1 : 1);
	    /* if p1->n_value == p2->n_value fall through and sort by name */
	}

	if(cmd_flags.x == TRUE){
	    if((unsigned long)p1->n_un.n_strx > strsize ||
	       (unsigned long)p2->n_un.n_strx > strsize){
		if((unsigned long)p1->n_un.n_strx > strsize)
		    r = -1;
		else if((unsigned long)p2->n_un.n_strx > strsize)
		    r = 1;
	    }
	    else
		r = strcmp(p1->n_un.n_strx + strings, p2->n_un.n_strx +strings);
	}
	else
	    r = strcmp(p1->n_un.n_name, p2->n_un.n_name);

	if(cmd_flags.r == TRUE)
	    return(-r);
	else
	    return(r);
}

static
int
value_diff_compare(
struct value_diff *p1,
struct value_diff *p2)
{
	if(p1->size < p2->size)
	    return(-1);
	else if(p1->size > p2->size)
	    return(1);
	/* if p1->size == p2->size */
	return(0);
}

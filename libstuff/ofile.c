/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#ifdef SHLIB
#include "shlib.h"
#endif
#include <libc.h>
#include <mach/mach.h>
#include "stuff/openstep_mach.h"
#include <stddef.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <ar.h>
#include <sys/file.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#import <mach/m68k/thread_status.h>
#import <mach/ppc/thread_status.h>
#import <mach/m88k/thread_status.h>
#import <mach/i860/thread_status.h>
#import <mach/i386/thread_status.h>
#import <mach/sparc/thread_status.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include "stuff/bool.h"
#ifdef OFI
#include <mach-o/dyld.h>
#endif
#include "stuff/bytesex.h"
#include "stuff/arch.h"
#include "stuff/round.h"
#include "stuff/errors.h"
#include "stuff/allocate.h"
#include "stuff/ofile.h"
#include "stuff/print.h"

#ifdef OTOOL
#undef ALIGNMENT_CHECKS
#include "otool.h"
#include "ofile_print.h"
static enum bool otool_first_ofile_map = TRUE;
#else /* !define(OTOOL) */
#if (!defined(m68k) && !defined(__i386__))
#define ALIGNMENT_CHECKS
#endif /* (!defined(m68k) && !defined(__i386__)) */
#endif /* OTOOL */

/* <mach/loader.h> */
/* The maximum section alignment allowed to be specified, as a power of two */
#define MAXSECTALIGN		15 /* 2**15 or 0x8000 */

enum check_type {
    CHECK_BAD,
    CHECK_GOOD
};
static enum bool ofile_specific_arch(
    struct ofile *ofile,
    unsigned long narch);
static enum check_type check_fat(
    struct ofile *ofile);
static enum check_type check_fat_object_in_archive(
    struct ofile *ofile);
static enum check_type check_archive(
    struct ofile *ofile,
    enum bool archives_with_fat_objects);
static enum check_type check_extend_format_1(
    struct ofile *ofile,
    struct ar_hdr *ar_hdr,
    unsigned long size_left,
    unsigned long *member_name_size);
static enum check_type check_Mach_O(
    struct ofile *ofile);
static enum check_type check_dylib_module(
    struct ofile *ofile,
    struct symtab_command *st,
    struct dysymtab_command *dyst,
    char *strings,
    unsigned long module_index);

#ifndef OFI
/*
 * ofile_process() processes the specified file name can calls the routine
 * processor on the ofiles in it.  arch_flags is an array of architectures
 * containing narch_flags which are the only architectures to process if
 * narch_flags is non-zero.  If all_archs is TRUE then all architectures of
 * the specified file are processed.  The specified file name can be of the
 * form "archive(member)" which is taken to mean that member in that archive
 * (or that module of a dynamic library if dylib_flat is not FALSE).
 * For each ofile that is to be processed the routine processor is called with
 * the corresponding ofile struct, the arch_name pass to it is either NULL or
 * an architecture name (when it should be printed or show by processor) and
 * cookie is the same value as passed to ofile_process.
 */
__private_extern__
void
ofile_process(
char *name,
struct arch_flag *arch_flags,
unsigned long narch_flags,
enum bool all_archs,
enum bool process_non_objects,
enum bool dylib_flat,
enum bool use_member_syntax,
void (*processor)(struct ofile *ofile, char *arch_name, void *cookie),
void *cookie)
{
    char *member_name, *p, *arch_name;
    unsigned long len, i;
    struct ofile ofile;
    enum bool flag, hostflag, arch_found, family;
    struct arch_flag host_arch_flag;
    const struct arch_flag *family_arch_flag;

	/*
	 * If use_member_syntax is TRUE look for a name of the form
	 * "archive(member)" which is to mean a member in that archive (the
	 * member name must be at least one character long to be recognized as
	 * this form).
	 */
	member_name = NULL;
	if(use_member_syntax == TRUE){
	    len = strlen(name);
	    if(len >= 4 && name[len-1] == ')'){
		p = strrchr(name, '(');
		if(p != NULL && p != name){
		    member_name = p+1;
		    *p = '\0';
		    name[len-1] = '\0';
		}
	    }
	}

#ifdef OTOOL
	otool_first_ofile_map = TRUE;
#endif /* OTOOL */
	if(ofile_map(name, NULL, NULL, &ofile, FALSE) == FALSE)
	    return;
#ifdef OTOOL
	otool_first_ofile_map = FALSE;
#endif /* OTOOL */

	if(ofile.file_type == OFILE_FAT){
	    /*
	     * This is a fat file so see if a list of architecture is
	     * specified and process only those.
	     */
	    if(all_archs == FALSE && narch_flags != 0){

		family = FALSE;
		if(narch_flags == 1){
		    family_arch_flag =
			get_arch_family_from_cputype(arch_flags[0].cputype);
		    if(family_arch_flag != NULL)
			family = (enum bool)(family_arch_flag->cpusubtype ==
					     arch_flags[0].cpusubtype);
		}

		for(i = 0; i < narch_flags; i++){
		    if(ofile_first_arch(&ofile) == FALSE)
			return;
		    arch_found = FALSE;
		    if(narch_flags != 1)
			arch_name = ofile.arch_flag.name;
		    else
			arch_name = NULL;
		    do{
			if(ofile.arch_flag.cputype ==
				arch_flags[i].cputype &&
			   (ofile.arch_flag.cpusubtype ==
				arch_flags[i].cpusubtype || family == TRUE)){
			    arch_found = TRUE;
			    if(ofile.arch_type == OFILE_ARCHIVE){
				if(member_name != NULL){
				    if(ofile_specific_member(member_name,
							     &ofile) == TRUE)
					processor(&ofile, arch_name, cookie);
				}
				else{
				    /* loop through archive */
#ifdef OTOOL
				    printf("Archive : %s", ofile.file_name);
				    if(arch_name != NULL)
					printf(" (architecture %s)",
					       arch_name);
				    printf("\n");
#endif /* OTOOL */
				    if(ofile_first_member(&ofile) == TRUE){
					flag = FALSE;
					do{
					    if(process_non_objects == TRUE ||
					       ofile.member_type ==
								OFILE_Mach_O){
						processor(&ofile, arch_name,
							  cookie);
						flag = TRUE;
					    }
					}while(ofile_next_member(&ofile) ==
						TRUE);
					if(flag == FALSE){
					    error("for architecture: %s "
						  "archive: %s contains no "
						  "members that are object "
						  "files", ofile.arch_flag.name,
						  ofile.file_name);
					}
				    }
				    else{
					error("for architecture: %s archive: "
					      "%s contains no members",
					      ofile.arch_flag.name,
					      ofile.file_name);
				    }
				}
			    }
			    else if(process_non_objects == TRUE ||
				    ofile.arch_type == OFILE_Mach_O){
				if(ofile.arch_type == OFILE_Mach_O &&
				   (ofile.mh->filetype == MH_DYLIB ||
				    ofile.mh->filetype == MH_DYLIB_STUB)){
				    if(dylib_flat == TRUE){
					processor(&ofile, arch_name, cookie);
				    }
				    else{
					if(member_name != NULL){
					    if(ofile_specific_module(
						member_name, &ofile) == TRUE)
						processor(&ofile, arch_name,
							  cookie);
					}
					else{
					    /*loop through the dynamic library*/
					    if(ofile_first_module(&ofile)){
						do{
						    processor(&ofile, arch_name,
							cookie);
						}while(ofile_next_module(
							&ofile));
					    }
					    else{
						error("for architecture: %s "
						      "dynamic library: %s "
						      "contains no modules",
						      ofile.arch_flag.name,
						      ofile.file_name);
					    }
					}
				    }
				}
				else{
				    if(member_name != NULL)
					error("for architecture: %s file: %s "
					      "is not an archive and thus does "
					      "not contain member: %s",
					      ofile.arch_flag.name,
					      ofile.file_name,
					      member_name);
				    else
					processor(&ofile, arch_name, cookie);
				}
			    }
			    else if(ofile.arch_type == OFILE_UNKNOWN){
				error("for architecture: %s file: %s is "
				      "not an object file",
				      ofile.arch_flag.name,ofile.file_name);
			    }
			    break;
			}
		    }while(ofile_next_arch(&ofile) == TRUE);
		    if(arch_found == FALSE)
			error("file: %s does not contain architecture: %s",
			      ofile.file_name, arch_flags[i].name);
		}
		return;
	    }

	    /*
	     * This is a fat file and no architectures has been specified
	     * so if it contains the host architecture process only that
	     * architecture but if not process all architectures
	     * specified.
	     */
	    if(all_archs == FALSE){
		(void)get_arch_from_host(&host_arch_flag, NULL);
		hostflag = FALSE;

		family = FALSE;
		family_arch_flag =
		    get_arch_family_from_cputype(host_arch_flag.cputype);
		if(family_arch_flag != NULL)
		    family = (enum bool)(family_arch_flag->cpusubtype ==
					 host_arch_flag.cpusubtype);

		ofile_unmap(&ofile);
		if(ofile_map(name, NULL, NULL, &ofile, FALSE) == FALSE)
		    return;
		if(ofile_first_arch(&ofile) == FALSE)
		    return;
		do{
		    if(ofile.arch_flag.cputype ==
			    host_arch_flag.cputype &&
		       (ofile.arch_flag.cpusubtype ==
			    host_arch_flag.cpusubtype || family == TRUE)){
			hostflag = TRUE;
			if(ofile.arch_type == OFILE_ARCHIVE){
			    if(member_name != NULL){
				if(ofile_specific_member(member_name,
							 &ofile) == TRUE)
				    processor(&ofile, NULL, cookie);
			    }
			    else{
				/* loop through archive */
#ifdef OTOOL
				printf("Archive : %s\n", ofile.file_name);
#endif /* OTOOL */
				if(ofile_first_member(&ofile) == TRUE){
				    flag = FALSE;
				    do{
					if(process_non_objects == TRUE ||
				           ofile.member_type == OFILE_Mach_O){
					    processor(&ofile, NULL, cookie);
					    flag = TRUE;
					}
				    }while(ofile_next_member(&ofile) ==
					   TRUE);
				    if(flag == FALSE){
					error("archive: %s contains no "
					      "members that are object "
					      "files", ofile.file_name);
				    }
				}
				else{
				    error("archive: %s contains no "
					  "members", ofile.file_name);
				}
			    }
			}
			else if(process_non_objects == TRUE ||
				ofile.arch_type == OFILE_Mach_O){
			    if(ofile.arch_type == OFILE_Mach_O &&
			       (ofile.mh->filetype == MH_DYLIB ||
				ofile.mh->filetype == MH_DYLIB_STUB)){
				if(dylib_flat == TRUE){
				    processor(&ofile, NULL, cookie);
				}
				else{
				    if(member_name != NULL){
					if(ofile_specific_module(member_name,
						&ofile) == TRUE)
					    processor(&ofile, NULL, cookie);
				    }
				    else{
					/* loop through the dynamic library */
					if(ofile_first_module(&ofile) == TRUE){
					    do{
						processor(&ofile, NULL, cookie);
					    }while(ofile_next_module(&ofile));
					}
					else{
					    error("for architecture: %s dynamic"
						  " library: %s contains no "
						  "modules",
						  ofile.arch_flag.name,
						  ofile.file_name);
					}
				    }
				}
			    }
			    else{
				if(member_name != NULL)
				    error("for architecture: %s file: %s is "
					  "not an archive and thus does not "
					  "contain member: %s",
					  ofile.arch_flag.name, ofile.file_name,
					  member_name);
				else
				    processor(&ofile, NULL, cookie);
			    }
			}
			else if(ofile.arch_type == OFILE_UNKNOWN){
			    error("file: %s is not an object file",
				  ofile.file_name);
			}
		    }
		}while(hostflag == FALSE && ofile_next_arch(&ofile) == TRUE);
		if(hostflag == TRUE)
		    return;
	    }

	    /*
	     * Either all architectures have been specified or none have
	     * been specified and it does not contain the host architecture
	     * so do all the architectures in the fat file
	     */
	    ofile_unmap(&ofile);
	    if(ofile_map(name, NULL, NULL, &ofile, FALSE) == FALSE)
		return;
	    if(ofile_first_arch(&ofile) == FALSE)
		return;
	    do{
		if(ofile.arch_type == OFILE_ARCHIVE){
		    if(member_name != NULL){
			if(ofile_specific_member(member_name, &ofile) == TRUE)
			    processor(&ofile, ofile.arch_flag.name, cookie);
		    }
		    else{
			/* loop through archive */
#ifdef OTOOL
			printf("Archive : %s (architecture %s)\n",
			       ofile.file_name, ofile.arch_flag.name);
#endif /* OTOOL */
			if(ofile_first_member(&ofile) == TRUE){
			    flag = FALSE;
			    do{
				if(process_non_objects == TRUE ||
				   ofile.member_type == OFILE_Mach_O){
				    processor(&ofile, ofile.arch_flag.name,
					      cookie);
				    flag = TRUE;
				}
			    }while(ofile_next_member(&ofile) == TRUE);
			    if(flag == FALSE){
				error("for architecture: %s archive: %s "
				      "contains no members that are object "
				      "files", ofile.arch_flag.name,
				      ofile.file_name);
			    }
			}
			else{
			    error("for architecture: %s archive: %s "
				  "contains no members",
				  ofile.arch_flag.name, ofile.file_name);
			}
		    }
		}
		else if(process_non_objects == TRUE ||
			ofile.arch_type == OFILE_Mach_O){
		    if(ofile.arch_type == OFILE_Mach_O &&
		       (ofile.mh->filetype == MH_DYLIB ||
			ofile.mh->filetype == MH_DYLIB_STUB)){
			if(dylib_flat == TRUE){
			    processor(&ofile, ofile.arch_flag.name, cookie);
			}
			else{
			    if(member_name != NULL){
				if(ofile_specific_module(member_name, &ofile)
				   == TRUE)
				    processor(&ofile, ofile.arch_flag.name,
					      cookie);
			    }
			    else{
				/* loop through the dynamic library */
				if(ofile_first_module(&ofile) == TRUE){
				    do{
					processor(&ofile, ofile.arch_flag.name,
						  cookie);
				    }while(ofile_next_module(&ofile) == TRUE);
				}
				else{
				    error("for architecture: %s dynamic library"
					  ": %s contains no modules",
					  ofile.arch_flag.name,ofile.file_name);
				}
			    }
			}
		    }
		    else{
			if(member_name != NULL)
			    error("for architecture: %s file: %s is not an "
				  "archive and thus does not contain member: "
				  "%s", ofile.arch_flag.name, ofile.file_name,
				  member_name);
			else
			    processor(&ofile, ofile.arch_flag.name, cookie);
		    }
		}
		else if(ofile.arch_type == OFILE_UNKNOWN){
		    error("for architecture: %s file: %s is not an "
			  "object file", ofile.arch_flag.name,
			  ofile.file_name);
		}
	    }while(ofile_next_arch(&ofile) == TRUE);
	}
	else if(ofile.file_type == OFILE_ARCHIVE){
	    if(narch_flags != 0){
		arch_found = FALSE;
		for(i = 0; i < narch_flags; i++){
		    family = FALSE;
		    if(narch_flags == 1){
			family_arch_flag =
			    get_arch_family_from_cputype(arch_flags[0].cputype);
			if(family_arch_flag != NULL)
			    family = (enum bool)(family_arch_flag->cpusubtype ==
						 arch_flags[0].cpusubtype);
		    }
		    if(ofile.archive_cputype == arch_flags[i].cputype &&
		       (ofile.archive_cpusubtype == arch_flags[i].cpusubtype ||
			family == TRUE)){
			arch_found = TRUE;
		    }
		    else{
			error("file: %s does not contain architecture: %s",
			      ofile.file_name, arch_flags[i].name);
		    }
		}
		if(arch_found == FALSE)
		    return;
	    }
	    if(member_name != NULL){
		if(ofile_specific_member(member_name, &ofile) == TRUE)
		    processor(&ofile, NULL, cookie);
	    }
	    else{
		/* loop through archive */
#ifdef OTOOL
		printf("Archive : %s\n", ofile.file_name);
#endif /* OTOOL */
		if(ofile_first_member(&ofile) == TRUE){
		    flag = FALSE;
		    do{
			if(process_non_objects == TRUE ||
			    ofile.member_type == OFILE_Mach_O){
			    processor(&ofile, NULL, cookie);
			    flag = TRUE;
			}
		    }while(ofile_next_member(&ofile) == TRUE);
		    if(flag == FALSE){
			error("archive: %s contains no members that are "
			      "object files", ofile.file_name);
		    }
		}
		else{
		    error("archive: %s contains no members",
			  ofile.file_name);
		}
	    }
	}
	else if(ofile.file_type == OFILE_Mach_O){
	    if(narch_flags != 0){
		arch_found = FALSE;
		for(i = 0; i < narch_flags; i++){
		    family = FALSE;
		    if(narch_flags == 1){
			family_arch_flag =
			    get_arch_family_from_cputype(arch_flags[0].cputype);
			if(family_arch_flag != NULL)
			    family = (enum bool)(family_arch_flag->cpusubtype ==
						 arch_flags[0].cpusubtype);
		    }
#ifdef OTOOL
		    if(ofile.mh->magic == SWAP_LONG(MH_MAGIC)){
			if((cpu_type_t)SWAP_LONG(ofile.mh->cputype) ==
				arch_flags[i].cputype &&
			   ((cpu_subtype_t)SWAP_LONG(ofile.mh->cpusubtype) ==
				arch_flags[i].cpusubtype ||
			    family == TRUE)){
			    arch_found = TRUE;
			}
		    }
		    else
#endif /* OTOOL */
		    if(ofile.mh->cputype == arch_flags[i].cputype &&
		       (ofile.mh->cpusubtype == arch_flags[i].cpusubtype ||
			family == TRUE)){
			arch_found = TRUE;
		    }
		    else{
			error("file: %s does not contain architecture: %s",
			      ofile.file_name, arch_flags[i].name);
		    }
		}
		if(arch_found == FALSE)
		    return;
	    }
	    if(ofile.mh->filetype == MH_DYLIB ||
	       ofile.mh->filetype == MH_DYLIB_STUB){
		if(dylib_flat == TRUE){
		    processor(&ofile, NULL, cookie);
		}
		else{
		    if(member_name != NULL){
			if(ofile_specific_module(member_name, &ofile) == TRUE)
			    processor(&ofile, NULL, cookie);
		    }
		    else{
			/* loop through the dynamic library */
			if(ofile_first_module(&ofile) == TRUE){
			    do{
				processor(&ofile, NULL, cookie);
			    }while(ofile_next_module(&ofile) == TRUE);
			}
			else{
			    error("dynamic library: %s contains no modules",
				  ofile.file_name);
			}
		    }
		}
	    }
	    else{
		if(member_name != NULL)
		    error("file: %s is not an archive and thus does not contain"
			  " member: %s", ofile.file_name, member_name);
		else
		    processor(&ofile, NULL, cookie);
	    }
	}
	else{
	    if(process_non_objects == TRUE)
		processor(&ofile, NULL, cookie);
	    else if(member_name != NULL)
		error("file: %s(%s) is not an object file", name,
		      member_name);
	    else
		error("file: %s is not an object file", name);
	}
}
#endif /* !defined(OFI) */

/*
 * ofile_map maps in the object file specified by file_name, arch_flag and
 * object_name and fills in the ofile struct pointed to by ofile for it.
 * When arch_flag and object_name are both NULL, the file is just set up into
 * ofile (if the file can be opened and mapped in, if not this call fails
 * are error routnes are called).  If arch_flag is not NULL and object_file is
 * NULL, then the file must be a Mach-O file or a fat file with the architecture
 * specified in the arch_flag, if not this call fails and error routines are
 * called.  When arch_flag and object_name are both not NULL, then the file must
 * be an archive or a fat file containing archives for the specified architec-
 * ture and contain an archive member object file with the name object_name,
 * otherwise this call fails and error routines are called.  If arch_flag is
 * NULL and object_file is not NULL, then the file name must be an archive (not
 * a fat file containing archives) and contain an archive member object file
 * with the name object_name, otherwise this call fails and calls error
 * routines.  If this call suceeds then it returns non-zero and the ofile
 * structure pointed to by ofile is filled in.  If this call fails it returns 0
 * and calls error routines to print error messages and clears the
 * ofile structure pointed to by ofile.
 */
__private_extern__
#ifdef OFI
NSObjectFileImageReturnCode
#else
enum bool
#endif
ofile_map(
const char *file_name,
const struct arch_flag *arch_flag,	/* can be NULL */
const char *object_name,		/* can be NULL */
struct ofile *ofile,
enum bool archives_with_fat_objects)
{
    int fd;
    struct stat stat_buf;
    unsigned long size, magic;
    kern_return_t r;
    char *addr;

	magic = 0; /* to shut up the compiler warning message */
	memset(ofile, '\0', sizeof(struct ofile));

	/* Open the file and map it in */
	if((fd = open(file_name, O_RDONLY)) == -1){
#ifdef OFI
	    return(NSObjectFileImageAccess);
#else
	    system_error("can't open file: %s", file_name);
	    return(FALSE);
#endif
	}
	if(fstat(fd, &stat_buf) == -1){
	    close(fd);
#ifdef OFI
	    return(NSObjectFileImageAccess);
#else
	    system_error("can't stat file: %s", file_name);
	    return(FALSE);
#endif
	}
	size = stat_buf.st_size;
	if((r = map_fd((int)fd, (vm_offset_t)0, (vm_offset_t *)&addr,
		       (boolean_t)TRUE, (vm_size_t)size)) != KERN_SUCCESS){
	    my_mach_error(r, "can't map file: %s", file_name);
	    close(fd);
	    return(FALSE);
	}
	close(fd);
#ifdef OTOOL
	if(otool_first_ofile_map && Wflag)
	    printf("Modification time = %ld\n", (long int)stat_buf.st_mtime);
#endif /* OTOOL */

	return(ofile_map_from_memory(addr, size, file_name, arch_flag,
			     object_name, ofile, archives_with_fat_objects));
}

/*
 * ofile_map_from_memory() is the guts of ofile_map() but with an interface
 * to pass the address and size of the file already mapped in.
 */
__private_extern__
#ifdef OFI
NSObjectFileImageReturnCode
#else
enum bool
#endif
ofile_map_from_memory(
char *addr,
unsigned long size,
const char *file_name,
const struct arch_flag *arch_flag,	/* can be NULL */
const char *object_name,		/* can be NULL */
struct ofile *ofile,
enum bool archives_with_fat_objects)
{
    unsigned long i, magic;
    enum byte_sex host_byte_sex;
    struct arch_flag host_arch_flag;
    enum bool family;
    const struct arch_flag *family_arch_flag;

	/* fill in the start of the ofile structure */
	ofile->file_name = savestr(file_name);
	if(ofile->file_name == NULL)
	    return(FALSE);
	ofile->file_addr = addr;
	ofile->file_size = size;

	/* Try to figure out what kind of file this is */

	if(size >= sizeof(unsigned long)){
	   magic = *((unsigned long *)addr);
	}
	host_byte_sex = get_host_byte_sex();

	/* see if this file is a fat file (always in big endian byte sex) */
#ifdef __BIG_ENDIAN__
	if(size >= sizeof(struct fat_header) && magic == FAT_MAGIC)
#endif /* __BIG_ENDIAN__ */
#ifdef __LITTLE_ENDIAN__
	if(size >= sizeof(struct fat_header) && SWAP_LONG(magic) == FAT_MAGIC)
#endif /* __LITTLE_ENDIAN__ */
	{
	    ofile->file_type = OFILE_FAT;
	    ofile->fat_header = (struct fat_header *)addr;
#ifdef __LITTLE_ENDIAN__
	    swap_fat_header(ofile->fat_header, host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
#ifdef OTOOL
	    if(otool_first_ofile_map && fflag)
		printf("Fat headers\n");
#endif /* OTOOL */
	    if(sizeof(struct fat_header) + ofile->fat_header->nfat_arch *
	       sizeof(struct fat_arch) > size){
#ifdef OTOOL
		error("fat file: %s truncated or malformed (fat_arch structs "
		      "would extend past the end of the file)", file_name);
		ofile->fat_archs = allocate(ofile->fat_header->nfat_arch *
					    sizeof(struct fat_arch));
		memset(ofile->fat_archs, '\0',  ofile->fat_header->nfat_arch *
		       sizeof(struct fat_arch));
		memcpy(ofile->fat_archs,
		       addr + sizeof(struct fat_header),
	    	       size - sizeof(struct fat_header));
#ifdef __LITTLE_ENDIAN__
		swap_fat_arch(ofile->fat_archs, ofile->fat_header->nfat_arch,
			      host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
		if(otool_first_ofile_map && fflag)
		    print_fat_headers(ofile->fat_header, ofile->fat_archs,
				      size, vflag);
		free(ofile->fat_archs);
		ofile_unmap(ofile);
		return(FALSE);
		ofile_unmap(ofile);
		return(FALSE);
#else /* !defined(OTOOL) */
		goto unknown;
#endif /* OTOOL */
	    }
	    ofile->fat_archs = (struct fat_arch *)(addr +
						   sizeof(struct fat_header));
#ifdef __LITTLE_ENDIAN__
	    swap_fat_arch(ofile->fat_archs, ofile->fat_header->nfat_arch,
			  host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
#ifdef OTOOL
	    if(otool_first_ofile_map && fflag)
		print_fat_headers(ofile->fat_header, ofile->fat_archs,
				  size, vflag);
#endif /* OTOOL */
	    if(check_fat(ofile) == CHECK_BAD){
		ofile_unmap(ofile);
#ifdef OFI
		return(NSObjectFileImageFormat);
#else
		return(FALSE);
#endif
	    }
	    /*
	     * Now that the fat file is mapped fill in the ofile to the level
	     * the caller wants based on the arch_flag and object_name passed.
	     * If the caller did not specify an arch_flag or an object_name
	     * then everything the caller wants is done.
	     */
	    if(arch_flag == NULL && object_name == NULL)
		goto success;
	    if(arch_flag == NULL){
		if(get_arch_from_host(&host_arch_flag, NULL) == 0){
		    error("can't determine the host architecture (specify an "
			  "arch_flag or fix get_arch_from_host() )");
		    goto cleanup;
		}
		ofile->arch_flag.name = savestr(host_arch_flag.name);
		if(ofile->arch_flag.name == NULL)
		    goto cleanup;
		ofile->arch_flag.cputype = host_arch_flag.cputype;
		ofile->arch_flag.cpusubtype = host_arch_flag.cpusubtype;
	    }
	    else{
		ofile->arch_flag.name = savestr(arch_flag->name);
		if(ofile->arch_flag.name == NULL)
		    goto cleanup;
		ofile->arch_flag.cputype = arch_flag->cputype;
		ofile->arch_flag.cpusubtype = arch_flag->cpusubtype;
	    }

	    ofile->narch = ULONG_MAX;
	    for(i = 0; i < ofile->fat_header->nfat_arch; i++){
		if(ofile->fat_archs[i].cputype ==
			ofile->arch_flag.cputype &&
		   ofile->fat_archs[i].cpusubtype ==
			ofile->arch_flag.cpusubtype){
		    ofile->narch = i;
		    break;
		}
	    }
	    if(ofile->narch == ULONG_MAX){
		family = FALSE;
		family_arch_flag =
		    get_arch_family_from_cputype(ofile->arch_flag.cputype);
		if(family_arch_flag != NULL)
		    family = (enum bool)(family_arch_flag->cpusubtype ==
					 ofile->arch_flag.cpusubtype);
		ofile->narch = ULONG_MAX;
		for(i = 0; i < ofile->fat_header->nfat_arch; i++){
		    if(ofile->fat_archs[i].cputype ==
			    ofile->arch_flag.cputype &&
		       (family == TRUE || ofile->fat_archs[i].cpusubtype ==
			    ofile->arch_flag.cpusubtype)){
			ofile->arch_flag.cpusubtype =
			    ofile->fat_archs[i].cpusubtype;
			ofile->narch = i;
			break;
		    }
		}
	    }
	    if(ofile->narch == ULONG_MAX){
#ifdef OFI
		ofile_unmap(ofile);
		return(NSObjectFileImageArch);
#else
		error("fat file: %s does not contain architecture %s",
		      ofile->file_name, arch_flag->name);
		ofile_unmap(ofile);
		return(FALSE);
#endif
	    }
	    /* Now determine the file type for this specific architecture */
	    size = ofile->fat_archs[i].size;
	    addr = addr + ofile->fat_archs[i].offset;
	    if(size >= sizeof(struct mach_header))
		memcpy(&magic, addr, sizeof(unsigned long));
	    /* see if this file is Mach-O file */
	    if(size >= sizeof(struct mach_header) &&
	       (magic == MH_MAGIC || magic == SWAP_LONG(MH_MAGIC))){
#ifdef ALIGNMENT_CHECKS
		if(ofile->fat_archs[i].offset % sizeof(unsigned long) != 0){
		    error("fat file: %s architecture %s malformed for an "
			  "object file (offset is not a multiple of sizeof("
			  "unsigned long))", ofile->file_name, arch_flag->name);
		    ofile_unmap(ofile);
#ifdef OFI
		    return(NSObjectFileImageFormat);
#else
		    return(FALSE);
#endif
		}
#endif /* ALIGNMENT_CHECKS */
		ofile->arch_type = OFILE_Mach_O;
		ofile->object_addr = addr;
		ofile->object_size = size;
		if(magic == MH_MAGIC)
		    ofile->object_byte_sex = host_byte_sex;
		else
		    ofile->object_byte_sex =
			host_byte_sex == BIG_ENDIAN_BYTE_SEX ?
			LITTLE_ENDIAN_BYTE_SEX : BIG_ENDIAN_BYTE_SEX;
		ofile->mh = (struct mach_header *)addr;
		ofile->load_commands = (struct load_command *)(addr +
					    sizeof(struct mach_header));
		if(check_Mach_O(ofile) == CHECK_BAD){
		    ofile_unmap(ofile);
#ifdef OFI
		    return(NSObjectFileImageFormat);
#else
		    return(FALSE);
#endif
		}
		if(object_name != NULL){
		    error("fat file: %s architecture %s is not an archive "
			  "(object_name to ofile_map() can't be specified to "
			  "be other than NULL)", ofile->file_name,
			  arch_flag->name);
		    goto cleanup;
		}
	    }
	    /* see if this file is an archive file */
	    else if(size >= SARMAG && strncmp(addr, ARMAG, SARMAG) == 0){
		ofile->arch_type = OFILE_ARCHIVE;
		if(check_archive(ofile, FALSE) == CHECK_BAD){
		    ofile_unmap(ofile);
#ifdef OFI
		    return(NSObjectFileImageInappropriateFile);
#else
		    return(FALSE);
#endif
		}
#ifdef ALIGNMENT_CHECKS
		if(ofile->archive_cputype != 0 &&
		   ofile->fat_archs[i].offset % sizeof(unsigned long) != 0){
		    error("fat file: %s architecture %s malformed archive that "
			  "contains object files (offset to archive is not a "
			  "multiple of sizeof(unsigned long))",
			  ofile->file_name, arch_flag->name);
		    ofile_unmap(ofile);
#ifdef OFI
		    return(NSObjectFileImageInappropriateFile);
#else
		    return(FALSE);
#endif
		}
#endif /* ALIGNMENT_CHECKS */
		if(object_name != NULL){
		    if(ofile_specific_member(object_name, ofile) == FALSE)
			goto cleanup;
		}
	    }
	    /* this file type is now known to be unknown to this program */
	    else{
		ofile->file_type = OFILE_UNKNOWN;
		if(object_name != NULL){
		    error("fat file: %s architecture %s is not an archive "
			  "(object_name to ofile_map() can't be specified to "
			  "be other than NULL)", ofile->file_name,
			  arch_flag->name);
		    goto cleanup;
		}
	    }
	}
	/* see if this file is Mach-O file */
	else if(size >= sizeof(struct mach_header) &&
		(magic == MH_MAGIC || magic == SWAP_LONG(MH_MAGIC))){
	    ofile->file_type = OFILE_Mach_O;
	    ofile->object_addr = addr;
	    ofile->object_size = size;
	    if(magic == MH_MAGIC)
		ofile->object_byte_sex = host_byte_sex;
	    else
		ofile->object_byte_sex = host_byte_sex == BIG_ENDIAN_BYTE_SEX ?
				 LITTLE_ENDIAN_BYTE_SEX : BIG_ENDIAN_BYTE_SEX;
	    ofile->mh = (struct mach_header *)addr;
	    ofile->load_commands = (struct load_command *)(addr +
					sizeof(struct mach_header));
	    if(check_Mach_O(ofile) == CHECK_BAD){
		ofile_unmap(ofile);
#ifdef OFI
		return(NSObjectFileImageFormat);
#else
		return(FALSE);
#endif
	    }
	    if(object_name != NULL){
		error("file: %s is not an archive (object_name to ofile_map() "
		      "can't be specified to be other than NULL)",
		      ofile->file_name);
		goto cleanup;
	    }
	    if(arch_flag != NULL){
		if(arch_flag->cputype != ofile->mh->cputype &&
		   arch_flag->cpusubtype != ofile->mh->cpusubtype){
#ifdef OFI
		    ofile_unmap(ofile);
		    return(NSObjectFileImageArch);
#else
		    error("object file: %s does not match specified arch_flag: "
			  "%s passed to ofile_map()", ofile->file_name,
			  arch_flag->name);
		    ofile_unmap(ofile);
		    return(FALSE);
#endif
		    goto cleanup;
		}
	    }
	}
	/* see if this file is an archive file */
	else if(size >= SARMAG && strncmp(addr, ARMAG, SARMAG) == 0){
	    ofile->file_type = OFILE_ARCHIVE;
	    if(check_archive(ofile, archives_with_fat_objects) == CHECK_BAD)
		goto cleanup;
	    if(object_name != NULL){
		if(ofile_specific_member(object_name, ofile) == FALSE)
		    goto cleanup;
		if(arch_flag != NULL){
		    if(arch_flag->cputype != ofile->mh->cputype &&
		       arch_flag->cpusubtype != ofile->mh->cpusubtype){
			error("object file: %s(%.*s) does not match specified "
			    "arch_flag: %s passed to ofile_map()",
			    ofile->file_name, (int)ofile->member_name_size,
			    ofile->member_name, arch_flag->name);
			goto cleanup;
		    }
		}
	    }
	    else{
		if(arch_flag != NULL){
		    if(arch_flag->cputype != ofile->archive_cputype &&
		       arch_flag->cpusubtype != ofile->archive_cpusubtype){
			error("archive file: %s objects do not match specified "
			      "arch_flag: %s passed to ofile_map()",
			      ofile->file_name, arch_flag->name);
			goto cleanup;
		    }
		}
	    }
	}
	/* this file type is now known to be unknown to this program */
	else{
#ifndef OTOOL
unknown:
#endif
	    ofile->file_type = OFILE_UNKNOWN;
	    if(arch_flag != NULL){
#ifdef OFI
		ofile_unmap(ofile);
		return(NSObjectFileImageInappropriateFile);
#else
		error("file: %s is unknown type (arch_flag to ofile_map() "
		      "can't be specified to be other than NULL)",
		      ofile->file_name);
		ofile_unmap(ofile);
		return(FALSE);
#endif
	    }
	    if(object_name != NULL){
		error("file: %s is not an archive (object_name to ofile_map() "
		      "can't be specified to be other than NULL)",
		      ofile->file_name);
		goto cleanup;
	    }
	}
success:
	return(TRUE);

cleanup:
	ofile_unmap(ofile);
	return(FALSE);
}

/*
 * ofile_unmap() deallocates the memory associated with the specified ofile
 * struct.
 */
__private_extern__
void
ofile_unmap(
struct ofile *ofile)
{
    kern_return_t r;

	if(ofile->file_addr != NULL){
	    if((r = vm_deallocate(mach_task_self(),
				 (vm_address_t)ofile->file_addr,
				 (vm_size_t)ofile->file_size)) != KERN_SUCCESS){
		my_mach_error(r, "Can't vm_deallocate mapped memory for file: "
			      "%s", ofile->file_name);
	    }
	}
	if(ofile->file_name != NULL)
	    free(ofile->file_name);
	if(ofile->arch_flag.name != NULL)
	    free(ofile->arch_flag.name);
	memset(ofile, '\0', sizeof(struct ofile));
}

/*
 * ofile_first_arch() sets up the ofile struct for a fat file to the first arch
 * in it.
 */
__private_extern__
enum bool
ofile_first_arch(
struct ofile *ofile)
{
	if(ofile->file_type == OFILE_FAT ||
	   (ofile->file_type == OFILE_ARCHIVE &&
	    ofile->member_type == OFILE_FAT) )
	    return(ofile_specific_arch(ofile, 0));
	else{
	    error("ofile_first_arch() called and file type of: %s is not a fat "
		  "file\n", ofile->file_name);
	    return(FALSE);
	}
}

/*
 * ofile_first_arch() sets up the ofile struct for a fat file to the next arch
 * in it.
 */
__private_extern__
enum bool
ofile_next_arch(
struct ofile *ofile)
{
	if(ofile->file_type == OFILE_FAT ||
	   (ofile->file_type == OFILE_ARCHIVE &&
	    ofile->member_type == OFILE_FAT) ){
	    if(ofile->narch + 1 < ofile->fat_header->nfat_arch)
		return(ofile_specific_arch(ofile, ofile->narch + 1));
	    else
		return(FALSE);
	}
	else{
	    error("ofile_next_arch() called and file type of: %s is not a fat "
		  "file\n", ofile->file_name);
	    return(FALSE);
	}
}

/*
 * ofile_specific_arch() sets up the ofile struct for the fat file for the
 * specified narch.
 */
static
enum bool
ofile_specific_arch(
struct ofile *ofile,
unsigned long narch)
{
    char *addr;
    unsigned long size, magic;
    enum byte_sex host_byte_sex;

	ofile->narch = narch;
	ofile->arch_type = OFILE_UNKNOWN;
	if(ofile->arch_flag.name != NULL)
	    free(ofile->arch_flag.name);
	ofile->arch_flag.name = NULL;
	ofile->arch_flag.cputype = 0;
	ofile->arch_flag.cpusubtype = 0;
	ofile->archive_cputype = 0;
	ofile->archive_cpusubtype = 0;
	ofile->object_addr = NULL;
	ofile->object_size = 0;
	ofile->object_byte_sex = UNKNOWN_BYTE_SEX;
	ofile->mh = NULL;
	ofile->load_commands = NULL;

	ofile->arch_flag.cputype = ofile->fat_archs[ofile->narch].cputype;
	ofile->arch_flag.cpusubtype = ofile->fat_archs[ofile->narch].cpusubtype;
	set_arch_flag_name(&(ofile->arch_flag));


	/* Now determine the file type for this specific architecture */
	if(ofile->file_type == OFILE_FAT){
	    ofile->member_offset = 0;
	    ofile->member_addr = NULL;
	    ofile->member_size = 0;
	    ofile->member_ar_hdr = NULL;
	    ofile->member_type = OFILE_UNKNOWN;

	    size = ofile->fat_archs[ofile->narch].size;
	    addr = ofile->file_addr + ofile->fat_archs[ofile->narch].offset;
	}
	else{
	    if(ofile->file_type != OFILE_ARCHIVE ||
	       ofile->member_type != OFILE_FAT){
		error("internal error. ofile_specific_arch() called but file "
		      "is not a fat file or an archive with a fat member ");
	    }
	    size = ofile->fat_archs[ofile->narch].size;
	    addr = ofile->file_addr +
		   ofile->member_offset +
		   ofile->fat_archs[ofile->narch].offset;
	}

#ifdef OTOOL
	if(addr - ofile->file_addr > (ptrdiff_t)ofile->file_size){
	    error("fat file: %s offset to architecture %s extends past end "
		  "of file", ofile->file_name, ofile->arch_flag.name);
	    return(FALSE);
	}
	if(addr + size > ofile->file_addr + ofile->file_size)
	    size = (ofile->file_addr + ofile->file_size) - addr;
#endif /* OTOOL */

	if(size >= sizeof(struct mach_header))
	    memcpy(&magic, addr, sizeof(unsigned long));
	/* see if this file is Mach-O file */
	if(size >= sizeof(struct mach_header) &&
	   (magic == MH_MAGIC || magic == SWAP_LONG(MH_MAGIC))){
#ifdef ALIGNMENT_CHECKS
	    if(ofile->fat_archs[ofile->narch].offset %
	       sizeof(unsigned long) != 0){
		if(ofile->file_type == OFILE_ARCHIVE){
		    error("fat file: %s(%.*s) architecture %s malformed for an "
			  "object file (offset is not a multiple of sizeof("
			  "unsigned long))", ofile->file_name,
			  (int)ofile->member_name_size, ofile->member_name,
			  ofile->arch_flag.name);
		}
		else
		    error("fat file: %s architecture %s malformed for an "
			  "object file (offset is not a multiple of sizeof("
			  "unsigned long))", ofile->file_name,
			  ofile->arch_flag.name);
		goto cleanup;
	    }
#endif /* ALIGNMENT_CHECKS */
	    ofile->arch_type = OFILE_Mach_O;
	    ofile->object_addr = addr;
	    ofile->object_size = size;
	    host_byte_sex = get_host_byte_sex();
	    if(magic == MH_MAGIC)
		ofile->object_byte_sex = host_byte_sex;
	    else
		ofile->object_byte_sex =
		    host_byte_sex == BIG_ENDIAN_BYTE_SEX ?
		    LITTLE_ENDIAN_BYTE_SEX : BIG_ENDIAN_BYTE_SEX;
	    ofile->mh = (struct mach_header *)addr;
	    ofile->load_commands = (struct load_command *)(addr +
					sizeof(struct mach_header));
	    if(check_Mach_O(ofile) == CHECK_BAD)
		goto cleanup;
	}
	/* see if this file is an archive file */
	else if(size >= SARMAG && strncmp(addr, ARMAG, SARMAG) == 0){
	    ofile->arch_type = OFILE_ARCHIVE;
	    if(check_archive(ofile, FALSE) == CHECK_BAD)
		goto cleanup;
#ifdef ALIGNMENT_CHECKS
	    if(ofile->archive_cputype != 0 &&
	       ofile->fat_archs[ofile->narch].offset %
		sizeof(unsigned long) != 0){
		error("fat file: %s architecture %s malformed archive that "
		      "contains object files (offset to archive is not a "
		      "multiple of sizeof(unsigned long))",
		      ofile->file_name, ofile->arch_flag.name);
		goto cleanup;
	    }
#endif /* ALIGNMENT_CHECKS */
	}
	/*
	 * This type for this architecture is now known to be unknown to this
	 * program.
	 */
	else{
	    ofile->arch_type = OFILE_UNKNOWN;
	}
	return(TRUE);
cleanup:
	ofile->narch = 0;;
	ofile->arch_type = OFILE_UNKNOWN;
	if(ofile->arch_flag.name != NULL)
	    free(ofile->arch_flag.name);
	ofile->arch_flag.name = NULL;
	ofile->arch_flag.cputype = 0;
	ofile->arch_flag.cpusubtype = 0;
	if(ofile->file_type != OFILE_ARCHIVE){
	    ofile->member_offset = 0;
	    ofile->member_addr = NULL;
	    ofile->member_size = 0;
	    ofile->member_ar_hdr = NULL;
	    ofile->member_type = OFILE_UNKNOWN;
	}
	ofile->archive_cputype = 0;
	ofile->archive_cpusubtype = 0;
	ofile->object_addr = NULL;
	ofile->object_size = 0;
	ofile->object_byte_sex = UNKNOWN_BYTE_SEX;
	ofile->mh = NULL;
	ofile->load_commands = NULL;
	return(FALSE);
}

/*
 * ofile_first_member() set up the ofile structure (the member_* fields and
 * the object file fields if the first member is an object file) for the first
 * member.
 */
__private_extern__
enum bool
ofile_first_member(
struct ofile *ofile)
{
    char *addr;
    unsigned long size, offset, magic;
    enum byte_sex host_byte_sex;
    struct ar_hdr *ar_hdr;
    unsigned long ar_name_size;

	/* These fields are to be filled in by this routine, clear them first */
	ofile->member_offset = 0;
	ofile->member_addr = NULL;
	ofile->member_size = 0;
	ofile->member_ar_hdr = NULL;
	ofile->member_name = NULL;
	ofile->member_name_size = 0;
	ofile->member_type = OFILE_UNKNOWN;
	ofile->object_addr = NULL;
	ofile->object_size = 0;
	ofile->object_byte_sex = UNKNOWN_BYTE_SEX;
	ofile->mh = NULL;
	ofile->load_commands = NULL;

	/*
	 * Get the address and size of the archive.
	 */
	if(ofile->file_type == OFILE_FAT){
	    if(ofile->arch_type != OFILE_ARCHIVE){
		error("ofile_first_member() called on fat file: %s with a "
		      "non-archive architecture or no architecture selected\n",
		      ofile->file_name);
		return(FALSE);
	    }
	    addr = ofile->file_addr + ofile->fat_archs[ofile->narch].offset;
	    size = ofile->fat_archs[ofile->narch].size;
	}
	else if(ofile->file_type == OFILE_ARCHIVE){
	    addr = ofile->file_addr;
	    size = ofile->file_size;
	}
	else{
	    error("ofile_first_member() called and file type of %s is "
		  "OFILE_UNKNOWN\n", ofile->file_name);
	    return(FALSE);
	}
#ifdef OTOOL
	if((addr + SARMAG) - ofile->file_addr > (ptrdiff_t)ofile->file_size){
	    archive_error(ofile, "offset to first member extends past the end "
			  "of the file");
	    return(FALSE);
	}
	if(addr + size > ofile->file_addr + ofile->file_size)
	    size = (ofile->file_addr + ofile->file_size) - addr;
#endif /* OTOOL */
	if(size < SARMAG || strncmp(addr, ARMAG, SARMAG) != 0){
	    archive_error(ofile, "internal error. ofile_first_member() "
			  "called but file does not have an archive magic "
			  "string");
	    return(FALSE);
	}

	offset = SARMAG;
	if(offset != size && offset + sizeof(struct ar_hdr) > size){
	    archive_error(ofile, "truncated or malformed (archive header of "
			  "first member extends past the end of the file)");
	    return(FALSE);
	}

	/* check for empty archive */
	if(size == offset)
	    return(FALSE);

	/* now we know there is a first member so set it up */
	ar_hdr = (struct ar_hdr *)(addr + offset);
	offset += sizeof(struct ar_hdr);
	ofile->member_offset = offset;
	ofile->member_addr = addr + offset;
	ofile->member_size = strtoul(ar_hdr->ar_size, NULL, 10);
	ofile->member_ar_hdr = ar_hdr;
	ofile->member_type = OFILE_UNKNOWN;
	ofile->member_name = ar_hdr->ar_name;
	if(strncmp(ofile->member_name, AR_EFMT1, sizeof(AR_EFMT1) - 1) == 0){
	    ofile->member_name = ar_hdr->ar_name + sizeof(struct ar_hdr);
	    ar_name_size = strtoul(ar_hdr->ar_name + sizeof(AR_EFMT1) - 1,
				   NULL, 10);
	    ofile->member_name_size = ar_name_size;
	    ofile->member_offset += ar_name_size;
	    ofile->member_addr += ar_name_size;
	    ofile->member_size -= ar_name_size;
	}
	else{
	    ofile->member_name_size = size_ar_name(ar_hdr);
	    ar_name_size = 0;
	}

	host_byte_sex = get_host_byte_sex();

	if(ofile->member_size > sizeof(unsigned long)){
	    memcpy(&magic, ofile->member_addr, sizeof(unsigned long));
#ifdef __BIG_ENDIAN__
	    if(magic == FAT_MAGIC)
#endif /* __BIG_ENDIAN__ */
#ifdef __LITTLE_ENDIAN__
	    if(magic == SWAP_LONG(FAT_MAGIC))
#endif /* __LITTLE_ENDIAN__ */
	    {
		ofile->member_type = OFILE_FAT;
		ofile->fat_header =
			(struct fat_header *)(ofile->member_addr);
#ifdef __LITTLE_ENDIAN__
		swap_fat_header(ofile->fat_header, host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
		if(sizeof(struct fat_header) +
		   ofile->fat_header->nfat_arch *
		   sizeof(struct fat_arch) > ofile->member_size){
		    archive_member_error(ofile, "fat file truncated or "
			    "malformed (fat_arch structs would extend past "
			    "the end of the archive member)");
		    goto fatcleanup;
		}
		ofile->fat_archs = (struct fat_arch *)
		    (ofile->member_addr + sizeof(struct fat_header));
#ifdef __LITTLE_ENDIAN__
		swap_fat_arch(ofile->fat_archs,
			      ofile->fat_header->nfat_arch, host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
		if(check_fat_object_in_archive(ofile) == FALSE)
		    goto fatcleanup;
	    }
	    else if(size - (offset + ar_name_size) >=
		    sizeof(struct mach_header) &&
	       (magic == MH_MAGIC || magic == SWAP_LONG(MH_MAGIC))){
#ifdef ALIGNMENT_CHECKS
		if((offset + ar_name_size) % sizeof(unsigned long) != 0){
		    archive_member_error(ofile, "offset in archive not "
			"a multiple of sizeof(unsigned long) (must be "
			"since member is an object file)");
		    goto cleanup;
		}
#endif /* ALIGNMENT_CHECKS */
		ofile->member_type = OFILE_Mach_O;
		ofile->object_addr = ofile->member_addr;
		ofile->object_size = ofile->member_size;
		if(magic == MH_MAGIC)
		    ofile->object_byte_sex = host_byte_sex;
		else
		    ofile->object_byte_sex =
			   host_byte_sex == BIG_ENDIAN_BYTE_SEX ?
			   LITTLE_ENDIAN_BYTE_SEX : BIG_ENDIAN_BYTE_SEX;
		ofile->mh = (struct mach_header *)(ofile->object_addr);
		ofile->load_commands = (struct load_command *)
		    (ofile->object_addr + sizeof(struct mach_header));
		if(check_Mach_O(ofile) == CHECK_BAD)
		    goto cleanup;
	    }
	}
	return(TRUE);

fatcleanup:
	ofile->fat_header = NULL;
	ofile->fat_archs = NULL;
cleanup:
	ofile->member_offset = 0;
	ofile->member_addr = 0;
	ofile->member_size = 0;
	ofile->member_ar_hdr = NULL;
	ofile->member_name = NULL;
	ofile->member_name_size = 0;
	ofile->member_type = OFILE_UNKNOWN;
	ofile->object_addr = NULL;
	ofile->object_size = 0;
	ofile->object_byte_sex = UNKNOWN_BYTE_SEX;
	ofile->mh = NULL;
	ofile->load_commands = NULL;
	return(FALSE);
}

/*
 * ofile_next_member() set up the ofile structure (the member_* fields and
 * the object file fields if the next member is an object file) for the next
 * member.
 */
__private_extern__
enum bool
ofile_next_member(
struct ofile *ofile)
{
    char *addr;
    unsigned long size, offset, magic;
    enum byte_sex host_byte_sex;
    struct ar_hdr *ar_hdr;
    unsigned long ar_name_size;

	/*
	 * Get the address and size of the archive.
	 */
	if(ofile->file_type == OFILE_FAT){
	    if(ofile->arch_type != OFILE_ARCHIVE){
		error("ofile_next_member() called on fat file: %s with a "
		      "non-archive architecture or no architecture selected\n",
		      ofile->file_name);
		return(FALSE);
	    }
	    addr = ofile->file_addr + ofile->fat_archs[ofile->narch].offset;
	    size = ofile->fat_archs[ofile->narch].size;
	}
	else if(ofile->file_type == OFILE_ARCHIVE){
	    addr = ofile->file_addr;
	    size = ofile->file_size;
	}
	else{
	    error("ofile_next_member() called and file type of %s is "
		  "OFILE_UNKNOWN\n", ofile->file_name);
	    return(FALSE);
	}
	if(size < SARMAG || strncmp(addr, ARMAG, SARMAG) != 0){
	    archive_error(ofile, "internal error. ofile_next_member() "
			  "called but file does not have an archive magic "
			  "string");
	    return(FALSE);
	}
	if(ofile->member_ar_hdr == NULL){
	    archive_error(ofile, "internal error. ofile_next_member() called "
			  "but the ofile struct does not have an archive "
			  "member selected");
	    return(FALSE);
	}

	/* figure out the offset to the next member */
	offset = ofile->member_offset + round(ofile->member_size,sizeof(short));
#ifdef OTOOL
	if((addr - ofile->file_addr) + offset > ofile->file_size){
	    archive_error(ofile, "offset to next member extends past the end "
			  "of the file");
	    return(FALSE);
	}
#endif /* OTOOL */
	/* if now at the end of the file then no more members */
	if(offset == size)
	     goto cleanup;
	if(offset > size){
	    archive_error(ofile, "truncated or malformed (archive header of "
			  "next member extends past the end of the file)");
	    return(FALSE);
	}

	/* now we know there is a next member so set it up */
	ar_hdr = (struct ar_hdr *)(addr + offset);
	offset += sizeof(struct ar_hdr);
	ofile->member_offset = offset;
	ofile->member_addr = addr + offset;
	ofile->member_size = strtoul(ar_hdr->ar_size, NULL, 10);
	ofile->member_ar_hdr = ar_hdr;
	ofile->member_name = ar_hdr->ar_name;
	if(strncmp(ofile->member_name, AR_EFMT1, sizeof(AR_EFMT1) - 1) == 0){
	    ofile->member_name = ar_hdr->ar_name + sizeof(struct ar_hdr);
	    ar_name_size = strtoul(ar_hdr->ar_name + sizeof(AR_EFMT1) - 1,
				   NULL, 10);
	    ofile->member_name_size = ar_name_size;
	    ofile->member_offset += ar_name_size;
	    ofile->member_addr += ar_name_size;
	    ofile->member_size -= ar_name_size;
	}
	else{
	    ofile->member_name_size = size_ar_name(ar_hdr);
	    ar_name_size = 0;
	}
	ofile->member_type = OFILE_UNKNOWN;
	ofile->object_addr = NULL;
	ofile->object_size = 0;
	ofile->object_byte_sex = UNKNOWN_BYTE_SEX;
	ofile->mh = NULL;
	ofile->load_commands = NULL;

	host_byte_sex = get_host_byte_sex();

	if(ofile->member_size > sizeof(unsigned long)){
	    memcpy(&magic, ofile->member_addr, sizeof(unsigned long));
#ifdef __BIG_ENDIAN__
	    if(magic == FAT_MAGIC)
#endif /* __BIG_ENDIAN__ */
#ifdef __LITTLE_ENDIAN__
	    if(magic == SWAP_LONG(FAT_MAGIC))
#endif /* __LITTLE_ENDIAN__ */
	    {
		ofile->member_type = OFILE_FAT;
		ofile->fat_header = (struct fat_header *)(ofile->member_addr);
#ifdef __LITTLE_ENDIAN__
		swap_fat_header(ofile->fat_header, host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
		if(sizeof(struct fat_header) +
		   ofile->fat_header->nfat_arch *
		   sizeof(struct fat_arch) > ofile->member_size){
		    archive_member_error(ofile, "fat file truncated or "
			    "malformed (fat_arch structs would extend past "
			    "the end of the archive member)");
		    goto cleanup;
		}
		ofile->fat_archs = (struct fat_arch *)(ofile->member_addr +
					       sizeof(struct fat_header));
#ifdef __LITTLE_ENDIAN__
		swap_fat_arch(ofile->fat_archs,
			      ofile->fat_header->nfat_arch, host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
		if(check_fat_object_in_archive(ofile) == FALSE)
		    goto cleanup;
	    }
	    else if(size - (offset + ar_name_size) >=
		    sizeof(struct mach_header) &&
		    (magic == MH_MAGIC || magic == SWAP_LONG(MH_MAGIC))){
#ifdef ALIGNMENT_CHECKS
		if((offset + ar_name_size) % sizeof(unsigned long) != 0){
		    archive_member_error(ofile, "offset in archive not "
			"a multiple of sizeof(unsigned long) (must be "
			"since member is an object file)");
		    goto cleanup;
		}
#endif /* ALIGNMENT_CHECKS */
		ofile->member_type = OFILE_Mach_O;
		ofile->object_addr = ofile->member_addr;
		ofile->object_size = ofile->member_size;
		if(magic == MH_MAGIC)
		    ofile->object_byte_sex = host_byte_sex;
		else
		    ofile->object_byte_sex =
			   host_byte_sex == BIG_ENDIAN_BYTE_SEX ?
			   LITTLE_ENDIAN_BYTE_SEX : BIG_ENDIAN_BYTE_SEX;
		ofile->mh = (struct mach_header *)ofile->object_addr;
		ofile->load_commands = (struct load_command *)
			   (ofile->object_addr + sizeof(struct mach_header));
		if(check_Mach_O(ofile) == CHECK_BAD)
		    goto cleanup;
	    }
	}
	return(TRUE);

cleanup:
	if(ofile->member_type == OFILE_FAT){
	    ofile->fat_header = NULL;
	    ofile->fat_archs = NULL;
	}
	ofile->member_offset = 0;
	ofile->member_addr = NULL;
	ofile->member_size = 0;
	ofile->member_ar_hdr = NULL;
	ofile->member_name = NULL;
	ofile->member_name_size = 0;
	ofile->member_type = OFILE_UNKNOWN;
	ofile->object_addr = NULL;
	ofile->object_size = 0;
	ofile->object_byte_sex = UNKNOWN_BYTE_SEX;
	ofile->mh = NULL;
	ofile->load_commands = NULL;
	return(FALSE);
}

/*
 * ofile_specific_member() set up the ofile structure (the member_* fields and
 * the object file fields if the member is an object file) for the specified
 * member member_name.
 */
__private_extern__
enum bool
ofile_specific_member(
const char *member_name,
struct ofile *ofile)
{
    long i;
    char *addr;
    unsigned long size, offset, magic;
    enum byte_sex host_byte_sex;
    char *ar_name;
    unsigned long ar_name_size;
    struct ar_hdr *ar_hdr;

	/* These fields are to be filled in by this routine, clear them first */
	ofile->member_offset = 0;
	ofile->member_addr = NULL;
	ofile->member_size = 0;
	ofile->member_ar_hdr = NULL;
	ofile->member_name = NULL;
	ofile->member_name_size = 0;
	ofile->member_type = OFILE_UNKNOWN;
	ofile->object_addr = NULL;
	ofile->object_size = 0;
	ofile->object_byte_sex = UNKNOWN_BYTE_SEX;
	ofile->mh = NULL;
	ofile->load_commands = NULL;

	/*
	 * Get the address and size of the archive.
	 */
	if(ofile->file_type == OFILE_FAT){
	    if(ofile->arch_type != OFILE_ARCHIVE){
		error("ofile_specific_member() called on fat file: %s with a "
		      "non-archive architecture or no architecture selected\n",
		      ofile->file_name);
		return(FALSE);
	    }
	    addr = ofile->file_addr + ofile->fat_archs[ofile->narch].offset;
	    size = ofile->fat_archs[ofile->narch].size;
	}
	else if(ofile->file_type == OFILE_ARCHIVE){
	    addr = ofile->file_addr;
	    size = ofile->file_size;
	}
	else{
	    error("ofile_specific_member() called and file type of %s is "
		  "OFILE_UNKNOWN\n", ofile->file_name);
	    return(FALSE);
	}
	if(size < SARMAG || strncmp(addr, ARMAG, SARMAG) != 0){
	    archive_error(ofile, "internal error. ofile_specific_member() "
			  "called but file does not have an archive magic "
			  "string");
	    return(FALSE);
	}

	offset = SARMAG;
	if(offset != size && offset + sizeof(struct ar_hdr) > size){
	    archive_error(ofile, "truncated or malformed (archive header of "
			  "first member extends past the end of the file)");
	    return(FALSE);
	}
	while(size > offset){
	    ar_hdr = (struct ar_hdr *)(addr + offset);
	    offset += sizeof(struct ar_hdr);
	    if(strncmp(ar_hdr->ar_name, AR_EFMT1, sizeof(AR_EFMT1) - 1) == 0){
#ifdef OTOOL
		if(check_extend_format_1(ofile, ar_hdr, size - offset,
				&ar_name_size) == CHECK_BAD){
		    i = size_ar_name(ar_hdr);
		    ar_name = ar_hdr->ar_name;
		    ar_name_size = 0;
		}
		else
#endif /* OTOOL */
		{
		    i = strtoul(ar_hdr->ar_name + sizeof(AR_EFMT1) - 1,NULL,10);
		    ar_name = ar_hdr->ar_name + sizeof(struct ar_hdr);
		    ar_name_size = i;
		}
	    }
	    else{
		i = size_ar_name(ar_hdr);
		ar_name = ar_hdr->ar_name;
		ar_name_size = 0;
	    }
	    if(i > 0 && strncmp(ar_name, member_name, i) == 0){

		ofile->member_name = ar_name;
		ofile->member_name_size = i;
		ofile->member_offset = offset + ar_name_size;
		ofile->member_addr = addr + offset + ar_name_size;
		ofile->member_size = strtoul(ar_hdr->ar_size, NULL, 10) -
				     ar_name_size;
		ofile->member_ar_hdr = ar_hdr;
		ofile->member_type = OFILE_UNKNOWN;

		host_byte_sex = get_host_byte_sex();

		if(ofile->member_size > sizeof(unsigned long)){
		    memcpy(&magic, addr + offset + ar_name_size,
			   sizeof(unsigned long));
#ifdef __BIG_ENDIAN__
		    if(magic == FAT_MAGIC)
#endif /* __BIG_ENDIAN__ */
#ifdef __LITTLE_ENDIAN__
		    if(magic == SWAP_LONG(FAT_MAGIC))
#endif /* __LITTLE_ENDIAN__ */
		    {
			ofile->member_type = OFILE_FAT;
			ofile->fat_header =
			    (struct fat_header *)(addr + offset + ar_name_size);
#ifdef __LITTLE_ENDIAN__
			swap_fat_header(ofile->fat_header, host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
			if(sizeof(struct fat_header) +
			   ofile->fat_header->nfat_arch *
			   sizeof(struct fat_arch) > ofile->member_size){
			    archive_member_error(ofile, "fat file truncated or "
				    "malformed (fat_arch structs would extend "
				    "past the end of the archive member)");
			    goto fatcleanup;
			}
			ofile->fat_archs =
			    (struct fat_arch *)(addr + offset + ar_name_size +
					        sizeof(struct fat_header));
#ifdef __LITTLE_ENDIAN__
			swap_fat_arch(ofile->fat_archs,
				      ofile->fat_header->nfat_arch,
				      host_byte_sex);
#endif /* __LITTLE_ENDIAN__ */
			if(check_fat_object_in_archive(ofile) == FALSE)
			    goto fatcleanup;
		    }
		    else if(size - (offset + ar_name_size) >=
			    sizeof(struct mach_header) &&
			   (magic == MH_MAGIC || magic == SWAP_LONG(MH_MAGIC))){
#ifdef ALIGNMENT_CHECKS
			if((offset + ar_name_size) %sizeof(unsigned long) != 0){
			    archive_member_error(ofile, "offset in archive not "
				"a multiple of sizeof(unsigned long) (must be "
				"since member is an object file)");
			    goto cleanup;
			}
#endif /* ALIGNMENT_CHECKS */
			ofile->member_type = OFILE_Mach_O;
			ofile->object_addr = ofile->member_addr;
			ofile->object_size = ofile->member_size;
			if(magic == MH_MAGIC)
			    ofile->object_byte_sex = host_byte_sex;
			else
			    ofile->object_byte_sex =
				   host_byte_sex == BIG_ENDIAN_BYTE_SEX ?
				   LITTLE_ENDIAN_BYTE_SEX : BIG_ENDIAN_BYTE_SEX;
			ofile->mh = (struct mach_header *)ofile->object_addr;
			ofile->load_commands = (struct load_command *)
			    (ofile->object_addr + sizeof(struct mach_header));
			if(check_Mach_O(ofile) == CHECK_BAD)
			    goto cleanup;
		    }
		}
		return(TRUE);
	    }
	    offset += round(strtoul(ar_hdr->ar_size, NULL, 10),
			    sizeof(short));
	}
	archive_error(ofile, "does not contain a member named: %s",
		      member_name);
fatcleanup:
	ofile->fat_header = NULL;
	ofile->fat_archs = NULL;
cleanup:
	ofile->member_offset = 0;
	ofile->member_addr = NULL;
	ofile->member_size = 0;
	ofile->member_ar_hdr = NULL;
	ofile->member_name = NULL;
	ofile->member_name_size = 0;
	ofile->member_type = OFILE_UNKNOWN;
	ofile->object_addr = NULL;
	ofile->object_size = 0;
	ofile->object_byte_sex = UNKNOWN_BYTE_SEX;
	ofile->mh = NULL;
	ofile->load_commands = NULL;
	return(FALSE);
}

/*
 * ofile_first_module() set up the ofile structure (the dylib_module field)
 * for the first module of an MH_DYLIB or MH_DYLIB_STUB file.
 */
__private_extern__
enum bool
ofile_first_module(
struct ofile *ofile)
{
    unsigned long i;
    struct symtab_command *st;
    struct dysymtab_command *dyst;
    struct load_command *lc;
    enum bool swapped;
    enum byte_sex host_byte_sex;
    struct dylib_module m;
    char *strings;

	/* These fields are to be filled in by this routine, clear them first */
	ofile->modtab = NULL;
	ofile->nmodtab = 0;
	ofile->dylib_module = NULL;
	ofile->dylib_module_name = NULL;

	if(ofile->file_type == OFILE_FAT){
	    if(ofile->arch_type != OFILE_Mach_O &&
	       (ofile->mh->filetype != MH_DYLIB &&
	        ofile->mh->filetype != MH_DYLIB_STUB)){
		error("ofile_first_module() called on fat file: %s with a "
		      "non-MH_DYLIB architecture or no architecture selected\n",
		      ofile->file_name);
		return(FALSE);
	    }
	}
	else if(ofile->arch_type != OFILE_Mach_O &&
	        (ofile->mh->filetype != MH_DYLIB &&
	         ofile->mh->filetype != MH_DYLIB_STUB)){
	    error("ofile_first_module() called and file type of %s is "
		  "non-MH_DYLIB\n", ofile->file_name);
	    return(FALSE);
	}

	st = NULL;
	dyst = NULL;
	lc = ofile->load_commands;
	for(i = 0; i < ofile->mh->ncmds; i++){
	    if(st == NULL && lc->cmd == LC_SYMTAB){
		st = (struct symtab_command *)lc;
	    }
	    else if(lc->cmd == LC_DYSYMTAB){
		dyst = (struct dysymtab_command *)lc;
	    }
	    lc = (struct load_command *)((char *)lc + lc->cmdsize);
	}
	if(st == NULL || dyst == NULL){
#ifndef OTOOL
	    Mach_O_error(ofile, "MH_DYLIB format error (does not have a symbol "
		"table and/or a dynamic symbol table)");
#endif
	    return(FALSE);
	}
	if(dyst->nmodtab == 0)
	    return(FALSE);

	ofile->nmodtab = dyst->nmodtab;
	ofile->modtab = (struct dylib_module *)(ofile->object_addr +
						dyst->modtaboff);
	ofile->dylib_module = ofile->modtab;
	host_byte_sex = get_host_byte_sex();
	swapped = (enum bool)(host_byte_sex != ofile->object_byte_sex);
	strings = (char *)(ofile->object_addr + st->stroff);
	m = *ofile->dylib_module;
	if(swapped)
	    swap_dylib_module(&m, 1, host_byte_sex);
	if(check_dylib_module(ofile, st, dyst, strings, 0) == CHECK_BAD)
	    return(FALSE);
	ofile->dylib_module_name = strings + m.module_name;
	return(TRUE);
}

/*
 * ofile_next_module() set up the ofile structure (the dylib_module field)
 * for the next module of an MH_DYLIB or MH_DYLIB_STUB file.
 */
__private_extern__
enum bool
ofile_next_module(
struct ofile *ofile)
{
    unsigned long i, module_index;
    struct symtab_command *st;
    struct dysymtab_command *dyst;
    struct load_command *lc;
    enum bool swapped;
    enum byte_sex host_byte_sex;
    struct dylib_module m;
    char *strings;

	if(ofile->file_type == OFILE_FAT){
	    if(ofile->arch_type != OFILE_Mach_O &&
	       (ofile->mh->filetype != MH_DYLIB &&
	        ofile->mh->filetype != MH_DYLIB_STUB)){
		error("ofile_next_module() called on fat file: %s with a "
		      "non-MH_DYLIB architecture or no architecture selected\n",
		      ofile->file_name);
		return(FALSE);
	    }
	}
	else if(ofile->arch_type != OFILE_Mach_O &&
	        (ofile->mh->filetype != MH_DYLIB &&
	         ofile->mh->filetype != MH_DYLIB_STUB)){
	    error("ofile_next_module() called and file type of %s is "
		  "non-MH_DYLIB\n", ofile->file_name);
	    return(FALSE);
	}
	st = NULL;
	dyst = NULL;
	lc = ofile->load_commands;
	for(i = 0; i < ofile->mh->ncmds; i++){
	    if(st == NULL && lc->cmd == LC_SYMTAB){
		st = (struct symtab_command *)lc;
	    }
	    else if(lc->cmd == LC_DYSYMTAB){
		dyst = (struct dysymtab_command *)lc;
	    }
	    lc = (struct load_command *)((char *)lc + lc->cmdsize);
	}
	if(st == NULL || dyst == NULL){
#ifndef OTOOL
	    Mach_O_error(ofile, "MH_DYLIB format error (does not have a symbol "
		"table and/or a dynamic symbol table)");
#endif
	    return(FALSE);
	}

	module_index = (ofile->dylib_module + 1) - ofile->modtab;
	if(module_index >= ofile->nmodtab)
	    return(FALSE);

	ofile->dylib_module++;
	host_byte_sex = get_host_byte_sex();
	swapped = (enum bool)(host_byte_sex != ofile->object_byte_sex);
	strings = (char *)(ofile->object_addr + st->stroff);
	m = *ofile->dylib_module;
	if(swapped)
	    swap_dylib_module(&m, 1, host_byte_sex);
	if(check_dylib_module(ofile, st, dyst, strings, module_index) ==
	   CHECK_BAD)
	    return(FALSE);
	ofile->dylib_module_name = strings + m.module_name;
	return(TRUE);
}

/*
 * ofile_specific_module() set up the ofile structure (the dylib_module fields)
 * for the specified module, module_name, of an MH_DYLIB or an MH_DYLIB_STUB
 * file.
 */
__private_extern__
enum bool
ofile_specific_module(
const char *module_name,
struct ofile *ofile)
{
    unsigned long i;
    enum bool swapped;
    enum byte_sex host_byte_sex;
    struct symtab_command *st;
    struct dysymtab_command *dyst;
    struct load_command *lc;
    struct dylib_module *p, m;
    char *strings;

	/* These fields are to be filled in by this routine, clear them first */
	ofile->modtab = NULL;
	ofile->nmodtab = 0;
	ofile->dylib_module = NULL;
	ofile->dylib_module_name = NULL;

	if(ofile->file_type == OFILE_FAT){
	    if(ofile->arch_type != OFILE_Mach_O &&
	       (ofile->mh->filetype != MH_DYLIB &&
	        ofile->mh->filetype != MH_DYLIB_STUB)){
		error("ofile_specific_module() called on fat file: %s with a "
		      "non-MH_DYLIB architecture or no architecture selected\n",
		      ofile->file_name);
		return(FALSE);
	    }
	}
	else if(ofile->arch_type != OFILE_Mach_O &&
	        (ofile->mh->filetype != MH_DYLIB &&
	         ofile->mh->filetype != MH_DYLIB_STUB)){
	    error("ofile_specific_module() called and file type of %s is "
		  "non-MH_DYLIB\n", ofile->file_name);
	    return(FALSE);
	}

	st = NULL;
	dyst = NULL;
	lc = ofile->load_commands;
	for(i = 0; i < ofile->mh->ncmds; i++){
	    if(st == NULL && lc->cmd == LC_SYMTAB){
		st = (struct symtab_command *)lc;
	    }
	    else if(lc->cmd == LC_DYSYMTAB){
		dyst = (struct dysymtab_command *)lc;
	    }
	    lc = (struct load_command *)((char *)lc + lc->cmdsize);
	}
	if(st == NULL || dyst == NULL){
#ifndef OTOOL
	    Mach_O_error(ofile, "MH_DYLIB format error (does not have a symbol "
		"table and/or a dynamic symbol table)");
#endif
	    return(FALSE);
	}
	if(dyst->nmodtab == 0)
	    return(FALSE);

	host_byte_sex = get_host_byte_sex();
	swapped = (enum bool)(host_byte_sex != ofile->object_byte_sex);
	strings = (char *)(ofile->object_addr + st->stroff);
	ofile->nmodtab = dyst->nmodtab;
	ofile->modtab = (struct dylib_module *)(ofile->object_addr +
						dyst->modtaboff);
	p = ofile->modtab;
	for(i = 0; i < dyst->nmodtab; i++){
	    m = *p;
	    if(swapped)
		swap_dylib_module(&m, 1, host_byte_sex);
	    ofile->dylib_module = p;
	    if(check_dylib_module(ofile, st, dyst, strings, i) == CHECK_BAD)
		return(FALSE);
	    if(strcmp(module_name, strings + m.module_name) == 0){
		ofile->dylib_module_name = strings + m.module_name;
		return(TRUE);
	    }
	    p++;
	}
#ifndef OTOOL
	Mach_O_error(ofile, "does not contain a module named: %s", module_name);
#endif
	ofile->modtab = NULL;
	ofile->nmodtab = 0;
	ofile->dylib_module = NULL;
	ofile->dylib_module_name = NULL;
	return(FALSE);
}

#ifdef DEBUG
__private_extern__
void
ofile_print(
struct ofile *ofile)
{
	printf("file_name = %s\n", ofile->file_name);
	printf("file_addr = 0x%x\n", (unsigned int)ofile->file_addr);
	printf("file_size = 0x%x\n", (unsigned int)ofile->file_size);
	printf("file_type = 0x%x\n", (unsigned int)ofile->file_type);
	printf("fat_header = 0x%x\n", (unsigned int)ofile->fat_header);
	printf("fat_archs = 0x%x\n", (unsigned int)ofile->fat_archs);
	printf("narch = 0x%x\n", (unsigned int)ofile->narch);
	printf("arch_type = 0x%x\n", (unsigned int)ofile->arch_type);
	printf("arch_flag.name = %s\n", ofile->arch_flag.name);
	printf("arch_flag.cputype = 0x%x\n",
		(unsigned int)ofile->arch_flag.cputype);
	printf("arch_flag.cpusubtype = 0x%x\n",
		(unsigned int)ofile->arch_flag.cpusubtype);
	printf("member_offset = 0x%x\n", (unsigned int)ofile->member_offset);
	printf("member_addr = 0x%x\n", (unsigned int)ofile->member_addr);
	printf("member_size = 0x%x\n", (unsigned int)ofile->member_size);
	printf("member_ar_hdr = 0x%x\n", (unsigned int)ofile->member_ar_hdr);
	printf("member_type = 0x%x\n", (unsigned int)ofile->member_type);
	printf("archive_cputype = 0x%x\n",
		(unsigned int)ofile->archive_cputype);
	printf("archive_cpusubtype = 0x%x\n",
		(unsigned int)ofile->archive_cpusubtype);
	printf("object_addr = 0x%x\n", (unsigned int)ofile->object_addr);
	printf("object_size = 0x%x\n", (unsigned int)ofile->object_size);
	printf("object_byte_sex = 0x%x\n",
		(unsigned int)ofile->object_byte_sex);
	printf("mh = 0x%x\n", (unsigned int)ofile->mh);
	printf("load_commands = 0x%x\n", (unsigned int)ofile->load_commands);
}
#endif /* DEBUG */

/*
 * check_fat() checks the fat ofile for correctness (the fat_header and
 * fat_archs are assumed to be in the host byte sex).
 */
static
enum check_type
check_fat(
struct ofile *ofile)
{
#ifdef OTOOL
	return(CHECK_GOOD);
#else /* !defined OTOOL */

    unsigned long i, j;

	if(ofile->file_type != OFILE_FAT){
	    error("internal error. check_fat() call and file type of: %s is "
		  "not OFILE_FAT\n", ofile->file_name);
	    return(CHECK_BAD);
	}
	if(ofile->fat_header->nfat_arch == 0){
	    error("fat file: %s malformed (contains zero architecture types)",
		  ofile->file_name);
	    return(CHECK_BAD);
	}
	for(i = 0; i < ofile->fat_header->nfat_arch; i++){
	    if(ofile->fat_archs[i].offset + ofile->fat_archs[i].size >
	       ofile->file_size){
		error("fat file: %s truncated or malformed (offset plus size "
		      "of cputype (%d) cpusubtype (%d) extends past the "
		      "end of the file)", ofile->file_name,
		      ofile->fat_archs[i].cputype,
		      ofile->fat_archs[i].cpusubtype);
		return(CHECK_BAD);
	    }
	    if(ofile->fat_archs[i].align > MAXSECTALIGN){
		error("fat file: %s align (2^%lu) too large for cputype (%d) "
		      "cpusubtype (%d) (maximum 2^%d)", ofile->file_name,
		      ofile->fat_archs[i].align, ofile->fat_archs[i].cputype,
		      ofile->fat_archs[i].cpusubtype, MAXSECTALIGN);
		return(CHECK_BAD);
	    }
	    if(ofile->fat_archs[i].offset %
	       (1 << ofile->fat_archs[i].align) != 0){
		error("fat file: %s offset: %lu for cputype (%d) cpusubtype "
		      "(%d)) not aligned on it's alignment (2^%lu)",
		      ofile->file_name,
		      ofile->fat_archs[i].offset,
		      ofile->fat_archs[i].cputype,
		      ofile->fat_archs[i].cpusubtype,
		      ofile->fat_archs[i].align);
		return(CHECK_BAD);
	    }
	}
	for(i = 0; i < ofile->fat_header->nfat_arch; i++){
	    for(j = i + 1; j < ofile->fat_header->nfat_arch; j++){
		if(ofile->fat_archs[i].cputype ==
		     ofile->fat_archs[j].cputype &&
		   ofile->fat_archs[i].cpusubtype ==
		     ofile->fat_archs[j].cpusubtype){
		    error("fat file: %s contains two of the same "
			  "architecture (cputype (%d) cpusubtype (%d))",
			  ofile->file_name, ofile->fat_archs[i].cputype,
			  ofile->fat_archs[i].cpusubtype);
		    return(CHECK_BAD);
		}
	    }
	}
	return(CHECK_GOOD);
#endif /* OTOOL */
}

/*
 * check_fat_object_in_archive() checks the fat object file which is a member
 * of a thin archive for correctness (the fat_header and fat_archs are assumed
 * to be in the host byte sex).  This is not a legal form but allowed when
 * archives_with_fat_objects is TRUE when ofile_map() is called.
 *
 */
static
enum check_type
check_fat_object_in_archive(
struct ofile *ofile)
{
    unsigned long i, j, magic;

	if(ofile->file_type != OFILE_ARCHIVE){
	    error("internal error. check_fat_object_in_archive() called and "
		  "file type of: %s is not OFILE_ARCHIVE\n", ofile->file_name);
	    return(CHECK_BAD);
	}
	if(ofile->fat_header->nfat_arch == 0){
	    archive_member_error(ofile, "fat file malformed (contains zero "
				 "architecture types)");
	    return(CHECK_BAD);
	}
	for(i = 0; i < ofile->fat_header->nfat_arch; i++){
	    if(ofile->fat_archs[i].offset + ofile->fat_archs[i].size >
	       ofile->member_size){
		archive_member_error(ofile, "fat file truncated or malformed "
			"(offset plus size of cputype (%d) cpusubtype (%d) "
			"extends past the end of the file)", 
		        ofile->fat_archs[i].cputype,
		        ofile->fat_archs[i].cpusubtype);
		return(CHECK_BAD);
	    }
	    if(ofile->fat_archs[i].align > MAXSECTALIGN){
		archive_member_error(ofile, "fat file's align (2^%lu) too "
			"large for cputype (%d) cpusubtype (%d) (maximum 2^%d)",
			ofile->fat_archs[i].align, ofile->fat_archs[i].cputype,
			ofile->fat_archs[i].cpusubtype, MAXSECTALIGN);
		return(CHECK_BAD);
	    }
	    if(ofile->fat_archs[i].offset %
	       (1 << ofile->fat_archs[i].align) != 0){
		archive_member_error(ofile, "fat file's offset: %lu for "
			"cputype (%d) cpusubtype (%d) not aligned on it's "
			"alignment (2^%lu)", ofile->fat_archs[i].offset,
			ofile->fat_archs[i].cputype,
			ofile->fat_archs[i].cpusubtype,
			ofile->fat_archs[i].align);
		return(CHECK_BAD);
	    }

	    /*
	     * The only supported format where fat files are allowed to appear
	     * in archives is when the fat file contains only object files.
	     */
	    if(ofile->fat_archs[i].size < sizeof(struct mach_header)){
		archive_member_error(ofile, "fat file for cputype (%d) "
			"cpusubtype (%d) is not an object file (size too small "
			"to be an object file)", ofile->fat_archs[i].cputype,
			ofile->fat_archs[i].cpusubtype);
		return(CHECK_BAD);
	    }
	    memcpy(&magic,
		   ofile->file_addr + ofile->member_offset +
			ofile->fat_archs[i].offset,
		   sizeof(unsigned long));
	    if(magic != MH_MAGIC && magic != SWAP_LONG(MH_MAGIC)){
		archive_member_error(ofile, "fat file for cputype (%d) "
			"cpusubtype (%d) is not an object file (bad magic "
			"number)", ofile->fat_archs[i].cputype,
			ofile->fat_archs[i].cpusubtype);
		return(CHECK_BAD);
	    }
#ifdef ALIGNMENT_CHECKS
	    if((ofile->member_offset + ofile->fat_archs[i].offset) %
		sizeof(unsigned long) != 0){
		archive_member_error(ofile, "fat object file's offset in "
			"archive not a multiple of sizeof(unsigned long) "
			"(must be since member is an object file)");
		return(CHECK_BAD);
	    }
#endif /* ALIGNMENT_CHECKS */
	}
	for(i = 0; i < ofile->fat_header->nfat_arch; i++){
	    for(j = i + 1; j < ofile->fat_header->nfat_arch; j++){
		if(ofile->fat_archs[i].cputype ==
		     ofile->fat_archs[j].cputype &&
		   ofile->fat_archs[i].cpusubtype ==
		     ofile->fat_archs[j].cpusubtype){
		    archive_member_error(ofile, "fat file contains two of the "
			"same architecture (cputype (%d) cpusubtype (%d))",
			ofile->fat_archs[i].cputype,
			ofile->fat_archs[i].cpusubtype);
		    return(CHECK_BAD);
		}
	    }
	}
	return(CHECK_GOOD);
}

/*
 * check_archive() checks the archive referenced in the ofile for correctness.
 */
static
enum check_type
check_archive(
struct ofile *ofile,
enum bool archives_with_fat_objects)
{
#ifdef OTOOL
	return(CHECK_GOOD);
#else /* !defined OTOOL */
    char *addr;
    unsigned long size, offset, magic;
    enum byte_sex host_byte_sex;
    enum bool swapped;
    struct mach_header mh;
    struct ar_hdr *ar_hdr;
    unsigned long ar_name_size;

	/*
	 * Get the address and size of the archive (as well as the cputype and
	 * cpusubtype if known) and make sure it is an archive.
	 */
	if(ofile->file_type == OFILE_FAT){
	    addr = ofile->file_addr + ofile->fat_archs[ofile->narch].offset;
	    size = ofile->fat_archs[ofile->narch].size;
	    ofile->archive_cputype = ofile->fat_archs[ofile->narch].cputype;
	    ofile->archive_cpusubtype =
				     ofile->fat_archs[ofile->narch].cpusubtype;
	}
	else if(ofile->file_type == OFILE_ARCHIVE){
	    addr = ofile->file_addr;
	    size = ofile->file_size;
	    ofile->archive_cputype = 0;
	    ofile->archive_cpusubtype = 0;
	}
	else{
	    error("internal error. check_archive() call and file type of %s is "
		  "OFILE_UNKNOWN\n", ofile->file_name);
	    return(CHECK_BAD);
	}
	if(size < SARMAG || strncmp(addr, ARMAG, SARMAG) != 0){
	    error("internal error. check_archive() call for file %s which does "
		  "not have an archive magic string", ofile->file_name);
	    return(CHECK_BAD);
	}

	host_byte_sex = get_host_byte_sex();
	/*
	 * Check this archive out to make sure that it does not contain
	 * any fat files and that all object files it contains have the
	 * same cputype and subsubtype.
	 */
	offset = SARMAG;
	if(offset == size)
	    return(CHECK_GOOD);
	if(offset != size && offset + sizeof(struct ar_hdr) > size){
	    archive_error(ofile, "truncated or malformed (archive header of "
			  "first member extends past the end of the file)");
	    return(CHECK_BAD);
	}
	while(size > offset){
	    ar_hdr = (struct ar_hdr *)(addr + offset);
	    ofile->member_offset = offset;
	    ofile->member_addr = addr + offset;
	    ofile->member_size = strtoul(ar_hdr->ar_size, NULL, 10);
	    ofile->member_ar_hdr = ar_hdr;
	    ofile->member_name = ar_hdr->ar_name;
	    ofile->member_name_size = size_ar_name(ofile->member_ar_hdr);
	    offset += sizeof(struct ar_hdr);
	    /*
	     * See if this archive member is using extend format #1 where
	     * the size of the name is in ar_name and the name follows the
	     * archive header.
	     */
	    ar_name_size = 0;
	    if(strncmp(ofile->member_name,AR_EFMT1, sizeof(AR_EFMT1) - 1) == 0){
		if(check_extend_format_1(ofile, ar_hdr, size - offset,
				&ar_name_size) == CHECK_BAD)
		    return(CHECK_BAD);
		ofile->member_name = ar_hdr->ar_name + sizeof(struct ar_hdr);
		ofile->member_name_size = ar_name_size;
		offset += ar_name_size;
		ofile->member_offset += ar_name_size;
		ofile->member_addr += ar_name_size;
		ofile->member_size -= ar_name_size;
	    }
	    if(size - offset > sizeof(unsigned long)){
		memcpy(&magic, addr + offset, sizeof(unsigned long));
#ifdef __BIG_ENDIAN__
		if(magic == FAT_MAGIC)
#endif /* __BIG_ENDIAN__ */
#ifdef __LITTLE_ENDIAN__
		if(magic == SWAP_LONG(FAT_MAGIC))
#endif /* __LITTLE_ENDIAN__ */
		{
		    if(archives_with_fat_objects == FALSE ||
		       ofile->file_type != OFILE_ARCHIVE){
			archive_member_error(ofile, "is a fat file (not "
					     "allowed in an archive)");
			return(CHECK_BAD);
		    }
		}
		else{
		    if(size - offset >= sizeof(struct mach_header) &&
		       (magic == MH_MAGIC || magic == SWAP_LONG(MH_MAGIC))){
			memcpy(&mh, addr + offset, sizeof(struct mach_header));
			if(magic == SWAP_LONG(MH_MAGIC)){
			    magic = MH_MAGIC;
			    swapped = TRUE;
			    swap_mach_header(&mh, host_byte_sex);
			}
			swapped = FALSE;
		    }
		    if(magic == MH_MAGIC){
			if(ofile->archive_cputype == 0){
			    ofile->archive_cputype = mh.cputype;
			    ofile->archive_cpusubtype = mh.cpusubtype;
			}
			else if(ofile->archive_cputype != mh.cputype){
			    archive_member_error(ofile, "cputype (%d) does not "
				"match previous archive members cputype (%d) "
				"(all members must match)", mh.cputype,
				ofile->archive_cputype);
			}
		    }
		}
	    }
	    offset += round(ofile->member_size, sizeof(short));
	}
	ofile->member_offset = 0;
	ofile->member_addr = NULL;
	ofile->member_size = 0;
	ofile->member_ar_hdr = NULL;;
	ofile->member_name = NULL;
	ofile->member_name_size = 0;
	return(CHECK_GOOD);
#endif /* OTOOL */
}

/*
 * check_extend_format_1() checks the archive header for extended format #1.
 */
static
enum check_type
check_extend_format_1(
struct ofile *ofile,
struct ar_hdr *ar_hdr,
unsigned long size_left,
unsigned long *member_name_size)
{
    char *p, *endp, buf[sizeof(ar_hdr->ar_name)+1];
    unsigned long ar_name_size;

	*member_name_size = 0;

	buf[sizeof(ar_hdr->ar_name)] = '\0';
	memcpy(buf, ar_hdr->ar_name, sizeof(ar_hdr->ar_name));
	p = buf + sizeof(AR_EFMT1) - 1;
	if(isdigit(*p) == 0){
	    archive_error(ofile, "malformed (ar_name: %.*s for archive "
		"extend format #1 starts with non-digit)",
		(int)sizeof(ar_hdr->ar_name), ar_hdr->ar_name);
	    return(CHECK_BAD);
	}
	ar_name_size = strtoul(p, &endp, 10);
	if(ar_name_size == ULONG_MAX && errno == ERANGE){
	    archive_error(ofile, "malformed (size in ar_name: %.*s for "
		"archive extend format #1 overflows unsigned long)",
		(int)sizeof(ar_hdr->ar_name), ar_hdr->ar_name);
	    return(CHECK_BAD);
	}
	while(*endp == ' ' && *endp != '\0')
	    endp++;
	if(*endp != '\0'){
	    archive_error(ofile, "malformed (size in ar_name: %.*s for "
		"archive extend format #1 contains non-digit and "
		"non-space characters)", (int)sizeof(ar_hdr->ar_name),
		ar_hdr->ar_name);
	    return(CHECK_BAD);
	}
	if(ar_name_size > size_left){
	    archive_error(ofile, "truncated or malformed (archive name "
		"of member extends past the end of the file)");
	    return(CHECK_BAD);
	}
	*member_name_size = ar_name_size;
	return(CHECK_GOOD);
}

/*
 * check_Mach_O() checks the object file's mach header and load commands
 * referenced in the ofile for correctness (this also swaps the mach header
 * and load commands into the host byte sex if needed).
 */
static
enum check_type
check_Mach_O(
struct ofile *ofile)
{
#ifdef OTOOL
	return(CHECK_GOOD);
#else /* !defined OTOOL */
    unsigned long size, i, j;
    char *addr;
    enum byte_sex host_byte_sex;
    enum bool swapped;
    struct mach_header *mh;
    struct load_command *load_commands, *lc, l;
    struct segment_command *sg;
    struct section *s;
    struct symtab_command *st;
    struct dysymtab_command *dyst;
    struct symseg_command *ss;
    struct fvmlib_command *fl;
    struct dylib_command *dl;
    struct sub_framework_command *sub;
    struct sub_umbrella_command *usub;
    struct sub_library_command *lsub;
    struct sub_client_command *csub;
    struct prebound_dylib_command *pbdylib;
    struct dylinker_command *dyld;
    struct thread_command *ut;
    struct ident_command *id;
    struct routines_command *rc;
    struct twolevel_hints_command *hints;
    struct prebind_cksum_command *cs;
    unsigned long flavor, count, nflavor;
    char *p, *state;

	addr = ofile->object_addr;
	size = ofile->object_size;
	mh = ofile->mh;
	load_commands = ofile->load_commands;
	host_byte_sex = get_host_byte_sex();
	swapped = (enum bool)(host_byte_sex != ofile->object_byte_sex);

	if(swapped)
	    swap_mach_header(mh, host_byte_sex);
	if(mh->sizeofcmds + sizeof(struct mach_header) > size){
	    Mach_O_error(ofile, "truncated or malformed object (load commands "
			 "extend past the end of the file)");
	    return(CHECK_BAD);
	}
	if(ofile->file_type == OFILE_FAT){
	    if(ofile->fat_archs[ofile->narch].cputype != ofile->mh->cputype){
		Mach_O_error(ofile, "malformed fat file (fat header "
		    "architecture: %lu's cputype does not match "
		    "object file's mach header)", ofile->narch);
		return(CHECK_BAD);
	    }
	}
	/*
	 * Make a pass through the load commands checking them to the level
	 * that they can be parsed and all fields with offsets and sizes do
	 * not extend past the end of the file.
	 */
	st = NULL;
	dyst = NULL;
	rc = NULL;
	hints = NULL;
	cs = NULL;
	for(i = 0, lc = load_commands; i < mh->ncmds; i++){
	    l = *lc;
	    if(swapped)
		swap_load_command(&l, host_byte_sex);
	    /* check load command size for a multiple of sizeof(long) */
	    if(l.cmdsize % sizeof(long) != 0){
		Mach_O_error(ofile, "malformed object (load command %lu cmdsize"
			     " not a multiple of sizeof(long))", i);
		return(CHECK_BAD);
	    }
	    /* check that load command does not extends past end of commands */
	    if((char *)lc + l.cmdsize > (char *)load_commands + mh->sizeofcmds){
		Mach_O_error(ofile, "truncated or malformed object (load "
			     "command %lu extends past the end of the file)",i);
		return(CHECK_BAD);
	    }
	    /* check that the load command size is not zero */
	    if(l.cmdsize == 0){
		Mach_O_error(ofile, "malformed object (load command %lu cmdsize"
			     " is zero)", i);
		return(CHECK_BAD);
	    }
	    switch(l.cmd){
	    case LC_SEGMENT:
		sg = (struct segment_command *)lc;
		if(swapped)
		    swap_segment_command(sg, host_byte_sex);
		if(sg->cmdsize != sizeof(struct segment_command) +
				     sg->nsects * sizeof(struct section)){
		    Mach_O_error(ofile, "malformed object (inconsistant cmdsize"
				 "in LC_SEGMENT command %lu for the number of "
				 "sections)", i);
		    return(CHECK_BAD);
		}
		if(sg->fileoff > size){
		    Mach_O_error(ofile, "truncated or malformed object "
				 "(LC_SEGMENT command %lu fileoff field extends"
				 " past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(sg->fileoff + sg->filesize > size){
		    Mach_O_error(ofile, "truncated or malformed object "
				 "(LC_SEGMENT command %lu fileoff field plus "
				 "filesize field extends past the end of the "
				 "file)", i);
		    return(CHECK_BAD);
		}
		s = (struct section *)
		    ((char *)sg + sizeof(struct segment_command));
		if(swapped)
		    swap_section(s, sg->nsects, host_byte_sex);
		for(j = 0 ; j < sg->nsects ; j++){
		    if(s->flags != S_ZEROFILL && s->offset > size){
			Mach_O_error(ofile, "truncated or malformed object "
				"(offset field of section %lu in LC_SEGMENT "
				"command %lu extends past the end of the file)",
				j, i);
			return(CHECK_BAD);
		    }
		    if(s->flags != S_ZEROFILL && s->offset + s->size > size){
			Mach_O_error(ofile, "truncated or malformed object "
				"(offset field plus size field of section %lu "
				"in LC_SEGMENT command %lu extends past the "
				"end of the file)", j, i);
			return(CHECK_BAD);
		    }
		    if(s->reloff > size){
			Mach_O_error(ofile, "truncated or malformed object "
				"(reloff field of section %lu in LC_SEGMENT "
				"command %lu extends past the end of the file)",
				j, i);
			return(CHECK_BAD);
		    }
		    if(s->reloff + s->nreloc * sizeof(struct relocation_info) >
		       size){
			Mach_O_error(ofile, "truncated or malformed object "
				"(reloff field plus nreloc field times sizeof("
				"struct relocation_info) of section %lu in "
				"LC_SEGMENT command %lu extends past the end "
				"of the file)", j, i);
			return(CHECK_BAD);
		    }
		    s++;
		}
		break;

	    case LC_SYMTAB:
		if(st != NULL){
		    Mach_O_error(ofile, "malformed object (more than one "
			"LC_SYMTAB command)");
		    return(CHECK_BAD);
		}
		st = (struct symtab_command *)lc;
		if(swapped)
		    swap_symtab_command(st, host_byte_sex);
		if(st->cmdsize != sizeof(struct symtab_command)){
		    Mach_O_error(ofile, "malformed object (LC_SYMTAB command "
			"%lu has incorrect cmdsize)", i);
		    return(CHECK_BAD);
		}
		if(st->symoff > size){
		    Mach_O_error(ofile, "truncated or malformed object (symoff "
			"field of LC_SYMTAB command %lu extends past the end "
			"of the file)", i);
		    return(CHECK_BAD);
		}
		if(st->symoff + st->nsyms * sizeof(struct nlist) > size){
		    Mach_O_error(ofile, "truncated or malformed object (symoff "
			"field plus nsyms field times sizeof(struct nlist) of "
			"LC_SYMTAB command %lu extends past the end of the "
			"file)", i);
		    return(CHECK_BAD);
		}
		if(st->stroff > size){
		    Mach_O_error(ofile, "truncated or malformed object (stroff "
			"field of LC_SYMTAB command %lu extends past the end "
			"of the file)", i);
		    return(CHECK_BAD);
		}
		if(st->stroff + st->strsize > size){
		    Mach_O_error(ofile, "truncated or malformed object (stroff "
			"field plus strsize field of LC_SYMTAB command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_DYSYMTAB:
		if(dyst != NULL){
		    Mach_O_error(ofile, "malformed object (more than one "
			"LC_DYSYMTAB command)");
		    return(CHECK_BAD);
		}
		dyst = (struct dysymtab_command *)lc;
		if(swapped)
		    swap_dysymtab_command(dyst, host_byte_sex);
		if(dyst->cmdsize != sizeof(struct dysymtab_command)){
		    Mach_O_error(ofile, "malformed object (LC_DYSYMTAB command "
			"%lu has incorrect cmdsize)", i);
		    return(CHECK_BAD);
		}
		if(dyst->tocoff > size){
		    Mach_O_error(ofile, "truncated or malformed object (tocoff "
			"field of LC_DYSYMTAB command %lu extends past the end "
			"of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->tocoff +
		   dyst->ntoc * sizeof(struct dylib_table_of_contents) > size){
		    Mach_O_error(ofile, "truncated or malformed object (tocoff "
			"field plus ntoc field times sizeof(struct dylib_table"
			"_of_contents) of LC_DYSYMTAB command %lu extends past "
			"the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->modtaboff > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(modtaboff field of LC_DYSYMTAB command %lu extends "
			"past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->modtaboff +
		   dyst->nmodtab * sizeof(struct dylib_module) > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(modtaboff field plus nmodtab field times sizeof("
			"struct dylib_module) of LC_DYSYMTAB command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->extrefsymoff > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(extrefsymoff field of LC_DYSYMTAB command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->extrefsymoff +
		   dyst->nextrefsyms * sizeof(struct dylib_reference) > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(extrefsymoff field plus nextrefsyms field times "
			"sizeof(struct dylib_reference) of LC_DYSYMTAB command "
			"%lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->indirectsymoff > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(indirectsymoff field of LC_DYSYMTAB command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->indirectsymoff +
		   dyst->nindirectsyms * sizeof(unsigned long) > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(indirectsymoff field plus nindirectsyms field times "
			"sizeof(unsigned long) of LC_DYSYMTAB command "
			"%lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->extreloff > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(extreloff field of LC_DYSYMTAB command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->extreloff +
		   dyst->nextrel * sizeof(struct relocation_info) > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(extreloff field plus nextrel field times "
			"sizeof(struct relocation_info) of LC_DYSYMTAB command "
			"%lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->locreloff > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(locreloff field of LC_DYSYMTAB command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(dyst->locreloff +
		   dyst->nlocrel * sizeof(struct relocation_info) > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(locreloff field plus nlocrel field times "
			"sizeof(struct relocation_info) of LC_DYSYMTAB command "
			"%lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_ROUTINES:
		if(rc != NULL){
		    Mach_O_error(ofile, "malformed object (more than one "
			"LC_ROUTINES command)");
		    return(CHECK_BAD);
		}
		rc = (struct routines_command *)lc;
		if(swapped)
		    swap_routines_command(rc, host_byte_sex);
		if(rc->cmdsize != sizeof(struct routines_command)){
		    Mach_O_error(ofile, "malformed object (LC_ROUTINES command "
			"%lu has incorrect cmdsize)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_TWOLEVEL_HINTS:
		if(hints != NULL){
		    Mach_O_error(ofile, "malformed object (more than one "
			"LC_TWOLEVEL_HINTS command)");
		    return(CHECK_BAD);
		}
		hints = (struct twolevel_hints_command *)lc;
		if(swapped)
		    swap_twolevel_hints_command(hints, host_byte_sex);
		if(hints->cmdsize != sizeof(struct twolevel_hints_command)){
		    Mach_O_error(ofile, "malformed object (LC_TWOLEVEL_HINTS "
			         "command %lu has incorrect cmdsize)", i);
		    return(CHECK_BAD);
		}
		if(hints->offset > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(offset field of LC_TWOLEVEL_HINTS command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(hints->offset +
		   hints->nhints * sizeof(struct twolevel_hint) > size){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(offset field plus nhints field times "
			"sizeof(struct twolevel_hint) of LC_TWOLEVEL_HINTS "
			" command %lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_PREBIND_CKSUM:
		if(cs != NULL){
		    Mach_O_error(ofile, "malformed object (more than one "
			"LC_PREBIND_CKSUM command)");
		    return(CHECK_BAD);
		}
		cs = (struct prebind_cksum_command *)lc;
		if(swapped)
		    swap_prebind_cksum_command(cs, host_byte_sex);
		if(cs->cmdsize != sizeof(struct prebind_cksum_command)){
		    Mach_O_error(ofile, "malformed object (LC_PREBIND_CKSUM "
			"command %lu has incorrect cmdsize)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_SYMSEG:
		ss = (struct symseg_command *)lc;
		if(swapped)
		    swap_symseg_command(ss, host_byte_sex);
		if(ss->cmdsize != sizeof(struct symseg_command)){
		    Mach_O_error(ofile, "malformed object (LC_SYMSEG command "
			"%lu has incorrect cmdsize)", i);
		    return(CHECK_BAD);
		}
		if(ss->offset > size){
		    Mach_O_error(ofile, "truncated or malformed object (offset "
			"field of LC_SYMSEG command %lu extends past the end "
			"of the file)", i);
		    return(CHECK_BAD);
		}
		if(ss->offset + ss->size > size){
		    Mach_O_error(ofile, "truncated or malformed object (offset "
			"field plus size field of LC_SYMTAB command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_IDFVMLIB:
	    case LC_LOADFVMLIB:
		fl = (struct fvmlib_command *)lc;
		if(swapped)
		    swap_fvmlib_command(fl, host_byte_sex);
		if(fl->cmdsize < sizeof(struct fvmlib_command)){
		    Mach_O_error(ofile, "malformed object (%s command %lu has "
			"too small cmdsize field)", fl->cmd == LC_IDFVMLIB ? 
			"LC_IDFVMLIB" : "LC_LOADFVMLIB", i);
		    return(CHECK_BAD);
		}
		if(fl->fvmlib.name.offset >= fl->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object (name."
			"offset field of %s command %lu extends past the end "
			"of the file)", fl->cmd == LC_IDFVMLIB ? "LC_IDFVMLIB"
			: "LC_LOADFVMLIB", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_ID_DYLIB:
	    case LC_LOAD_DYLIB:
	    case LC_LOAD_WEAK_DYLIB:
		dl = (struct dylib_command *)lc;
		if(swapped)
		    swap_dylib_command(dl, host_byte_sex);
		if(dl->cmdsize < sizeof(struct dylib_command)){
		    Mach_O_error(ofile, "malformed object (%s command %lu has "
			"too small cmdsize field)", dl->cmd == LC_ID_DYLIB ? 
			"LC_ID_DYLIB" : (dl->cmd ==  LC_LOAD_DYLIB ?
			"LC_LOAD_DYLIB" : "LC_LOAD_WEAK_DYLIB"), i);
		    return(CHECK_BAD);
		}
		if(dl->dylib.name.offset >= dl->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object (name."
			"offset field of %s command %lu extends past the end "
			"of the file)", dl->cmd == LC_ID_DYLIB ? "LC_ID_DYLIB"
			: (dl->cmd ==  LC_LOAD_DYLIB ? "LC_LOAD_DYLIB" :
			"LC_LOAD_WEAK_DYLIB"), i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_SUB_FRAMEWORK:
		sub = (struct sub_framework_command *)lc;
		if(swapped)
		    swap_sub_framework_command(sub, host_byte_sex);
		if(sub->cmdsize < sizeof(struct sub_framework_command)){
		    Mach_O_error(ofile, "malformed object (LC_SUB_FRAMEWORK "
			"command %lu has too small cmdsize field)", i);
		    return(CHECK_BAD);
		}
		if(sub->umbrella.offset >= sub->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(umbrella.offset field of LC_SUB_FRAMEWORK command "
			"%lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_SUB_UMBRELLA:
		usub = (struct sub_umbrella_command *)lc;
		if(swapped)
		    swap_sub_umbrella_command(usub, host_byte_sex);
		if(usub->cmdsize < sizeof(struct sub_umbrella_command)){
		    Mach_O_error(ofile, "malformed object (LC_SUB_UMBRELLA "
			"command %lu has too small cmdsize field)", i);
		    return(CHECK_BAD);
		}
		if(usub->sub_umbrella.offset >= usub->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(sub_umbrella.offset field of LC_SUB_UMBRELLA command "
			"%lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_SUB_LIBRARY:
		lsub = (struct sub_library_command *)lc;
		if(swapped)
		    swap_sub_library_command(lsub, host_byte_sex);
		if(lsub->cmdsize < sizeof(struct sub_library_command)){
		    Mach_O_error(ofile, "malformed object (LC_SUB_LIBRARY "
			"command %lu has too small cmdsize field)", i);
		    return(CHECK_BAD);
		}
		if(lsub->sub_library.offset >= lsub->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(sub_library.offset field of LC_SUB_LIBRARY command "
			"%lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_SUB_CLIENT:
		csub = (struct sub_client_command *)lc;
		if(swapped)
		    swap_sub_client_command(csub, host_byte_sex);
		if(csub->cmdsize < sizeof(struct sub_client_command)){
		    Mach_O_error(ofile, "malformed object (LC_SUB_CLIENT "
			"command %lu has too small cmdsize field)", i);
		    return(CHECK_BAD);
		}
		if(csub->client.offset >= csub->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(cleient.offset field of LC_SUB_CLIENT command "
			"%lu extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_PREBOUND_DYLIB:
		pbdylib = (struct prebound_dylib_command *)lc;
		if(swapped)
		    swap_prebound_dylib_command(pbdylib, host_byte_sex);
		if(pbdylib->cmdsize < sizeof(struct dylib_command)){
		    Mach_O_error(ofile, "malformed object (LC_PREBIND_DYLIB "
			"command %lu has too small cmdsize field)", i);
		    return(CHECK_BAD);
		}
		if(pbdylib->name.offset >= pbdylib->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object (name."
			"offset field of LC_PREBIND_DYLIB command %lu extends "
			"past the end of the file)", i);
		    return(CHECK_BAD);
		}
		if(pbdylib->linked_modules.offset >= pbdylib->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object (linked_"
			"modules.offset field of LC_PREBIND_DYLIB command %lu "
			"extends past the end of the file)", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_ID_DYLINKER:
	    case LC_LOAD_DYLINKER:
		dyld = (struct dylinker_command *)lc;
		if(swapped)
		    swap_dylinker_command(dyld, host_byte_sex);
		if(dyld->cmdsize < sizeof(struct dylinker_command)){
		    Mach_O_error(ofile, "malformed object (%s command %lu has "
			"too small cmdsize field)",
			dyld->cmd == LC_ID_DYLINKER ? 
			"LC_ID_DYLINKER" : "LC_LOAD_DYLINKER", i);
		    return(CHECK_BAD);
		}
		if(dyld->name.offset >= dyld->cmdsize){
		    Mach_O_error(ofile, "truncated or malformed object (name."
			"offset field of %s command %lu extends past the end "
			"of the file)", dyld->cmd == LC_ID_DYLINKER ?
			"LC_ID_DYLINKER" : "LC_LOAD_DYLINKER", i);
		    return(CHECK_BAD);
		}
		break;

	    case LC_UNIXTHREAD:
	    case LC_THREAD:
		ut = (struct thread_command *)lc;
		if(swapped)
		    swap_thread_command(ut, host_byte_sex);
		state = (char *)ut + sizeof(struct thread_command);

	    	if(mh->cputype == CPU_TYPE_MC680x0){
		    struct m68k_thread_state_regs *cpu;
		    struct m68k_thread_state_68882 *fpu;
		    struct m68k_thread_state_user_reg *user_reg;

		    nflavor = 0;
		    p = (char *)ut + ut->cmdsize;
		    while(state < p){
			flavor = *((unsigned long *)state);
			if(swapped){
			    flavor = SWAP_LONG(flavor);
			    *((unsigned long *)state) = flavor;
			}
			state += sizeof(unsigned long);
			count = *((unsigned long *)state);
			if(swapped){
			    count = SWAP_LONG(count);
			    *((unsigned long *)state) = count;
			}
			state += sizeof(unsigned long);
			switch(flavor){
			case M68K_THREAD_STATE_REGS:
			    if(count != M68K_THREAD_STATE_REGS_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not M68K_THREAD_STATE_REGS_COUNT for "
				    "flavor number %lu which is a M68K_THREAD_"
				    "STATE_REGS flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    cpu = (struct m68k_thread_state_regs *)state;
			    if(swapped)
				swap_m68k_thread_state_regs(cpu, host_byte_sex);
			    state += sizeof(struct m68k_thread_state_regs);
			    break;
			case M68K_THREAD_STATE_68882:
			    if(count != M68K_THREAD_STATE_68882_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not M68K_THREAD_STATE_68882_COUNT for "
				    "flavor number %lu which is a M68K_THREAD_"
				    "STATE_68882 flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    fpu = (struct m68k_thread_state_68882 *)state;
			    if(swapped)
				swap_m68k_thread_state_68882(fpu,host_byte_sex);
			    state += sizeof(struct m68k_thread_state_68882);
			    break;
			case M68K_THREAD_STATE_USER_REG:
			    if(count != M68K_THREAD_STATE_USER_REG_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not M68K_THREAD_STATE_USER_REG_COUNT for "
				    "flavor number %lu which is a M68K_THREAD_"
				    "STATE_USER_REG flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    user_reg =
				(struct m68k_thread_state_user_reg *)state;
			    if(swapped)
				swap_m68k_thread_state_user_reg(user_reg,
								host_byte_sex);
			    state += sizeof(struct m68k_thread_state_user_reg);
			    break;
			default:
			    if(swapped){
				Mach_O_error(ofile, "malformed object (unknown "
				    "flavor for flavor number %lu in %s command"
				    " %lu can't byte swap it)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    state += count * sizeof(long);
			    break;
			}
			nflavor++;
		    }
		    break;
		}
	    	if(mh->cputype == CPU_TYPE_POWERPC ||
	    	   mh->cputype == CPU_TYPE_VEO){
		    ppc_thread_state_t *nrw_cpu;

		    nflavor = 0;
		    p = (char *)ut + ut->cmdsize;
		    while(state < p){
			flavor = *((unsigned long *)state);
			if(swapped){
			    flavor = SWAP_LONG(flavor);
			    *((unsigned long *)state) = flavor;
			}
			state += sizeof(unsigned long);
			count = *((unsigned long *)state);
			if(swapped){
			    count = SWAP_LONG(count);
			    *((unsigned long *)state) = count;
			}
			state += sizeof(unsigned long);
			switch(flavor){
			case PPC_THREAD_STATE:
			    if(count != PPC_THREAD_STATE_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not PPC_THREAD_STATE_COUNT for "
				    "flavor number %lu which is a PPC_THREAD_"
				    "STATE flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    nrw_cpu = (ppc_thread_state_t *)state;
			    if(swapped)
				swap_ppc_thread_state_t(nrw_cpu,
							     host_byte_sex);
			    state += sizeof(ppc_thread_state_t);
			    break;
			default:
			    if(swapped){
				Mach_O_error(ofile, "malformed object (unknown "
				    "flavor for flavor number %lu in %s command"
				    " %lu can't byte swap it)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    state += count * sizeof(long);
			    break;
			}
			nflavor++;
		    }
		    break;
		}
	    	if(mh->cputype == CPU_TYPE_MC88000){
		    m88k_thread_state_grf_t *cpu;
		    m88k_thread_state_xrf_t *fpu;
		    m88k_thread_state_user_t *user;
		    m88110_thread_state_impl_t *spu;

		    nflavor = 0;
		    p = (char *)ut + ut->cmdsize;
		    while(state < p){
			flavor = *((unsigned long *)state);
			if(swapped){
			    flavor = SWAP_LONG(flavor);
			    *((unsigned long *)state) = flavor;
			}
			state += sizeof(unsigned long);
			count = *((unsigned long *)state);
			if(swapped){
			    count = SWAP_LONG(count);
			    *((unsigned long *)state) = count;
			}
			state += sizeof(unsigned long);
			switch(flavor){
			case M88K_THREAD_STATE_GRF:
			    if(count != M88K_THREAD_STATE_GRF_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not M88K_THREAD_STATE_GRF_COUNT for "
				    "flavor number %lu which is a M88K_THREAD_"
				    "STATE_GRF flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    cpu = (m88k_thread_state_grf_t *)state;
			    if(swapped)
				swap_m88k_thread_state_grf_t(cpu,
							     host_byte_sex);
			    state += sizeof(m88k_thread_state_grf_t);
			    break;
			case M88K_THREAD_STATE_XRF:
			    if(count != M88K_THREAD_STATE_XRF_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not M88K_THREAD_STATE_XRF_COUNT for "
				    "flavor number %lu which is a M88K_THREAD_"
				    "STATE_XRF flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    fpu = (m88k_thread_state_xrf_t *)state;
			    if(swapped)
				swap_m88k_thread_state_xrf_t(fpu,
							     host_byte_sex);
			    state += sizeof(m88k_thread_state_xrf_t);
			    break;
			case M88K_THREAD_STATE_USER:
			    if(count != M88K_THREAD_STATE_USER_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not M88K_THREAD_STATE_USER_COUNT for "
				    "flavor number %lu which is a M88K_THREAD_"
				    "STATE_USER flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    user = (m88k_thread_state_user_t *)state;
			    if(swapped)
				swap_m88k_thread_state_user_t(user,
							      host_byte_sex);
			    state += sizeof(m88k_thread_state_user_t);
			    break;
			case M88110_THREAD_STATE_IMPL:
			    if(count != M88110_THREAD_STATE_IMPL_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not M88110_THREAD_STATE_IMPL_COUNT for "
				    "flavor number %lu which is a M88110_THREAD"
				    "_STATE_IMPL flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    spu = (m88110_thread_state_impl_t *)state;
			    if(swapped)
				swap_m88110_thread_state_impl_t(spu,
							      host_byte_sex);
			    state += sizeof(m88110_thread_state_impl_t);
			    break;
			default:
			    if(swapped){
				Mach_O_error(ofile, "malformed object (unknown "
				    "flavor for flavor number %lu in %s command"
				    " %lu can't byte swap it)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    state += count * sizeof(long);
			    break;
			}
			nflavor++;
		    }
		    break;
		}
	    	if(mh->cputype == CPU_TYPE_I860){
#ifdef m68k
		    struct i860_thread_state_regs *cpu;
#endif

		    nflavor = 0;
		    p = (char *)ut + ut->cmdsize;
		    while(state < p){
			flavor = *((unsigned long *)state);
			if(swapped){
			    flavor = SWAP_LONG(flavor);
			    *((unsigned long *)state) = flavor;
			}
			state += sizeof(unsigned long);
			count = *((unsigned long *)state);
			if(swapped){
			    count = SWAP_LONG(count);
			    *((unsigned long *)state) = count;
			}
			state += sizeof(unsigned long);
			switch(flavor){
			case I860_THREAD_STATE_REGS:
#ifdef m68k
			    if(count != I860_THREAD_STATE_REGS_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not I860_THREAD_STATE_REGS_COUNT for "
				    "flavor number %lu which is a I860_THREAD_"
				    "STATE_REGS flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    cpu = (struct i860_thread_state_regs *)state;
			    if(swapped)
				swap_i860_thread_state_regs(cpu, host_byte_sex);
			    state += sizeof(struct i860_thread_state_regs);
#else
			    state += count * sizeof(int);
#endif
			    break;
			default:
			    if(swapped){
				Mach_O_error(ofile, "malformed object (unknown "
				    "flavor for flavor number %lu in %s command"
				    " %lu can't byte swap it)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    state += count * sizeof(long);
			    break;
			}
			nflavor++;
		    }
		    break;
		}
	    	if(mh->cputype == CPU_TYPE_I386){
		    i386_thread_state_t *cpu;
		    i386_thread_fpstate_t *fpu;
		    i386_thread_exceptstate_t *exc;
		    i386_thread_cthreadstate_t *user;

		    nflavor = 0;
		    p = (char *)ut + ut->cmdsize;
		    while(state < p){
			flavor = *((unsigned long *)state);
			if(swapped){
			    flavor = SWAP_LONG(flavor);
			    *((unsigned long *)state) = flavor;
			}
			state += sizeof(unsigned long);
			count = *((unsigned long *)state);
			if(swapped){
			    count = SWAP_LONG(count);
			    *((unsigned long *)state) = count;
			}
			state += sizeof(unsigned long);
			switch(flavor){
			case i386_THREAD_STATE:
			    if(count != i386_THREAD_STATE_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not i386_THREAD_STATE_COUNT for flavor "
				    "number %lu which is a i386_THREAD_STATE "
				    "flavor in %s command %lu)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    cpu = (i386_thread_state_t *)state;
			    if(swapped)
				swap_i386_thread_state(cpu, host_byte_sex);
			    state += sizeof(i386_thread_state_t);
			    break;
			case i386_THREAD_FPSTATE:
			    if(count != i386_THREAD_FPSTATE_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not i386_THREAD_FPSTATE_COUNT for flavor "
				    "number %lu which is a i386_THREAD_FPSTATE "
				    "flavor in %s command %lu)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    fpu = (i386_thread_fpstate_t *)state;
			    if(swapped)
				swap_i386_thread_fpstate(fpu, host_byte_sex);
			    state += sizeof(i386_thread_fpstate_t);
			    break;
			case i386_THREAD_EXCEPTSTATE:
			    if(count != i386_THREAD_EXCEPTSTATE_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not i386_THREAD_EXCEPTSTATE_COUNT for "
				    "flavor number %lu which is a i386_THREAD_"
				    "EXCEPTSTATE flavor in %s command %lu)",
				    nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    exc = (i386_thread_exceptstate_t *)state;
			    if(swapped)
				swap_i386_thread_exceptstate(exc,host_byte_sex);
			    state += sizeof(i386_thread_exceptstate_t);
			    break;
			case i386_THREAD_CTHREADSTATE:
			    if(count != i386_THREAD_CTHREADSTATE_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not i386_THREAD_CTHREADSTATE_COUNT for "
				    "flavor number %lu which is a i386_THREAD_"
				    "CTHREADSTATE flavor in %s command %lu)",
				    nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    user = (i386_thread_cthreadstate_t *)state;
			    if(swapped)
				swap_i386_thread_cthreadstate(user,
							      host_byte_sex);
			    state += sizeof(i386_thread_cthreadstate_t);
			    break;
			default:
			    if(swapped){
				Mach_O_error(ofile, "malformed object (unknown "
				    "flavor for flavor number %lu in %s command"
				    " %lu can't byte swap it)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    state += count * sizeof(long);
			    break;
			}
			nflavor++;
		    }
		    break;
		}
	    	if(mh->cputype == CPU_TYPE_HPPA){
		    struct hp_pa_integer_thread_state *cpu;
		    struct hp_pa_frame_thread_state *frame;
		    struct hp_pa_fp_thread_state *fpu;

		    nflavor = 0;
		    p = (char *)ut + ut->cmdsize;
		    while(state < p){
			flavor = *((unsigned long *)state);
			if(swapped){
			    flavor = SWAP_LONG(flavor);
			    *((unsigned long *)state) = flavor;
			}
			state += sizeof(unsigned long);
			count = *((unsigned long *)state);
			if(swapped){
			    count = SWAP_LONG(count);
			    *((unsigned long *)state) = count;
			}
			state += sizeof(unsigned long);
			switch(flavor){
			case HPPA_INTEGER_THREAD_STATE:
			    if(count != HPPA_INTEGER_THREAD_STATE_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not HPPA_INTEGER_THREAD_STATE_COUNT for "
				    "flavor number %lu which is a "
				    "HPPA_INTEGER_THREAD_STATE "
				    "flavor in %s command %lu)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    cpu = (struct hp_pa_integer_thread_state *)state;
			    if(swapped)
				swap_hppa_integer_thread_state(cpu,
							       host_byte_sex);
			    state += sizeof(struct hp_pa_integer_thread_state);
			    break;
			case HPPA_FRAME_THREAD_STATE:
			    if(count != HPPA_FRAME_THREAD_STATE_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not HPPA_FRAME_THREAD_STATE_COUNT for "
				    "flavor number %lu which is a HPPA_FRAME_"
				    "THREAD_STATE flavor in %s command %lu)",
				    nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    frame = (struct hp_pa_frame_thread_state *)state;
			    if(swapped)
				swap_hppa_frame_thread_state(frame,host_byte_sex);
			    state += sizeof(struct hp_pa_frame_thread_state);
			    break;
			case HPPA_FP_THREAD_STATE:
			    if(count != HPPA_FP_THREAD_STATE_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not HPPA_FP_THREAD_STATE_COUNT for "
				    "flavor number %lu which is a HPPA_FP_"
				    "THREAD_STATE flavor in %s command %lu)",
				    nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    fpu = (struct hp_pa_fp_thread_state *)state;
			    if(swapped)
				swap_hppa_fp_thread_state(fpu,host_byte_sex);
			    state += sizeof(struct hp_pa_fp_thread_state);
			    break;
			default:
			    if(swapped){
				Mach_O_error(ofile, "malformed object (unknown "
				    "flavor for flavor number %lu in %s command"
				    " %lu can't byte swap it)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    state += count * sizeof(long);
			    break;
			}
			nflavor++;
		    }
		    break;
		}
	    	if(mh->cputype == CPU_TYPE_SPARC){
		    struct sparc_thread_state_regs *cpu;
		    struct sparc_thread_state_fpu *fpu;

		    nflavor = 0;
		    p = (char *)ut + ut->cmdsize;
		    while(state < p){
			flavor = *((unsigned long *)state);
			if(swapped){
			    flavor = SWAP_LONG(flavor);
			    *((unsigned long *)state) = flavor;
			}
			state += sizeof(unsigned long);
			count = *((unsigned long *)state);
			if(swapped){
			    count = SWAP_LONG(count);
			    *((unsigned long *)state) = count;
			}
			state += sizeof(unsigned long);
			switch(flavor){
			case SPARC_THREAD_STATE_REGS:
			    if(count != SPARC_THREAD_STATE_REGS_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not SPARC_THREAD_STATE_REGS_COUNT for "
				    "flavor number %lu which is a SPARC_THREAD_"
				    "STATE_REGS flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    cpu = (struct sparc_thread_state_regs *)state;
			    if(swapped)
				swap_sparc_thread_state_regs(cpu, host_byte_sex);
			    state += sizeof(struct sparc_thread_state_regs);
			    break;
			  case SPARC_THREAD_STATE_FPU:
			    if(count != SPARC_THREAD_STATE_FPU_COUNT){
				Mach_O_error(ofile, "malformed object (count "
				    "not SPARC_THREAD_STATE_FPU_COUNT for "
				    "flavor number %lu which is a SPARC_THREAD_"
				    "STATE_FPU flavor in %s command %lu)",
				    nflavor, ut->cmd == LC_UNIXTHREAD ? 
				    "LC_UNIXTHREAD" : "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    fpu = (struct sparc_thread_state_fpu *)state;
			    if(swapped)
				swap_sparc_thread_state_fpu(fpu, host_byte_sex);
			    state += sizeof(struct sparc_thread_state_fpu);
			    break;
			default:
			    if(swapped){
				Mach_O_error(ofile, "malformed object (unknown "
				    "flavor for flavor number %lu in %s command"
				    " %lu can't byte swap it)", nflavor,
				    ut->cmd == LC_UNIXTHREAD ? "LC_UNIXTHREAD" :
				    "LC_THREAD", i);
				return(CHECK_BAD);
			    }
			    state += count * sizeof(long);
			    break;
			}
			nflavor++;
		    }
		    break;
		}
		if(swapped){
		    Mach_O_error(ofile, "malformed object (unknown cputype and "
			"cpusubtype of object and can't byte swap and check %s "
			"command %lu)", ut->cmd == LC_UNIXTHREAD ?
			"LC_UNIXTHREAD" : "LC_THREAD", i);
		    return(CHECK_BAD);
		}
		break;
	    case LC_IDENT:
		id = (struct ident_command *)lc;
		if(swapped)
		    swap_ident_command(id, host_byte_sex);
		if((char *)id + id->cmdsize >
		   (char *)load_commands + mh->sizeofcmds){
		    Mach_O_error(ofile, "truncated or malformed object (cmdsize"
			"field of LC_IDENT command %lu extends past the end of "
			"the load commands)", i);
		    return(CHECK_BAD);
		}
		break;

#ifndef OFI
	    default:
		Mach_O_error(ofile, "malformed object (unknown load command "
			     "%lu)", i);
		return(CHECK_BAD);
#endif /* !defined(OFI) */
	    }

	    lc = (struct load_command *)((char *)lc + l.cmdsize);
	    /* check that next load command does not extends past the end */
	    if((char *)lc > (char *)load_commands + mh->sizeofcmds){
		Mach_O_error(ofile, "truncated or malformed object (load "
			     "command %lu extends past the end of the file)",
			     i + 1);
		return(CHECK_BAD);
	    }
	}
	if(st == NULL){
	    if(dyst != NULL){
		Mach_O_error(ofile, "truncated or malformed object (contains "
		  "LC_DYSYMTAB load command without a LC_SYMTAB load command)");
		return(CHECK_BAD);
	    }
	}
	else{
	    if(dyst != NULL){
		if(dyst->nlocalsym != 0 &&
		   dyst->ilocalsym > st->nsyms){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(ilocalsym in LC_DYSYMTAB load command extends past "
			"the end of the symbol table)");
		    return(CHECK_BAD);
		}
		if(dyst->nlocalsym != 0 &&
		   dyst->ilocalsym + dyst->nlocalsym > st->nsyms){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(ilocalsym plus nlocalsym in LC_DYSYMTAB load command "
			"extends past the end of the symbol table)");
		    return(CHECK_BAD);
		}

		if(dyst->nextdefsym != 0 &&
		   dyst->iextdefsym > st->nsyms){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(iextdefsym in LC_DYSYMTAB load command extends past "
			"the end of the symbol table)");
		    return(CHECK_BAD);
		}
		if(dyst->nextdefsym != 0 &&
		   dyst->iextdefsym + dyst->nextdefsym > st->nsyms){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(iextdefsym plus nextdefsym in LC_DYSYMTAB load "
			"command extends past the end of the symbol table)");
		    return(CHECK_BAD);
		}

		if(dyst->nundefsym != 0 &&
		   dyst->iundefsym > st->nsyms){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(iundefsym in LC_DYSYMTAB load command extends past "
			"the end of the symbol table)");
		    return(CHECK_BAD);
		}
		if(dyst->nundefsym != 0 &&
		   dyst->iundefsym + dyst->nundefsym > st->nsyms){
		    Mach_O_error(ofile, "truncated or malformed object "
			"(iundefsym plus nundefsym in LC_DYSYMTAB load command "
			"extends past the end of the symbol table)");
		    return(CHECK_BAD);
		}
		if(rc != NULL){
		    if(rc->init_module > dyst->nmodtab){
			Mach_O_error(ofile, "malformed object (init_module in "
			    "LC_ROUTINES load command extends past the end of "
			    "the module table)");
			return(CHECK_BAD);
		    }
		}
		if(hints != NULL){
		    if(hints->nhints != dyst->nundefsym){
			Mach_O_error(ofile, "malformed object (nhints in "
			    "LC_TWOLEVEL_HINTS load command not the same as "
			    "nundefsym in LC_DYSYMTAB load command)");
			return(CHECK_BAD);
		    }
		}
	    }
	}
	/* check for an inconsistant size of the load commands */
	if((char *)load_commands + mh->sizeofcmds != (char *)lc){
	    Mach_O_error(ofile, "malformed object (inconsistant sizeofcmds "
			 "field in mach header)");
	    return(CHECK_BAD);
	}

	/* looks good return ok */
	return(CHECK_GOOD);
#endif /* OTOOL */
}

/*
 * check_dylib_module() checks the object file's dylib_module as referenced
 * by the dylib_module field in the ofile for correctness.
 */
static
enum check_type
check_dylib_module(
struct ofile *ofile,
struct symtab_command *st,
struct dysymtab_command *dyst,
char *strings,
unsigned long module_index)
{
#ifdef OTOOL
	return(CHECK_GOOD);
#else /* !defined OTOOL */
    unsigned long i;
    enum byte_sex host_byte_sex;
    enum bool swapped;
    struct dylib_module m;

	m = *ofile->dylib_module;
	host_byte_sex = get_host_byte_sex();
	swapped = (enum bool)(host_byte_sex != ofile->object_byte_sex);
	if(swapped)
	    swap_dylib_module(&m, 1, host_byte_sex);

	if(m.module_name > st->strsize){
	    Mach_O_error(ofile, "truncated or malformed object (module_name "
		"of module table entry %lu past the end of the string table)",
		module_index);
	    return(CHECK_BAD);
	}
	for(i = m.module_name; i < st->strsize && strings[i] != '\0'; i++)
		;
	if(i >= st->strsize){
	    Mach_O_error(ofile, "truncated or malformed object (module_name "
		"of module table entry %lu extends past the end of the string "
		"table)", module_index);
	    return(CHECK_BAD);
	}

	if(m.nextdefsym != 0){
	    if(m.iextdefsym > st->nsyms){
		Mach_O_error(ofile, "truncated or malformed object (iextdefsym "
		    "field of module table entry %lu past the end of the "
		    "symbol table", module_index);
		return(CHECK_BAD);
	    }
	    if(m.iextdefsym + m.nextdefsym > st->nsyms){
		Mach_O_error(ofile, "truncated or malformed object (iextdefsym "
		    "field of module table entry %lu plus nextdefsym field "
		    "extends past the end of the symbol table", module_index);
		return(CHECK_BAD);
	    }
	}
	if(m.nlocalsym != 0){
	    if(m.ilocalsym > st->nsyms){
		Mach_O_error(ofile, "truncated or malformed object (ilocalsym "
		    "field of module table entry %lu past the end of the "
		    "symbol table", module_index);
		return(CHECK_BAD);
	    }
	    if(m.ilocalsym + m.nlocalsym > st->nsyms){
		Mach_O_error(ofile, "truncated or malformed object (ilocalsym "
		    "field of module table entry %lu plus nlocalsym field "
		    "extends past the end of the symbol table", module_index);
		return(CHECK_BAD);
	    }
	}
	if(m.nrefsym != 0){
	    if(m.irefsym > dyst->nextrefsyms){
		Mach_O_error(ofile, "truncated or malformed object (irefsym "
		    "field of module table entry %lu past the end of the "
		    "reference table", module_index);
		return(CHECK_BAD);
	    }
	    if(m.irefsym + m.nrefsym > dyst->nextrefsyms){
		Mach_O_error(ofile, "truncated or malformed object (irefsym "
		    "field of module table entry %lu plus nrefsym field "
		    "extends past the end of the reference table",module_index);
		return(CHECK_BAD);
	    }
	}
	if(m.nextrel != 0){
	    if(m.iextrel > dyst->extreloff){
		Mach_O_error(ofile, "truncated or malformed object (iextrel "
		    "field of module table entry %lu past the end of the "
		    "external relocation enrties", module_index);
		return(CHECK_BAD);
	    }
	    if(m.iextrel + m.nextrel > dyst->extreloff){
		Mach_O_error(ofile, "truncated or malformed object (iextrel "
		    "field of module table entry %lu plus nextrel field "
		    "extends past the end of the external relocation enrties",
		    module_index);
		return(CHECK_BAD);
	    }
	}
	return(CHECK_GOOD);
#endif /* OTOOL */
}

__private_extern__
unsigned long
size_ar_name(
const struct ar_hdr *ar_hdr)
{
    long i;

	i = sizeof(ar_hdr->ar_name) - 1;
	if(ar_hdr->ar_name[i] == ' '){
	    do{
		if(ar_hdr->ar_name[i] != ' ')
		    break;
		i--;
	    }while(i > 0);
	}
	return(i + 1);
}

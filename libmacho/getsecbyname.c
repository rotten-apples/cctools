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
#include <mach-o/ldsyms.h>
#include <mach-o/swap.h>
#include <string.h>
#ifdef __DYNAMIC__
#include "mach-o/dyld.h" /* defines _dyld_lookup_and_bind() */
#endif
#ifndef __OPENSTEP__
#include <crt_externs.h>
#else /* defined(__OPENSTEP__) */

#if !defined(__DYNAMIC__)
#define DECLARE_VAR(var, type) \
extern type var
#define SETUP_VAR(var)
#define USE_VAR(var) var
#else
#define STRINGIFY(a) # a
#define DECLARE_VAR(var, type)	\
static type * var ## _pointer = NULL
#define SETUP_VAR(var)						\
if ( var ## _pointer == NULL) {				\
    _dyld_lookup_and_bind( STRINGIFY(_ ## var),		\
                           (unsigned long *) & var ## _pointer, NULL);	\
}
#define USE_VAR(var) (* var ## _pointer)
#endif
#endif /* __OPENSTEP__ */

/*
 * This routine returns the section structure for the named section in the
 * named segment for the mach_header pointer passed to it if it exist.
 * Otherwise it returns zero.
 */
const struct section *
getsectbynamefromheader(
struct mach_header *mhp,
const char *segname,
const char *sectname)
{
	struct segment_command *sgp;
	struct section *sp;
	unsigned long i, j;
        
	sgp = (struct segment_command *)
	      ((char *)mhp + sizeof(struct mach_header));
	for(i = 0; i < mhp->ncmds; i++){
	    if(sgp->cmd == LC_SEGMENT)
		if(strncmp(sgp->segname, segname, sizeof(sgp->segname)) == 0 ||
		   mhp->filetype == MH_OBJECT){
		    sp = (struct section *)((char *)sgp +
			 sizeof(struct segment_command));
		    for(j = 0; j < sgp->nsects; j++){
			if(strncmp(sp->sectname, sectname,
			   sizeof(sp->sectname)) == 0 &&
			   strncmp(sp->segname, segname,
			   sizeof(sp->segname)) == 0)
			    return(sp);
			sp = (struct section *)((char *)sp +
			     sizeof(struct section));
		    }
		}
	    sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	}
	return((struct section *)0);
}


/*
 * This routine returns the section structure for the named section in the
 * named segment for the mach_header pointer passed to it if it exist.
 * Otherwise it returns zero.  If fSwap == YES (the mach header has been
 * swapped to the endiannes of the current machine, but the segments and
 * sections are different) then the segment and sections are swapped.
 */
const struct section *
getsectbynamefromheaderwithswap(
    struct mach_header *mhp,
    const char *segname,
    const char *sectname, 
    int fSwap)
{
	struct segment_command *sgp;
	struct section *sp;
	unsigned long i, j;

	sgp = (struct segment_command *)
	      ((char *)mhp + sizeof(struct mach_header));
	for(i = 0; i < mhp->ncmds; i++){
	    if(sgp->cmd == (fSwap ? NXSwapLong(LC_SEGMENT) : LC_SEGMENT)) {
	    
		if (fSwap) {
#ifdef __LITTLE_ENDIAN__
		    swap_segment_command(sgp, NX_BigEndian);
#else
		    swap_segment_command(sgp, NX_LittleEndian);
#endif /* __LITTLE_ENDIAN__ */
		}
	    
		if(strncmp(sgp->segname, segname, sizeof(sgp->segname)) == 0 ||
		   mhp->filetype == MH_OBJECT){
		    sp = (struct section *)((char *)sgp +
			 sizeof(struct segment_command));
		
		    if (fSwap) {
#ifdef __LITTLE_ENDIAN__
			swap_section(sp, sgp->nsects, NX_BigEndian);
#else
			swap_section(sp, sgp->nsects, NX_LittleEndian);
#endif /* __LITTLE_ENDIAN__ */
		    }
		
		    for(j = 0; j < sgp->nsects; j++){
			if(strncmp(sp->sectname, sectname,
			   sizeof(sp->sectname)) == 0 &&
			   strncmp(sp->segname, segname,
			   sizeof(sp->segname)) == 0)
			    return(sp);
			sp = (struct section *)((char *)sp +
			     sizeof(struct section));
		    }
		}
		sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	    } else {
		sgp = (struct segment_command *)((char *)sgp +
		    (fSwap ? NXSwapLong(sgp->cmdsize) : sgp->cmdsize));
	    }
	}
	return((struct section *)0);
}

/*
 * This routine returns the a pointer the section structure of the named
 * section in the named segment if it exist in the mach executable it is
 * linked into.  Otherwise it returns zero.
 */
const struct section *
getsectbyname(
const char *segname,
const char *sectname)
{
    static struct mach_header *mhp = NULL;
#ifndef __OPENSTEP__
	if (mhp == NULL) {
	    mhp = _NSGetMachExecuteHeader();
	}
#else /* defined(__OPENSTEP__) */
	DECLARE_VAR(_mh_execute_header, struct mach_header);
        SETUP_VAR(_mh_execute_header);
	mhp = (struct mach_header *)(& USE_VAR(_mh_execute_header));
#endif /* __OPENSTEP__ */
	return(getsectbynamefromheader(mhp, segname, sectname));
}

/*
 * This routine returns the a pointer to the data for the named section in the
 * named segment if it exist in the mach executable it is linked into.  Also
 * it returns the size of the section data indirectly through the pointer size.
 * Otherwise it returns zero for the pointer and the size.
 */
char *
getsectdata(
const char *segname,
const char *sectname,
unsigned long *size)
{
	const struct section *sp;

	sp = getsectbyname(segname, sectname);
	if(sp == (struct section *)0){
	    *size = 0;
	    return((char *)0);
	}
	*size = sp->size;
	return((char *)(sp->addr));
}

/*
 * This routine returns the a pointer to the data for the named section in the
 * named segment if it exist in the mach header passed to it.  Also it returns
 * the size of the section data indirectly through the pointer size.  Otherwise
 *  it returns zero for the pointer and the size.
 */
char *
getsectdatafromheader(
struct mach_header *mhp,
const char *segname,
const char *sectname,
unsigned long *size)
{
	const struct section *sp;

	sp = getsectbynamefromheader(mhp, segname, sectname);
	if(sp == (struct section *)0){
	    *size = 0;
	    return((char *)0);
	}
	*size = sp->size;
	return((char *)(sp->addr));
}

#ifdef __DYNAMIC__
/*
 * This routine returns the a pointer to the data for the named section in the
 * named segment if it exist in the named Framework.  Also it returns the size
 * of the section data indirectly through the pointer size.  Otherwise it
 * returns zero for the pointer and the size.  The last component of the path
 * of the Framework is passed as FrameworkName.
 */
void *
getsectdatafromFramework(
const char *FrameworkName,
const char *segname,
const char *sectname,
unsigned long *size)
{
    unsigned long i, n, vmaddr_slide;
    struct mach_header *mh;
    const struct section *s;
    char *name, *p;

        n = _dyld_image_count();
        for(i = 0; i < n ; i++){
            name = _dyld_get_image_name(i);
            p = strrchr(name, '/');
            if(p != NULL && p[1] != '\0')
                name = p + 1;
            if(strcmp(name, FrameworkName) != 0)
                continue;
            mh = _dyld_get_image_header(i);
            vmaddr_slide = _dyld_get_image_vmaddr_slide(i);
            s = getsectbynamefromheader(mh, segname, sectname);
            if(s == NULL){
                *size = 0;
                return(NULL);
            }
            *size = s->size;
            return((void *)(s->addr + vmaddr_slide));
        }
        *size = 0;
        return(NULL);
}
#endif /* __DYNAMIC__ */

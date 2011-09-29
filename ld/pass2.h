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
#if defined(__MWERKS__) && !defined(extern)
#define extern __declspec(private_extern)
#endif

/*
 * The total size of the output file and the memory buffer for the output file.
 */
extern unsigned long output_size;
extern char *output_addr;

/*
 * This is used to setting the SG_NORELOC flag in the segment flags correctly.
 * See the comments in the file pass2.c where this is defined.
 */
extern struct merged_section **output_sections;

extern void pass2(
    void);
#if defined(RLD) && !defined(SA_RLD)
extern void pass2_rld_symfile(
    void);
#endif /* defined(RLD) && !defined(SA_RLD) */
extern void output_flush(
    unsigned long offset,
    unsigned long size);

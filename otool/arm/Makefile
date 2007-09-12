CC = /usr/local/iphonedev/bin/arm-apple-darwin-cc
CPPFLAGS = -I../../include -I.. -DOTOOL
CFLAGS = -O2
LIBSTUFF_C_SOURCES = \
	SymLoc.c allocate.c arch.c arch_usage.c best_arch.c \
	breakout.c bytesex.c checkout.c crc32.c \
	dylib_roots.c dylib_table.c errors.c execute.c \
	fatal_arch.c fatals.c get_arch_from_host.c \
	get_toc_byte_sex.c guess_short_name.c hash_string.c \
	hppa.c macosx_deployment_target.c ofile.c \
	ofile_error.c ofile_get_word.c print.c \
	reloc.c round.c seg_addr_table.c set_arch_flag_name.c \
	swap_headers.c symbol_list.c unix_standard_mode.c \
	version_number.c vm_flush_cache.c writeout.c
OTOOL_C_SOURCES = \
	arm_disasm.c hppa_disasm.c i386_disasm.c \
	i860_disasm.c m68k_disasm.c m88k_disasm.c \
	main.c notify.c ofile_print.c \
	ppc_disasm.c sparc_disasm.c vers.c
OTOOL_OBJC_SOURCES = \
	print_objc.m
LIBSTUFF_OBJECTS = \
	$(patsubst %.c,%.o,$(LIBSTUFF_C_SOURCES))
OTOOL_OBJECTS = \
	$(patsubst %.c,%.o,$(OTOOL_C_SOURCES)) \
	$(patsubst %.m,%.o,$(OTOOL_OBJC_SOURCES))
VPATH = ../../libstuff:..

all: otool

otool: libstuff.a $(OTOOL_OBJECTS)
	$(CC) -o $@ -L. -lstuff $(OTOOL_OBJECTS)

libstuff.a: $(LIBSTUFF_OBJECTS)
	rm -f libstuff.a
	ar cru libstuff.a $(LIBSTUFF_OBJECTS)
	ranlib libstuff.a

clean:
	rm -f *.o libstuff.a otool

print_objc.o: print_objc.m
	$(CC) $(CPPFLAGS) $(CFLAGS) -ObjC -c $^ -o $@


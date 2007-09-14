INFERIORS=as nm ld strip
RESULTS=$(INFERIORS:%=arm-apple-darwin-valgrind-%)

all:	$(RESULTS)

arm-apple-darwin-valgrind-%:	valwrap.c
	gcc -Wall -DPROGRAM_TO_INVOKE=\"$*\" -o $@ $^

install:
	for x in $(RESULTS); do install -c $$x /usr/local/bin/$$x; done

.PHONY:	all install


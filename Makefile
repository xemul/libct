MAKEFLAGS 	:= -r -R --no-print-directory

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

FIND		:= find
CSCOPE		:= cscope
TAGS		:= ctags
RM		:= rm -f
CP		:= cp
LD		:= ld
CC		:= gcc
CD		:= cd
ECHO		:= echo
NM		:= nm
AWK		:= awk
SH		:= bash
MAKE		:= make
OBJCOPY		:= objcopy
MKDIR		:= mkdir
LN		:= ln
ESED		:= esed
SED		:= sed
CAT		:= cat

#
# Fetch ARCH from the uname if not yet set
#
ARCH ?= $(shell uname -m | sed		\
		-e s/i.86/i386/		\
		-e s/sun4u/sparc64/	\
		-e s/arm.*/arm/		\
		-e s/sa110/arm/		\
		-e s/s390x/s390/	\
		-e s/parisc64/parisc/	\
		-e s/ppc.*/powerpc/	\
		-e s/mips.*/mips/	\
		-e s/sh[234].*/sh/)

ifeq ($(ARCH),x86_64)
	ARCH         := x86
	DEFINES      := -DCONFIG_X86_64 -DARCH="\"$(ARCH)\""
	LDARCH       := i386:x86-64
endif

ifneq ($(ARCH),x86)
$(error "The architecture $(ARCH) isn't supported"))
endif

cflags-y	+= -iquote src/include
cflags-y	+= -fno-strict-aliasing
cflags-y	+= -I/usr/include
export cflags-y

VERSION_MAJOR		:= 0
VERSION_MINOR		:= 1
VERSION_SUBLEVEL	:= 0
VERSION_EXTRA		:=
VERSION_NAME		:=

export VERSION_MAJOR VERSION_MINOR VERSION_SUBLEVEL VERSION_EXTRA VERSION_NAME

include scripts/Makefile.version
include scripts/Makefile.config

LIBS		:= -lrt -lprotobuf-c

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

WARNINGS	:= -Wall

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
	CFLAGS	+= -O0 -ggdb3
else
	CFLAGS	+= -O2
endif

CFLAGS		+= $(WARNINGS) $(DEFINES)

export E Q CC ECHO MAKE CFLAGS LIBS ARCH DEFINES MAKEFLAGS
export SH RM OBJCOPY LDARCH LD CP MKDIR CD LN
export ESED SED CAT

include scripts/Makefile.rules

build := -r -R --no-print-directory -f scripts/Makefile.build makefile=Makefile obj
run := -r -R --no-print-directory

LIBCT		:= libct.so

.PHONY: all clean tags docs

cflags-y += -iquote src/include
cflags-y += -iquote src/arch/$(ARCH)/include
export cflags-y

#
# First order targets, usually pregenerated
EARLY-GEN := $(VERSION_HEADER) config

#
# Protobuf data, shared across library
# and executable tool
src/protobuf/%:
	$(Q) $(MAKE) $(build)=src/protobuf $@
src/protobuf:
	$(Q) $(MAKE) $(build)=src/protobuf all

.PHONY: src/protobuf

#
# Proxy
LIBCTD := libctd

LDFLAGS += -L$(shell pwd)

src/libctd/%: src/protobuf
	$(Q) $(MAKE) $(build)=src/libctd $@
src/libctd: src/protobuf
	$(Q) $(MAKE) $(build)=src/libctd all

.PHONY: src/libctd

src/libctd/$(LIBCTD): src/libctd/built-in.o $(LIBCT) src/protobuf/built-in.o
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) $(LDFLAGS) -lct -o $@

#
# Library itself
src/%: $(EARLY-GEN) | src/protobuf
	$(Q) $(MAKE) $(build)=src $@
src: $(EARLY-GEN) | src/protobuf
	$(Q) $(MAKE) $(build)=src all

.PHONY: src

$(LIBCT): src/$(LIBCT)
	$(E) "  LN      " $@
	$(Q) $(LN) -sf $^ $@

all: $(LIBCT) src/libctd/$(LIBCTD)
	@true

docs:
	$(Q) $(MAKE) -s -C Documentation all

docs-pdf:
	$(Q) $(MAKE) -s -C Documentation all-pdfs

tags:
	$(E) "  GEN     " $@
	$(Q) $(RM) tags
	$(Q) $(FIND) -L . -name '*.[hcS]' ! -path './.*' -print | xargs ctags -a

clean:
	$(Q) $(MAKE) $(build)=src clean
	$(Q) $(MAKE) $(build)=src/libctd clean
	$(Q) $(MAKE) $(build)=src/protobuf clean
	$(Q) $(MAKE) -s -C Documentation clean
	$(Q) $(RM) $(LIBCT)
	$(Q) $(RM) src/libctd/$(LIBCTD)
	$(Q) $(RM) $(CONFIG)
	$(Q) $(RM) $(VERSION_HEADER)

.DEFAULT_GOAL := all

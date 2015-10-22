VERSION_MAJOR           := 0
VERSION_MINOR           := 1
VERSION_SUBLEVEL        :=
VERSION_EXTRA           :=
VERSION_NAME            :=
VERSION_SO_MAJOR        := 0
VERSION_SO_MINOR        := 1

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

# Installation paths
PREFIX          ?= /usr/local
MANDIR          := $(PREFIX)/share/man
LIBDIR          := $(PREFIX)/lib
# For recent Debian/Ubuntu with multiarch support
DEB_HOST_MULTIARCH ?= $(shell dpkg-architecture \
                        -qDEB_HOST_MULTIARCH 2>/dev/null)
ifneq "$(DEB_HOST_MULTIARCH)" ""
LIBDIR          := $(PREFIX)/lib/$(DEB_HOST_MULTIARCH)
# For most other systems
else ifeq "$(shell uname -m)" "x86_64"
LIBDIR          := $(PREFIX)/lib64
endif

INCLUDEDIR      := $(PREFIX)/include/libct

ifneq ($(ARCH),x86)
$(error "The architecture $(ARCH) isn't supported"))
endif

ifneq ("$(wildcard /proc/vz)","")
	VZ := 1
endif


cflags-y	+= -iquote src/include
cflags-y	+= -iquote src/include/vz
cflags-y	+= -iquote src/lsm
cflags-y	+= -iquote src
cflags-y	+= -fno-strict-aliasing
cflags-y	+= -I/usr/include
cflags-y	+= -I/usr/include/libnl3
cflags-y	+= -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include
cflags-y	+= -I/usr/lib64/dbus-1.0/include/
cflags-y	+= -I/usr/include/dbus-1.0
export cflags-y

VERSION_MAJOR		:= 0
VERSION_MINOR		:= 1
VERSION_SUBLEVEL	:= 0
VERSION_EXTRA		:=
VERSION_NAME		:=
CONFIG_SELINUX		:=
CONFIG_APPARMOR		:=

# FAKE_LIBS is required for go bindings,
# because LDFLAGS can not be customized there
FAKE_LIBS		:=

export VERSION_MAJOR VERSION_MINOR VERSION_SUBLEVEL VERSION_EXTRA VERSION_NAME

include scripts/Makefile.version
include scripts/Makefile.config

LIBS		:= -lrt

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

WARNINGS	:= -Wall -Wno-unused-result

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
	CFLAGS	+= -O0 -ggdb3
else
	CFLAGS	+= -O2
endif

ifeq ($(CONFIG_APPARMOR),y)
	DEFINES += -DHAVE_APPARMOR
else
	FAKE_LIBS += libapparmor.a
endif

ifeq ($(CONFIG_SELINUX),y)
	DEFINES += -DHAVE_SELINUX
else
	FAKE_LIBS += libselinux.a
endif

CFLAGS		+= $(WARNINGS) $(DEFINES)

export E Q CC ECHO MAKE CFLAGS LIBS ARCH DEFINES MAKEFLAGS
export CONFIG_SELINUX CONFIG_APPARMOR
export SH RM OBJCOPY LDARCH LD CP MKDIR CD LN
export ESED SED CAT

include scripts/Makefile.rules

build := -r -R --no-print-directory -f scripts/Makefile.build makefile=Makefile obj
run := -r -R --no-print-directory

LIBCT		:= libct
LIBCT-INC	:= src/include/uapi/libct.h src/include/uapi/libct-log-levels.h src/include/uapi/libct-errors.h

.PHONY: all clean tags docs

cflags-y += -I.shipped/libnl/include/
cflags-y += -iquote src/include
cflags-y += -iquote src/arch/$(ARCH)/include
export cflags-y

#
# First order targets, usually pregenerated
EARLY-GEN := $(VERSION_HEADER) config

#
# Library itself
src/%: $(EARLY-GEN)
	$(Q) $(MAKE) $(build)=src $@
src: $(EARLY-GEN)
	$(Q) $(MAKE) $(build)=src all

.PHONY: src

$(LIBCT).a: src/$(LIBCT).a
	$(E) "  LN      " $@
	$(Q) $(LN) -sf $^ $@

$(LIBCT).so: src/$(LIBCT).so
	$(E) "  LN      " $@
	$(Q) $(LN) -sf $^ $@

libselinux.a: src/$(LIBCT).a
	$(Q) $(LN) -sf $^ $@

libapparmor.a: src/$(LIBCT).a
	$(Q) $(LN) -sf $^ $@

src/$(LIBCT).so: src/$(LIBCT).a

all: $(LIBCT).so $(LIBCT).a $(FAKE_LIBS)
	@true

test-build:
	$(Q) $(MAKE) -C test all

test: test-build
	$(Q) $(MAKE) -C test run-local

docs:
	$(Q) $(MAKE) -s -C Documentation all

docs-pdf:
	$(Q) $(MAKE) -s -C Documentation all-pdfs

tags:
	$(E) "  GEN     " $@
	$(Q) $(RM) tags
	$(Q) $(FIND) -L . \( -name '*.[hcS]' -o -name '*.go' \) ! -path './.*' -print | xargs ctags -a

clean:
	$(Q) $(MAKE) $(build)=src clean
	$(Q) $(MAKE) -C test clean
	$(Q) $(MAKE) -s -C Documentation clean
	$(Q) $(RM) $(LIBCT).so $(LIBCT).a
	$(Q) $(RM) $(CONFIG)
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(RM) libapparmor.a libselinux.a

install:
	$(E) "  INSTALL "
	$(Q) install -D -m 755 $(LIBCT).so \
		$(DESTDIR)$(LIBDIR)/$(LIBCT).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR)
	$(Q) ln -fns $(LIBCT).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR) \
		$(DESTDIR)$(LIBDIR)/$(LIBCT).so.$(VERSION_SO_MAJOR)
	$(Q) ln -fns $(LIBCT).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR) \
		$(DESTDIR)$(LIBDIR)/$(LIBCT).so
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)
	$(Q) install -m 644 $(LIBCT-INC) $(DESTDIR)$(INCLUDEDIR)


.DEFAULT_GOAL := all

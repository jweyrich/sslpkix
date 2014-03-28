####### Platform specifics

# cut is necessary for Cygwin
PLATFORM_OS := $(shell uname | cut -d_ -f1)

####### Makefile Conventions - Directory variables

prefix = /usr
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
sbindir = $(exec_prefix)/sbin
libexecdir = $(exec_prefix)/libexec
datarootdir = $(prefix)/share
datadir = $(datarootdir)
sysconfdir = $(prefix)/etc
localstatedir = $(prefix)/var
includedir = $(prefix)/include
docdir = $(datarootdir)/doc/libsslpkix
infodir = $(datarootdir)/info
libdir = $(exec_prefix)/lib
localedir = $(datarootdir)/locale
mandir = $(datarootdir)/man
man1dir = $(mandir)/man1
manext = .1
man1ext = .1
srcdir = src src/openssl/apps src/x509
testdir = test

####### Makefile Conventions - Utilities

CC ?= gcc
CXX ?= g++
LINK = $(CXX)
CHK_DIR_EXISTS = test -d
CHK_FILE_EXISTS = test -f
INSTALL = install
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = $(INSTALL)
SYMLINK = ln -sf
MKDIR = mkdir -p
RM = rm -f
RM_DIR = rm -rf
ifeq ($(PLATFORM_OS), Darwin)
	STRIP = strip -x
else
	STRIP = strip --strip-unneeded
endif

####### Compiler options

DEST = $(DESTDIR)$(libdir)
INCPATH = -Iinclude
override LFLAGS   += -lssl -lcrypto
override CFLAGS   += -pipe -O0 -g3 -Wall -Wextra -pedantic -fmessage-length=0 -std=c99
override CXXFLAGS += -pipe -O0 -g3 -Wall -Wextra -pedantic -fmessage-length=0 -std=c++03
override CPPFLAGS += -DDEBUG

ifeq ($(PLATFORM_OS), Darwin)
	# We disable warnings for deprecated declarations because Apple deprecated OpenSSL in Mac OS X 10.7
	override CFLAGS   += -Wno-deprecated-declarations
	override CXXFLAGS += -Wno-deprecated-declarations
endif

VERSION_MAJOR = 1
VERSION_MINOR = 0
VERSION_PATCH = 1
VERSION = $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)
LIBNAME = libsslpkix
TESTNAME = run_tests

libsslpkix_BUILDDIR = $(CURDIR)/build
libsslpkix_SRCS_FILTER = $(wildcard ${dir}/*.c) $(wildcard ${dir}/*.cpp)
libsslpkix_SRCS = $(foreach dir, ${srcdir}, ${libsslpkix_SRCS_FILTER})
libsslpkix_OBJS = $(addprefix ${libsslpkix_BUILDDIR}/, $(addsuffix .o, $(basename ${libsslpkix_SRCS})))

test_SRCS_FILTER = $(wildcard ${dir}/*.c) $(wildcard ${dir}/*.cpp)
test_SRCS = $(foreach dir, ${testdir}, ${test_SRCS_FILTER})
test_OBJS = $(addprefix ${libsslpkix_BUILDDIR}/, $(addsuffix .o, $(basename ${test_SRCS})))

####### Build rules

.PHONY : libsslpkix test install strip-binaries install-strip uninstall clean

all: libsslpkix test

test: libsslpkix
test: INCPATH += -Ilib/Catch/include
test: LFLAGS += -L$(libsslpkix_BUILDDIR) -lsslpkix
test: $(test_OBJS)
	@echo 'Building test binary: $(libsslpkix_BUILDDIR)/$(TESTNAME)'
	$(LINK) -o $(libsslpkix_BUILDDIR)/$(TESTNAME) $(test_OBJS) $(LFLAGS)

libsslpkix: CPPFLAGS += -DSSLPKIX_LIBRARY
libsslpkix: CFLAGS += -fPIC
libsslpkix: CXXFLAGS += -fPIC
libsslpkix: $(libsslpkix_OBJS)
	@# @echo "Building static library: $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION).a"
	@# $(AR) cqv $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION).a $^
	@# $(RANLIB) $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION).a
	@# major.a -> version.a
	@# $(SYMLINK) $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION).a $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION_MAJOR).a
	@# .a -> major.a
	@# $(SYMLINK) $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION_MAJOR).a $(libsslpkix_BUILDDIR)/$(LIBNAME).a
ifeq ($(PLATFORM_OS), Linux)
	@echo 'Building shared library: $(libsslpkix_BUILDDIR)/$(LIBNAME).so.$(VERSION)'
	$(LINK) -o $(libsslpkix_BUILDDIR)/$(LIBNAME).so.$(VERSION) $^ $(LFLAGS) -shared -Wl,-soname,$(LIBNAME).so.$(VERSION_MAJOR)
	@# .so.major -> .so.version
	$(SYMLINK) $(libsslpkix_BUILDDIR)/$(LIBNAME).so.$(VERSION) $(libsslpkix_BUILDDIR)/$(LIBNAME).so.$(VERSION_MAJOR)
	@# .so -> .so.major
	$(SYMLINK) $(libsslpkix_BUILDDIR)/$(LIBNAME).so.$(VERSION_MAJOR) $(libsslpkix_BUILDDIR)/$(LIBNAME).so
else ifeq ($(PLATFORM_OS), Darwin)
	@echo 'Building shared library: $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION).dylib'
	$(LINK) -o $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION).dylib $^ $(LFLAGS) \
		-headerpad_max_install_names -dynamiclib \
		-flat_namespace -install_name $(LIBNAME).$(VERSION).dylib \
		-current_version $(VERSION) -compatibility_version $(VERSION_MAJOR).0
	@# major.dylib -> version.dylib
	$(SYMLINK) $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION).dylib $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION_MAJOR).dylib
	@# .dylib -> major.dylib
	$(SYMLINK) $(libsslpkix_BUILDDIR)/$(LIBNAME).$(VERSION_MAJOR).dylib $(libsslpkix_BUILDDIR)/$(LIBNAME).dylib
else ifeq ($(PLATFORM_OS), CYGWIN)
	@echo 'Building shared library: $(libsslpkix_BUILDDIR)/$(LIBNAME).dll'
	$(LINK) -o $(libsslpkix_BUILDDIR)/$(LIBNAME).dll $^ $(LFLAGS) -shared
	@# TODO: Use windres to embed a resource with version information into the DLL?
endif

$(libsslpkix_BUILDDIR)/%.o: %.c
	@echo 'Building file: $<'
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS) $(INCPATH)

$(libsslpkix_BUILDDIR)/%.o: %.cpp
	@echo 'Building file: $<'
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(CPPFLAGS) $(INCPATH)

install: installdirs
	@#$(INSTALL_DATA) $(libsslpkix_BUILDDIR)/$(LIBNAME).a $(DEST)/$(LIBNAME).a.$(VERSION)
	@#cd $(DEST); $(SYMLINK) $(LIBNAME).a.$(VERSION) $(LIBNAME).a
	@#cd $(DEST); $(SYMLINK) $(LIBNAME).a.$(VERSION) $(LIBNAME).a.1
ifeq ($(PLATFORM_OS), Linux)
	$(INSTALL_DATA) $(libsslpkix_BUILDDIR)/$(LIBNAME).so $(DEST)/$(LIBNAME).so.$(VERSION)
	cd $(DEST); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so
	cd $(DEST); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so.1
else ifeq ($(PLATFORM_OS), Darwin)
	$(INSTALL_DATA) $(libsslpkix_BUILDDIR)/$(LIBNAME).dylib $(DEST)/$(LIBNAME).$(VERSION).dylib
	cd $(DEST); $(SYMLINK) $(LIBNAME).$(VERSION).dylib $(LIBNAME).dylib
	cd $(DEST); $(SYMLINK) $(LIBNAME).$(VERSION).dylib $(LIBNAME).1.dylib
else ifeq ($(PLATFORM_OS), CYGWIN)
	# TODO
endif

installdirs:
	@$(CHK_DIR_EXISTS) $(DEST) || $(MKDIR) $(DEST)

strip-binaries:
ifeq ($(PLATFORM_OS), Linux)
	$(STRIP) $(LIBNAME).so
else ifeq ($(PLATFORM_OS), Darwin)
	$(STRIP) $(LIBNAME).dylib
else ifeq ($(PLATFORM_OS), CYGWIN)
	$(STRIP) $(LIBNAME).dll
endif

install-strip: strip-binaries install

uninstall:
	$(RM) $(DEST)/$(LIBNAME).so* \
		$(DEST)/$(LIBNAME)*.dylib

clean:
	$(RM_DIR) $(libsslpkix_BUILDDIR)

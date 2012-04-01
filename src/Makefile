####### Platform specifics

PLATFORM_OS := $(shell uname)
PLATFORM_ARCH := $(shell uname -p)

####### Compiler, tools and options

CC				= gcc
CXX				= g++
DEFINES			= -DDEBUG
CFLAGS			= -pipe -O0 -g3 -Wall -Wextra -pedantic -rdynamic -fmessage-length=0 $(DEFINES)
CXXFLAGS		= -pipe -O0 -g3 -Wall -Wextra -pedantic -rdynamic -fmessage-length=0 $(DEFINES)
INCPATH			= -I../include
LINK			= g++
LFLAGS			=
LIBS			= -lssl -lcrypto
AR				= ar cq
RANLIB			= ranlib -s
TAR				= tar -cf
COMPRESS		= gzip -9f
COPY			= cp -f
SED				= sed
COPY_FILE		= cp -f
COPY_DIR		= cp -f -R
STRIP			=
INSTALL_FILE	= $(COPY_FILE)
INSTALL_DIR		= $(COPY_DIR)
INSTALL_PROGRAM	= $(COPY_FILE)
DEL_FILE		= rm -f
SYMLINK			= ln -sf
DEL_DIR			= rm -rf
MOVE			= mv -f
CHK_DIR_EXISTS	= test -d
MKDIR			= mkdir -p

####### Files

# Don't use := on recursively-expanding variable
SOURCE_DIRS		= . openssl/apps x509
SOURCE_FILTER	= $(wildcard $(dir)/*.cpp) $(wildcard $(dir)/*.c)
SOURCES			= $(foreach dir, $(SOURCE_DIRS), $(SOURCE_FILTER))
OBJECTS			= $(addprefix $(OBJECTS_DIR)/, $(addsuffix .o, $(basename ${SOURCES})))
DIST			=
DEST_DIR		= ../build
OBJECTS_DIR		= $(DEST_DIR)/obj
TARGET			= libsslpkix
TARGET_VERSION	= 1.0

####### Build rules

.PHONY: all clean build pre-build post-build build-static build-shared
.SECONDARY: post-build

all: build build-static build-shared

pre-build:
	@echo 'Compiling...'

post-build:
	@echo 'Done.'

build: pre-build build-static build-shared build-binary
	@$(MAKE) --no-print-directory post-build

build-static: $(OBJECTS)
	@echo 'Building static library: $(DEST_DIR)/$(TARGET).a'
	$(AR) $(DEST_DIR)/$(TARGET).$(TARGET_VERSION).a $(OBJECTS)
	$(RANLIB) $(DEST_DIR)/$(TARGET).$(TARGET_VERSION).a
	$(SYMLINK) $(TARGET).$(TARGET_VERSION).a $(DEST_DIR)/$(TARGET).a

build-shared: $(OBJECTS)
ifeq ($(PLATFORM_OS), Linux)
	@echo 'Building shared library: $(DEST_DIR)/$(TARGET).so'
	$(LINK) $(LFLAGS) -shared -Wl,-soname,$(TARGET).so.$(TARGET_VERSION) \
		-o $(DEST_DIR)/$(TARGET).so.$(TARGET_VERSION) $(OBJECTS) $(LIBS)
	$(SYMLINK) $(TARGET).so.$(TARGET_VERSION) $(DEST_DIR)/$(TARGET).so
endif
ifeq ($(PLATFORM_OS), Darwin)
	@echo 'Building shared library: $(DEST_DIR)/$(TARGET).dylib'
	$(LINK) $(LFLAGS) -headerpad_max_install_names -dynamiclib \
		-o $(DEST_DIR)/$(TARGET).$(TARGET_VERSION).dylib \
		-flat_namespace -install_name $(TARGET).$(TARGET_VERSION).dylib \
		$(LIBS) -current_version $(TARGET_VERSION) -compatibility_version $(TARGET_VERSION)
	$(SYMLINK) $(TARGET).$(TARGET_VERSION).dylib $(DEST_DIR)/$(TARGET).dylib
endif

build-binary: $(OBJECTS)

clean:
	-$(DEL_DIR) $(OBJECTS)
	-$(DEL_FILE) \
		$(DEST_DIR)/$(TARGET).a \
		$(DEST_DIR)/$(TARGET).$(TARGET_VERSION).a
ifeq "$(PLATFORM_OS)" "Linux"
	-$(DEL_FILE) \
		$(DEST_DIR)/$(TARGET).so \
		$(DEST_DIR)/$(TARGET).so.$(TARGET_VERSION)
endif
ifeq "$(PLATFORM_OS)" "Darwin"
	-$(DEL_FILE) \
		$(DEST_DIR)/$(TARGET).dylib \
		$(DEST_DIR)/$(TARGET).$(TARGET_VERSION).dylib
endif

####### Compile

$(OBJECTS_DIR)/%.o: %.c
	@echo 'Building file: $<'
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c $(CFLAGS) $(INCPATH) -o $@ $<

$(OBJECTS_DIR)/%.o: %.cpp
	@echo 'Building file: $<'
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o $@ $<

#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# CppUTest makefile for vyatta-controller
#

#
# NOTE ON COMPILER INCLUDE PATHS:
#
# Note that we are building in <pkg_root>/test/module, and all include paths
# that are not generic to all build environments (eg /usr/include is ok,
# /src/BUILD/... is not) have thus been converted to relative paths via
# PKG_ROOT.

PKG_ROOT = ../..

#
# Put all objects away from source code in a 'well-know' location that ensures
# debian will always build from 'clean'.
#
BLD_DIR = build

#
# Just report the running of the test case rather than the whole build
# sequence.
#
MAKEFLAGS += --quiet

############################################################################
#                                                                          #
#          EVERYTHING ABOVE THIS POINT IS COMPLETELY GENERIC               #
#                                                                          #
############################################################################


#
# Changes below are specific to the test environment.
#
# Need this to ensure images get built cleanly when DEB_BUILD_HARDENING
# is enabled - hardening trashes the "linker magic" used by cpputest.
#
export DEB_BUILD_HARDENING_PIE=0

CFLAGS += -Wall -Wextra -g -O1
CPPFLAGS += -D_GNU_SOURCE -I$(PKG_ROOT)/daemon
CPPFLAGS += -I$(PKG_ROOT)/test/module/src
CPPFLAGS += -I$(PKG_ROOT)/test/module/src/mocks

# We could remove this if every stubs fn had __unused after every parameter
# but that makes the files quite ugly to read, and allowing unused params
# within test code doesn't seem entirely unreasonable.
CFLAGS += -Wno-unused-parameter

# Create dependencies files so we can do incremental test builds
CFLAGS += -MD

#
# These generate errors with -Werror enabled for C++ compilation as they are
# not valid for C++, so we need to filter them out.
#
#	-Wmissing-prototypes \
#	-Wnested-externs \
#	-Wold-style-definition \
#	-Wstrict-prototypes \
#
C_ONLY_FLAGS := \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wold-style-definition \
	-Wstrict-prototypes

#
# Additionally, we add extra flags/defines for CPP as follows:
#
# __STDC_LIMIT_MACROS: avoids 'UINT8_MAX' not declared in scope type errors
#
CXXFLAGS += \
	$(filter-out $(C_ONLY_FLAGS), $(CFLAGS)) \
	-D__STDC_LIMIT_MACROS

############################################################################
#                                                                          #
#          EVERYTHING AFTER THIS POINT IS COMPLETELY GENERIC               #
#                                                                          #
############################################################################

#
# Local definitions.  If above, CPP gets set to cpp and build fails.
#
CC = gcc
CPP = g++

LDFLAGS += -g -lstdc++ -L/usr/lib/x86_64-linux-gnu -lCppUTest -lCppUTestExt

#
# Pull in all our test definitions.  These include _SRCS and also _CFLAGS /
# _CPPFLAGS so each test can override existing flags (custom flags go at the
# end).  Each test adds its name to $(TESTS)
#
include *.mk

.PHONY: all
all: $(TESTS)

#
# C_OBJ_template and CPP_OBJ_template
#
# As we wish to build multiple tests with a single make command, and we may
# well be using common source code, quite possibly compiled with different
# compiler flags, we need to ensure we create rules for each object that allow
# for this.  Welcome to GNU makefile templates ...
#
# Each template takes the following inputs:
#
#  $(1): name of test
#  $(2): relative path to source file from '<pkg>/tests' directory in which
#        make is being run
#
# Each template carries out the following actions:
#
#  1) includes dependencies file (leading '-' indicates 'if it exists')
#
#  2) creates a rule for obj/<test_name>/<src_file_root>.o that depends on
#     the <relative_path_to>/src_file.[c|cpp] that will perform the following:
#
#       - create obj/<test_name> if it doesn't exist
#       - run gcc/g++ with common and test-specific CFLAGS on the source file,
#         putting the object created into obj/<test_name>/<src_file_root>.o
#
define C_OBJ_template
-include $(BLD_DIR)/obj/$(1)/$(notdir $(patsubst %.c,%.d,$(2)))
$(BLD_DIR)/obj/$(1)/$(notdir $(patsubst %.c,%.o,$(2))): $(2)
	mkdir -p $(BLD_DIR)/obj/$(1)
	$(CC) $(CPPFLAGS) $($(1)_CPPFLAGS) $(CFLAGS) $($(1)_CFLAGS) -o $(BLD_DIR)/obj/$(1)/$(notdir $(patsubst %.c,%.o,$(2))) -c $(2)
endef

define CPP_OBJ_template
-include $(BLD_DIR)/obj/$(1)/$(notdir $(patsubst %.cpp,%.d,$(2)))
$(BLD_DIR)/obj/$(1)/$(notdir $(patsubst %.cpp,%.o,$(2))): $(2)
	mkdir -p $(BLD_DIR)/obj/$(1)
	$(CPP) $(CPPFLAGS) $($(1)_CPPFLAGS) $(CXXFLAGS) $($(1)_CXXFLAGS) -o $(BLD_DIR)/obj/$(1)/$(notdir $(patsubst %.cpp,%.o,$(2))) -c $(2)
endef

#
# TEST_template
#
define TEST_template
# ALL tests need all_tests.cpp - top level CppUTest call that uses the magic
# of reflection to find all tests without them having to be individually
# registered (or forgotten!).
$(eval $(call CPP_OBJ_template,$(1),src/all_tests.cpp))

#
# Now we need to create C or CPP compilation templates for the SRC files.
# Note we could have C and CPP SRCs explicitly called out, likewise we could
# separate out UUT vs test/support code if we needed different build flags.
#
$(foreach src,$(filter %.c,$($(1)_SRCS)),$(eval $(call C_OBJ_template,$(1),$(src))))

$(foreach src,$(filter %.cpp,$($(1)_SRCS)),$(eval $(call CPP_OBJ_template,$(1),$(src))))

#
# I'm sure the prerequisites could be expressed more cleanly but I can't for
# the life of me get patsubst to substitute . o for .c and .cpp in one command,
# and neither can I get the $(foo:.c=.o) type substitution to work.  Sigh.
#
$(1): $(addprefix $(BLD_DIR)/obj/$(1)/,$(notdir $(patsubst %.c,%.o,$(filter %.c,$($(1)_SRCS))))) $(addprefix $(BLD_DIR)/obj/$(1)/,$(notdir $(patsubst %.cpp,%.o,$(filter %.cpp,$($(1)_SRCS))))) $(BLD_DIR)/obj/$(1)/all_tests.o
	@echo "Unit Test - building $(1)"
	@mkdir -p $(BLD_DIR)/bin
	$(CPP) -o $(BLD_DIR)/bin/$(1) $(BLD_DIR)/obj/$(1)/all_tests.o \
	$(addprefix $(BLD_DIR)/obj/$(1)/,$(notdir $(patsubst %.c,%.o,$(filter %.c,$($(1)_SRCS))))) \
	$(addprefix $(BLD_DIR)/obj/$(1)/,$(notdir $(patsubst %.cpp,%.o,$(filter %.cpp,$($(1)_SRCS))))) \
	$(LDFLAGS) $($(1)_LDFLAGS)
	@echo "Unit Test - running $(1)"
	$(BLD_DIR)/bin/$(1)
endef

$(foreach test,$(TESTS),$(eval $(call TEST_template,$(test))))

install:

clean:
	@rm -rf $(BLD_DIR)

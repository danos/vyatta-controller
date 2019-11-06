#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

vplane_test_SRCS := \
	../../daemon/vplane.c \
	src/vplane_cpputest.cpp \
	src/mocks/common_mocks.cpp \
	src/mocks/parser_mocks.cpp \


vplane_test_CPPFLAGS =

vplane_test_CFLAGS = $(shell pkg-config --cflags libczmq json-c)

vplane_test_CXXFLAGS = $(shell pkg-config --cflags libczmq)

vplane_test_LDFLAGS = $(shell pkg-config --libs libczmq json-c)

TESTS += vplane_test

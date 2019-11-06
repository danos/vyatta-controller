#
# Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

parser_test_SRCS := \
	../../daemon/parser.c \
	src/parser_cpputest.cpp \
	src/mocks/common_mocks.cpp \

parser_test_CFLAGS = $(shell pkg-config --cflags libczmq json-c)

parser_test_CXXFLAGS = $(shell pkg-config --cflags libczmq)

parser_test_LDFLAGS = $(shell pkg-config --libs libczmq json-c)
parser_test_LDFLAGS += -linih

TESTS += parser_test

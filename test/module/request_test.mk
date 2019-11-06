#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

request_test_SRCS := \
	../../daemon/request.c \
	../../daemon/vplane.c \
	../../daemon/devname.c \
	src/request_cpputest.cpp \
	src/mocks/common_mocks.cpp \
	src/mocks/parser_mocks.cpp \
	src/mocks/snapshot_mocks.cpp

request_test_CPPFLAGS =

request_test_CFLAGS = $(shell pkg-config --cflags libczmq json-c)

request_test_CXXFLAGS = $(shell pkg-config --cflags libczmq)

request_test_LDFLAGS = $(shell pkg-config --libs libczmq json-c)

TESTS += request_test

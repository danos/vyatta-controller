#
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

snapshot_test_SRCS := \
	../../daemon/snapshot.c \
	../../daemon/nlmsg.c \
	../../daemon/topic.c \
	../../daemon/mnlutil.c \
	src/snapshot_cpputest.cpp \
	src/mocks/common_mocks.cpp \
	src/mocks/parser_mocks.cpp

snapshot_test_CPPFLAGS =

snapshot_test_CFLAGS = $(shell pkg-config --cflags libczmq libzmq json-c libmnl)

snapshot_test_CXXFLAGS = $(shell pkg-config --cflags libczmq libzmq libmnl)
snapshot_test_CXXFLAGS += -std=c++11

snapshot_test_LDFLAGS = $(shell pkg-config --libs libczmq libzmq json-c libmnl)

TESTS += snapshot_test

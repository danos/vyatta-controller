#
# Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

nlmsg_test_SRCS := \
	../../daemon/nlmsg.c \
	../../daemon/topic.c \
	../../daemon/mnlutil.c \
	src/nlmsg_cpputest.cpp \
	src/mocks/common_mocks.cpp \
	src/mocks/parser_mocks.cpp

nlmsg_test_CPPFLAGS =

nlmsg_test_CFLAGS = $(shell pkg-config --cflags libczmq libzmq json-c libmnl)

nlmsg_test_CXXFLAGS = $(shell pkg-config --cflags libczmq libzmq libmnl)
nlmsg_test_CXXFLAGS += -std=c++11

nlmsg_test_LDFLAGS = $(shell pkg-config --libs libczmq libzmq json-c libmnl)

TESTS += nlmsg_test

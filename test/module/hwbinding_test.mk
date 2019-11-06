#
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

hwbinding_test_SRCS := \
	../../daemon/hwbinding.c \
	src/hwbinding_cpputest.cpp \
	src/mocks/common_mocks.cpp \

hwbinding_test_CPPFLAGS = -I../../ini/

hwbinding_test_CFLAGS = $(shell pkg-config --cflags libczmq)
hwbinding_test_CXXFLAGS = $(shell pkg-config --cflags libczmq)

hwbinding_test_LDFLAGS = $(shell pkg-config --libs libczmq)

TESTS += hwbinding_test

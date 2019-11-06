#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# Copyright (c) 2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

libvplaned_cfg_test_SRCS := \
	../../lib/vplaned_cfg.c \
	src/libvplaned_cfg_cpputest.cpp \
	src/mocks/common_mocks.cpp

libvplaned_cfg_test_CPPFLAGS = -I ../../lib

libvplaned_cfg_test_CFLAGS = $(shell pkg-config --cflags libczmq json-c)

libvplaned_cfg_test_CXXFLAGS = $(shell pkg-config --cflags libczmq json-c)
libvplaned_cfg_test_CXXFLAGS += -std=c++11

libvplaned_cfg_test_LDFLAGS = $(shell pkg-config --libs libczmq json-c)

TESTS += libvplaned_cfg_test

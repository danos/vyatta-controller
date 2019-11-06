#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

libvplaned_cstore_test_SRCS := \
	../../lib/vplaned_cstore.c \
	src/libvplaned_cstore_cpputest.cpp \
	src/mocks/common_mocks.cpp

libvplaned_cstore_test_CPPFLAGS = -I ../../lib

libvplaned_cstore_test_CFLAGS = $(shell pkg-config --cflags libczmq json-c)

libvplaned_cstore_test_CXXFLAGS = $(shell pkg-config --cflags libczmq json-c)
libvplaned_cstore_test_CXXFLAGS += -std=c++11

libvplaned_cstore_test_LDFLAGS = $(shell pkg-config --libs libczmq json-c)

TESTS += libvplaned_cstore_test

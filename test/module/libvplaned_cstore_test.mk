#
# Copyright (c) 2018-2020, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

libvplaned_cstore_test_SRCS := \
	../../lib/vplaned_cstore.c \
	../../lib/DataplaneEnvelope.pb-c.c \
	../../lib/VPlanedEnvelope.pb-c.c \
	src/libvplaned_cstore_cpputest.cpp \
	src/mocks/common_mocks.cpp

libvplaned_cstore_test_CPPFLAGS = -I ../../lib

libvplaned_cstore_test_CFLAGS = $(shell pkg-config --cflags libczmq json-c)

libvplaned_cstore_test_CXXFLAGS = $(shell pkg-config --cflags libczmq json-c)
libvplaned_cstore_test_CXXFLAGS += -std=c++11

libvplaned_cstore_test_LDFLAGS = $(shell pkg-config --libs libczmq json-c libprotobuf-c)
libvplaned_cstore_test_LDFLAGS += -lb64

TESTS += libvplaned_cstore_test

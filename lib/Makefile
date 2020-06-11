# Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

CFLAGS += -g -fPIC
CFLAGS += $(shell pkg-config --cflags libczmq json-c libprotobuf-c)


NAME := vplaned
OBJS := vplaned_cfg.o vplaned_cstore.o vplaned_event.o DataplaneEnvelope.pb-c.o \
	VPlanedEnvelope.pb-c.o
LIB := lib$(NAME).a

all: lib

lib: $(OBJS)
	$(AR) rs $(LIB) $(OBJS)

vplaned_cstore.o: DataplaneEnvelope.pb-c.h VPlanedEnvelope.pb-c.h

DataplaneEnvelope.pb-c.c DataplaneEnvelope.pb-c.h:
	protoc-c --c_out=. -I=/usr/share/vyatta-dataplane/protobuf/ $(DESTDIR)/usr/share/vyatta-dataplane/protobuf/DataplaneEnvelope.proto

VPlanedEnvelope.pb-c.c VPlanedEnvelope.pb-c.h:
	protoc-c --c_out=. -I=../protobuf ../protobuf/VPlanedEnvelope.proto

clean:
	$(RM) $(LIB) $(OBJS)

install: $(LIB) vplaned.h vplaned_cfg.h vplaned_cstore.h vplaned_event.h \
	libvplaned.pc
	install -D vplaned.h $(DESTDIR)/usr/include/vplaned.h
	install -D vplaned_cfg.h $(DESTDIR)/usr/include/vplaned_cfg.h
	install -D vplaned_cstore.h $(DESTDIR)/usr/include/vplaned_cstore.h
	install -D vplaned_event.h $(DESTDIR)/usr/include/vplaned_event.h
	install -D libvplaned.pc $(DESTDIR)/usr/lib/pkgconfig/libvplaned.pc
	install -D $(LIB) $(DESTDIR)/usr/lib/$(LIB)

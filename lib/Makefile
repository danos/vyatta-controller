# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

CFLAGS += -g -fPIC
CFLAGS += $(shell pkg-config --cflags libczmq json-c)

NAME := vplaned
OBJS := vplaned_cfg.o vplaned_cstore.o vplaned_event.o
LIB := lib$(NAME).a

all: lib

lib: $(OBJS)
	$(AR) rs $(LIB) $(OBJS)

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

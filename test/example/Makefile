# Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

CPPFLAGS += -D_GNU_SOURCE -I ../../lib
CFLAGS += -g
CFLAGS += $(shell pkg-config --cflags libczmq json-c)

         LIBS += -L../../lib -lvplaned
         LIBS += $(shell pkg-config --libs libczmq json-c)

BFD_OBJS = bfdtest.o

all: bfdtest

bfdtest: $(BFD_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ \
	      $(BFD_OBJS) $(LIBS)

clean:
	rm -f $(BFD_OBJS) bfdtest

install: bfdtest
	install bfdtest $(DESTDIR)/opt/vyatta/bin

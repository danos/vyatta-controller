# Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2012-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

# binary name
NAME = vplaned

CPPFLAGS += -D_GNU_SOURCE
CFLAGS += -g
CFLAGS += -pthread
CFLAGS += $(shell pkg-config --cflags libczmq)
CFLAGS += $(shell pkg-config --cflags libzmq)
CFLAGS += $(shell pkg-config --cflags json-c)
CFLAGS += $(shell pkg-config --cflags libmnl)
CFLAGS += $(shell pkg-config --cflags libvrfmanager-vyatta)
CFLAGS += $(shell pkg-config --cflags libprotobuf-c)
CFLAGS += $(shell pkg-config --cflags libsystemd)

LDFLAGS += -pthread

LIBS += $(shell pkg-config --libs libczmq)
LIBS += $(shell pkg-config --libs libzmq)
LIBS += $(shell pkg-config --libs json-c)
LIBS += $(shell pkg-config --libs libmnl)
LIBS += $(shell pkg-config --libs libvrfmanager-vyatta)
LIBS += $(shell pkg-config --libs libprotobuf-c)
LIBS += $(shell pkg-config --libs libsystemd)
LIBS += -linih
LIBS += -lb64

OBJS  = main.o VPlanedEnvelope.pb-c.o topic.o request.o snapshot.o nlmsg.o \
	util.o port.o tunnel.o protobuf.o \
	configcmd.o configdb.o configstore.o mrtstat.o team.o \
	parser.o vplane.o devname.o hwbinding.o \
	fsnotify.o mnlutil.o

all: $(NAME)

protobuf.o: VPlanedEnvelope.pb-c.c VPlanedEnvelope.pb-c.h

VPlanedEnvelope.pb-c.c VPlanedEnvelope.pb-c.h: ../protobuf/VPlanedEnvelope.proto
	../scripts/vyatta-generate-pb-perl.pl VPlanedEnvelope.proto ../scripts ../protobuf
	protoc -I=../protobuf --python_out=../scripts ../protobuf/VPlanedEnvelope.proto
	protoc-c --c_out=. -I=../protobuf ../protobuf/VPlanedEnvelope.proto

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $(NAME) $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(NAME)

install: $(NAME)
	install $(NAME) $(DESTDIR)/opt/vyatta/sbin


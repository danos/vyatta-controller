PROTO_FILES = VPlanedEnvelope.proto

CXXFLAGS += -fPIC
CXXFLAGS += $(shell pkg-config --cflags protobuf)
LIBS += $(shell pkg-config --libs protobuf)

GODIR = go/VPlanedEnvelope
GOLIB = $(GODIR)/VPlanedEnvelope.pb.go
GODESTDIR = $(DESTDIR)/usr/share/gocode/src/github.com/danos/vyatta-controller/protobuf/go/VPlanedEnvelope

CPP_SOURCES = $(PROTO_FILES:.proto=.pb.cc)
CPP_HEADERS = $(PROTO_FILES:.proto=.pb.h)
OBJS = $(CPP_SOURCES:.cc=.oxx)
CPP_TARGET = libvyatta-controller-proto.so.1
CPP_TARGET_LINK = libvyatta-controller-proto.so
PKG_CONFIG = $(patsubst lib%.so.1,%.pc,$(CPP_TARGET))

all: $(GOLIB) $(CPP_TARGET_LINK) $(PKG_CONFIG)

%.pb.cc: %.proto
	protoc -I=$(dir $^) --cpp_out=$(dir $@) $^

%.oxx: %.cc
	g++ $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $^

$(CPP_TARGET): $(OBJS)
	g++ -shared -fPIC $(LDFLAGS) $(LIBS) -Wl,-soname,$@ -o $@ $^

$(CPP_TARGET_LINK): $(CPP_TARGET)
	ln -s $^ $@

$(PKG_CONFIG):
	echo 'prefix=/usr' >> $@
	echo 'exec_prefix=$${prefix}' >> $@
	echo 'libdir=$${exec_prefix}/lib/$(DEB_HOST_MULTIARCH)' >> $@
	echo 'includedir=$${exec_prefix}/include/vyatta-controller/proto' >> $@
	echo '' >> $@
	echo 'Name: vyatta-controller-proto' >> $@
	echo 'Description: VPlaned controller protobufs' >> $@
	echo 'Version: 1.0.0' >> $@
	echo 'Libs: -L$${libdir} -lvyatta-controller-proto' >> $@
	echo 'Cflags: -I$${includedir}' >> $@

$(GOLIB): VPlanedEnvelope.proto
	mkdir -p $(GODIR)
	protoc -I=. --go_out=paths=source_relative:$(GODIR) VPlanedEnvelope.proto

install: $(GOLIB)
	install -d $(GODESTDIR)
	install -m 644 $(GOLIB) $(GODESTDIR)

clean:
	rm -rf $(GODIR)
	rm -f $(CPP_TARGET) $(CPP_TARGET_LINK) $(OBJS) $(PKG_CONFIG)

GODIR = go/VPlanedEnvelope
GOLIB = $(GODIR)/VPlanedEnvelope.pb.go
GODESTDIR = $(DESTDIR)/usr/share/gocode/src/github.com/danos/vyatta-controller/protobuf/go/VPlanedEnvelope

$(GOLIB): VPlanedEnvelope.proto
	mkdir -p $(GODIR)
	protoc -I=. --go_out=paths=source_relative:$(GODIR) VPlanedEnvelope.proto

all: $(GOLIB)

install: $(GOLIB)
	install -d $(GODESTDIR)
	install -m 644 $(GOLIB) $(GODESTDIR)

clean:
	rm -rf $(GODIR)

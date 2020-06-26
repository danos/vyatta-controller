# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property.

protobuf_source = files(
        'VPlanedEnvelope.proto'
)

install_data(protobuf_source,
        install_dir: get_option('datadir') / 'vyatta-dataplane' / 'protobuf'
)

protoc = find_program('protoc')

controller_protobuf_c = custom_target('controller_protobuf_c',
        input: protobuf_source,
        output: ['VPlanedEnvelope.pb-c.c', 'VPlanedEnvelope.pb-c.h'],
        command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--c_out=@OUTDIR@', '@INPUT@'],
)

controller_protobuf_cxx = custom_target('controller_protobuf_cxx',
        input: protobuf_source,
        output: ['VPlanedEnvelope.pb.cc', 'VPlanedEnvelope.pb.h'],
        command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--cpp_out=@OUTDIR@', '@INPUT@'],
        install: true,
        install_dir: [false, get_option('includedir') / 'vyatta-controller' / 'proto'],
)

controller_proto_cxx_library = shared_library(
        'vyatta-controller-proto',
        sources: [controller_protobuf_cxx],
        dependencies: [proto_cxx_dep],
        install: true,
        soversion: 1
)

pkg = import('pkgconfig')
pkg.generate(controller_proto_cxx_library, subdirs: 'vyatta-controller/proto')

protobuf_py = custom_target('controller_protobuf_py',
        input: protobuf_source,
        output: ['VPlanedEnvelope_pb2.py'],
        command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--python_out=@OUTDIR@', '@INPUT@'],
        install: true,
        install_dir: 'lib/python3/dist-packages/vyatta/proto'
)

perl_generator = files('../scripts/vyatta-generate-pb-perl.pl')

protobuf_perl = custom_target('controller_protobuf_perl',
        input: protobuf_source,
        output: ['VPlanedEnvelope.pm'],
        command: [perl_generator, '@INPUT@', '@OUTDIR@', '@CURRENT_SOURCE_DIR@'],
        install: true,
        install_dir: 'share/perl5/vyatta/proto'
)

protobuf_go = custom_target('controller_protobuf_go',
        input: protobuf_source,
        output: ['VPlanedEnvelope.pb.go'],
        command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--go_out=paths=source_relative:@OUTDIR@', '@INPUT@'],
        install: true,
        install_dir: 'share/gocode/src/github.com/danos/vyatta-controller/protobuf/go/VPlanedEnvelope'
)



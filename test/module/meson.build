# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property.

cpputest_dep = dependency('cpputest')

common_test_includes = include_directories(
        '../../daemon',
        'src',
        'src/mocks'
)
common_test_sources = files(
        'src/mocks/common_mocks.cpp',
        'src/all_tests.cpp'
)

hwbinding_test = executable(
        'hwbinding_test',
        sources: [
                '../../daemon/hwbinding.c',
                'src/hwbinding_cpputest.cpp',
                common_test_sources
        ],
        include_directories: common_test_includes,
        dependencies: [
                cpputest_dep,
                czmq_dep
        ]
)

test('HW Binding', hwbinding_test, workdir : meson.current_source_dir())

lib_include = include_directories('../../lib')

libvplaned_cfg_test = executable(
        'libvplaned_cfg_test',
        sources: [
                '../../lib/vplaned_cfg.c',
                'src/libvplaned_cfg_cpputest.cpp',
                common_test_sources
        ],
        include_directories: [common_test_includes, lib_include],
        dependencies: [
                cpputest_dep,
                czmq_dep,
                json_dep
        ]
)

test('Vplaned CFG', libvplaned_cfg_test)

libvplaned_cstore_test = executable(
        'libvplaned_cstore_test',
        sources: [
                '../../lib/vplaned_cstore.c',
                'src/libvplaned_cstore_cpputest.cpp',
                dataplane_protobuf_c,
                controller_protobuf_c,
                common_test_sources
        ],
        include_directories: [common_test_includes, lib_include],
        dependencies: [
                cpputest_dep,
                czmq_dep,
                json_dep,
                b64_dep,
                proto_c_dep
        ]
)

test('Vplaned Config Store', libvplaned_cstore_test)

nlmsg_test = executable(
        'nlmsg_test',
        sources: [
                '../../daemon/nlmsg.c',
                '../../daemon/topic.c',
                '../../daemon/mnlutil.c',
                'src/nlmsg_cpputest.cpp',
                'src/mocks/parser_mocks.cpp',
                common_test_sources
        ],
        include_directories: [common_test_includes],
        dependencies: [
                cpputest_dep,
                czmq_dep,
                json_dep,
                mnl_dep,
                zmq_dep
        ],
        cpp_args : '-Wno-unused-parameter'
)

test('Net Link MSG', nlmsg_test)

parser_test = executable(
        'parser_test',
        sources: [
                '../../daemon/parser.c',
                'src/parser_cpputest.cpp',
                common_test_sources
        ],
        include_directories: [common_test_includes],
        dependencies: [
                cpputest_dep,
                czmq_dep,
                json_dep,
                ini_dep
        ],
        cpp_args : '-Wno-unused-parameter'
)

test('Parser', parser_test, workdir : meson.current_source_dir())

request_test = executable(
        'request_test',
        sources: [
                '../../daemon/request.c',
                '../../daemon/vplane.c',
                '../../daemon/devname.c',
                'src/request_cpputest.cpp',
                'src/mocks/parser_mocks.cpp',
                'src/mocks/snapshot_mocks.cpp',
                common_test_sources
        ],
        include_directories: [common_test_includes],
        dependencies: [
                cpputest_dep,
                czmq_dep,
                json_dep,
        ],
        cpp_args : '-Wno-unused-parameter'
)

test('Requests', request_test)

snapshot_test = executable(
        'snapshot_test',
        sources: [
                '../../daemon/snapshot.c',
                '../../daemon/nlmsg.c',
                '../../daemon/topic.c',
                '../../daemon/mnlutil.c',
                'src/snapshot_cpputest.cpp',
                'src/mocks/parser_mocks.cpp',
                common_test_sources
        ],
        include_directories: [common_test_includes],
        dependencies: [
                cpputest_dep,
                czmq_dep,
                json_dep,
                mnl_dep,
                zmq_dep
        ],
        cpp_args : '-Wno-unused-parameter'
)

test('Requests', snapshot_test)

vplane_test = executable(
        'vplane_test',
        sources: [
                '../../daemon/vplane.c',
                'src/vplane_cpputest.cpp',
                'src/mocks/parser_mocks.cpp',
                common_test_sources
        ],
        include_directories: [common_test_includes],
        dependencies: [
                cpputest_dep,
                czmq_dep,
                json_dep,
        ],
        cpp_args : '-Wno-unused-parameter'
)

test('Vplaned', vplane_test)
# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property.

executable(
        'bfdtest',
        sources: ['bfdtest.c'],
        dependencies: [
                b64_dep,
                czmq_dep,
                json_dep,
                vplaned_dep
        ],
        install: true,
        install_dir: '/opt/vyatta/bin'
)

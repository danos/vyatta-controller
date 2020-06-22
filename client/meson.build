executable(
        'vplsh',
        sources: ['vplsh.c'],
        dependencies: [
                czmq_dep,
                json_dep,
                libedit_dep,
                vplaned_dep
        ],
        install: true,
        install_dir : '/opt/vyatta/bin'
)

executable(
        'snapshot',
        sources: ['snapshot.c'],
        dependencies: [
                czmq_dep,
                json_dep,
                mnl_dep,
                vplaned_dep
        ],
        install: true,
        install_dir : '/opt/vyatta/bin'
)

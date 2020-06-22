executable(
        'vplane-snmp',
        sources: ['vplane-snmp.c'],
        dependencies: [
                czmq_dep,
                json_dep,
                vplaned_dep
        ],
        install: true,
        install_dir: '/opt/vyatta/sbin'
)

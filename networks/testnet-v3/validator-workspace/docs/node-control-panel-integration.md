# Node Control Panel Integration

The Synergy Node Control Panel must create validators using the canonical contract in this repository:

- create or reuse Linux user `node`
- install the validator binary at `/opt/synergy/bin/synergy-validator`
- write non-secret config under `/etc/synergy/validator`
- write key material under `/etc/synergy/validator/keys`
- write chain data under `/var/lib/synergy/validator`
- write logs under `/var/log/synergy/validator`
- install `synergy-validator.service`
- install optional `synergy-node-control-panel.service`

Installers must not create one-off workspaces such as `validator-6-control-panel`.


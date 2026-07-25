# Testnet Validator Debug Cheat Sheet (Windows PowerShell)

Use this file when debugging a control-panel-managed validator appliance from Windows.

These commands assume the target Linux validator appliance root is:

- `/var/lib/synergy/validator`

Important:

- Local validator peer inspection uses JSON-RPC `synergy_getPeerInfo` on `http://127.0.0.1:5640`
- Do not use `http://127.0.0.1:5640/peers` for the local validator RPC
- Replace the validator address or hostname examples as needed
- These commands are written for PowerShell, not `cmd.exe`

## Set Common Variables

Run this block first if you want to use the `$Appliance`, `$Rpc`, `$Log`, `$PeerInfoBody`, and `$LatestBlockBody` shortcuts shown below.

```powershell
$Appliance = '/var/lib/synergy/validator'
$Rpc = 'http://127.0.0.1:5640'
$Log = "$Appliance\logs\control-start.stdout.log"
$PeerInfoBody = @{ jsonrpc = '2.0'; id = 1; method = 'synergy_getPeerInfo'; params = @() } | ConvertTo-Json -Compress
$LatestBlockBody = @{ jsonrpc = '2.0'; id = 1; method = 'synergy_getLatestBlock'; params = @() } | ConvertTo-Json -Compress
```

## Show Full Peer Payload

```powershell
Invoke-RestMethod -Uri $Rpc -Method Post -ContentType 'application/json' -Body $PeerInfoBody |
  Select-Object -ExpandProperty result |
  ConvertTo-Json -Depth 6
```

## Show Only Validator Peers

```powershell
Invoke-RestMethod -Uri $Rpc -Method Post -ContentType 'application/json' -Body $PeerInfoBody |
  Select-Object -ExpandProperty result |
  Select-Object -ExpandProperty peers |
  Where-Object { $_.validator_address -and $_.validator_address.Trim() -ne '' } |
  Select-Object public_address, validator_address, genesis_hash
```

## Show Only Status-Ready Validator Peers

```powershell
Invoke-RestMethod -Uri $Rpc -Method Post -ContentType 'application/json' -Body $PeerInfoBody |
  Select-Object -ExpandProperty result |
  Select-Object -ExpandProperty peers |
  Where-Object {
    $_.validator_address -and $_.validator_address.Trim() -ne '' -and
    $_.genesis_hash -and $_.genesis_hash.Trim() -ne ''
  } |
  Select-Object public_address, validator_address, genesis_hash
```

## Show Remote Validator Counts

This does not include the local validator. Add `1` if you want the same self-inclusive mental model used by the control panel.

```powershell
$result = Invoke-RestMethod -Uri $Rpc -Method Post -ContentType 'application/json' -Body $PeerInfoBody
$peers = @($result.result.peers)
$connected = @(
  $peers |
    Where-Object { $_.validator_address -and $_.validator_address.Trim() -ne '' } |
    Select-Object -ExpandProperty validator_address -Unique
)
$statusReady = @(
  $peers |
    Where-Object {
      $_.validator_address -and $_.validator_address.Trim() -ne '' -and
      $_.genesis_hash -and $_.genesis_hash.Trim() -ne ''
    } |
    Select-Object -ExpandProperty validator_address -Unique
)
[pscustomobject]@{
  peer_count = $result.result.peer_count
  remote_connected_validators = $connected.Count
  remote_status_ready_validators = $statusReady.Count
}
```

## Watch Validator Peer State Live

This version uses the variables from the block above.

```powershell
while ($true) {
  Get-Date
  Invoke-RestMethod -Uri $Rpc -Method Post -ContentType 'application/json' -Body $PeerInfoBody |
    Select-Object -ExpandProperty result |
    Select-Object -ExpandProperty peers |
    Where-Object { $_.validator_address -and $_.validator_address.Trim() -ne '' } |
    Select-Object public_address, validator_address, genesis_hash
  ''
  Start-Sleep -Seconds 2
}
```

Copy-paste version without variables:

```powershell
while ($true) {
  Get-Date
  $body = @{ jsonrpc = '2.0'; id = 1; method = 'synergy_getPeerInfo'; params = @() } | ConvertTo-Json -Compress
  Invoke-RestMethod -Uri 'http://127.0.0.1:5640' -Method Post -ContentType 'application/json' -Body $body |
    Select-Object -ExpandProperty result |
    Select-Object -ExpandProperty peers |
    Where-Object { $_.validator_address -and $_.validator_address.Trim() -ne '' } |
    Select-Object public_address, validator_address, genesis_hash
  ''
  Start-Sleep -Seconds 2
}
```

## Show Advertised Addresses And Consensus Thresholds

```powershell
Select-String -Path "$Workspace\config\node.toml" -Pattern 'public_host|public_address|validator_address|min_validators|status_ready_min_validators|persistent_peers'
```

## Show Bootstrap And Peer Overlay Inputs

```powershell
Select-String -Path "$Workspace\config\peers.toml" -Pattern 'bootnodes|seed_servers|additional_dial_targets|persistent_peers'
```

## Show The Current Latest Block Response

```powershell
Invoke-RestMethod -Uri $Rpc -Method Post -ContentType 'application/json' -Body $LatestBlockBody |
  Select-Object -ExpandProperty result |
  ConvertTo-Json -Depth 6
```

## Tail The Validator Log

```powershell
Get-Content $Log -Tail 120
```

## Follow The Validator Log Live

```powershell
Get-Content $Log -Wait
```

## Show Handshake, Status, Disconnect, And Dial Failures

```powershell
Select-String -Path $Log -Pattern 'Handshake received|Received status|Peer disconnected|Failed to dial peer' |
  Select-Object -Last 120
```

## Show Events For One Specific Validator Address

Example for validator `#1`:

```powershell
Select-String -Path $Log -Pattern 'synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs' |
  Select-Object -Last 80
```

## Show Listening Sockets On Validator Ports

```powershell
Get-NetTCPConnection -State Listen -LocalPort 5622,5640 |
  Select-Object LocalAddress, LocalPort, OwningProcess
```

## Show The Running Validator Process

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -match 'synergy-testnet' -or $_.CommandLine -match 'synergy-testnet' } |
  Select-Object ProcessId, Name, CommandLine
```

## Test Reachability To Another Validator

Example for validator `#1`:

```powershell
Test-NetConnection genesisval1.synergy-network.io -Port 5622
```

## Quick Interpretation

- `validator_address = ""` or `null`: peer transport exists, but validator identity handshake is not complete
- `genesis_hash = ""`: validator identity is known, but status sync has not completed yet
- Repeated `Handshake received` followed by `Peer disconnected`: the validator session is flapping
- `Failed to dial peer`: outbound dial path is failing
- Stable validator mesh requires the validator peer to stay visible in the JSON-RPC output, not only in old startup log lines

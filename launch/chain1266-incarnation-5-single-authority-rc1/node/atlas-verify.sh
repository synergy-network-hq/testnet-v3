#!/bin/bash
RPC=$(curl -s --max-time 8 -X POST http://127.0.0.1:5640 -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getBlockNumber","params":[]}' | python3 -c "import sys,json;print(json.load(sys.stdin)['result'])")
DB=$(sudo -u postgres psql -d synergy_explorer_v3 -tAc "select coalesce(max(number),0) from blocks;")
API=$(curl -s --max-time 8 http://127.0.0.1:3020/api/v1/network/summary | python3 -c "import sys,json;print(json.load(sys.stdin)['latestBlock'])")
echo "RPC_HEIGHT=$RPC ATLAS_DB=$DB ATLAS_API=$API LAG=$((RPC-DB))"
sudo -u postgres psql -d synergy_explorer_v3 -tAc "select 'rows='||count(*)||' head='||max(number)||' missing='||(max(number)-count(*))||' duplicates='||(count(*)-count(distinct number)) from blocks;"
echo -n "parent_mismatches="
sudo -u postgres psql -d synergy_explorer_v3 -tAc "select count(*) from blocks b join blocks p on p.number = b.number-1 where b.parent_hash <> p.hash;"
for H in 1 10 500 "$DB"; do
  RH=$(curl -s --max-time 8 -X POST http://127.0.0.1:5640 -H 'content-type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"synergy_getBlockByNumber\",\"params\":[$H]}" | python3 -c "import sys,json;r=json.load(sys.stdin).get('result') or {};print(r.get('hash',''))")
  AH=$(sudo -u postgres psql -d synergy_explorer_v3 -tAc "select hash from blocks where number=$H;")
  if [ "$RH" = "$AH" ]; then echo "height $H MATCH $RH"; else echo "height $H MISMATCH rpc=$RH atlas=$AH"; fi
done
sudo -u postgres psql -d synergy_explorer_v3 -tAc "select 'block1 validator='||validator_address||' protocol='||consensus_protocol from blocks where number=1;"

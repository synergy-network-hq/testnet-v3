"""One-way relocation of the attributed legacy gateway custody and history.

NodeNetwork embeds this module. The published 1266 gateway already has a
separate live transport on the destination. These assets stay inactive and
never replace a running service, account, identity, or finalized store.
"""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request


SOURCE = "8683ea9f4da9e9c05c26b6d8070cc13c0f5f75b0cd4a4de863492164f4c1e26d"
DESTINATION = "ca5c0c0942ab929347f279038fdcf001662a47c2cf3b53a5c631e74830755303"
GENESIS = "2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74"
CONTEXT = {"chain_id": 1266, "chain_incarnation": 5, "genesis_hash": GENESIS}
IDENTITY = Path("/etc/synergy/testnet-v3/rpc-gateway/identity")
HISTORY = Path("/var/lib/synergy/testnet-v3/rpc-gateway/chain-1266/incarnation-4/data")
DESTINATION_ROOT = Path("/opt/synergy/chain1266")
IMPORT = "relocated-rpc-gateway-incarnation-4"
RECORDS_IMPORT = "relocated-rpc-gateway-records"
ASSETS = {
    "identity.enc.json": (IDENTITY / "identity.enc.json", 31824,
        "170941eb372a70a5ad0308c00b2bc304a73f4d63f515c57d519d98e84caa652f"),
    "identity.pub.json": (IDENTITY / "identity.pub.json", 10673,
        "7b82e7aec612d088239c745f43ee6cca32980a0856d1080e809ba716ebcc0d26"),
    "identity-manifest.json": (IDENTITY / "manifest.json", 1449,
        "f23079c740ff8fc90693caf7f2a68e2fe5391bacbd0a31ede5923af603178008"),
    "coordinated-round-robin-finality.json": (HISTORY / "coordinated-round-robin-finality.json", 33117469,
        "448b40d579dda56fb24b384ccc844fed6170533d672183e8cbf597b6042e29f9"),
}
# Exact audited file inventory. Historical payloads remain opaque and inactive.
RECORDS = """
4-rc14-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc14/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc14-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc14/metadata.json|622|3ea54f59b923eacf526d6e3c0144a3b559deb0a8b7f37bb245d8f47d168fb1cd|501|50
4-rc14-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc14/node.env|901|3d779885f81ea8176f17a1739d1c60850a173b86d1aec41e4f13d81a11a25c33|501|50
4-rc14-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc14/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc14-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc14/bin/synergy-rpc-gateway-node|43990600|4375ed5915f2730391536d9c7273d78b3c72abf4a0ac182efdbeef0cacbee34a|501|50
4-rc16-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc16/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc16-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc16/metadata.json|622|3e84df4b07156680876b13afdaa4a02312f23d7f0622de1aa9eff7a812500842|501|50
4-rc16-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc16/node.env|901|2afddc3401036506479b6a5071f8e776aee7f4375587b4e4c75439c064436f97|501|50
4-rc16-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc16/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc16-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc16/bin/synergy-rpc-gateway-node|43526616|ca9ff486322bc2cec1b8582e85ea84b636ed46988b84e83ad7b4a42637570b1a|501|50
4-rc17-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc17/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc17-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc17/metadata.json|622|51657e0ed2d263cef9454230ec0d6ea6b20bfde1b43896454392fb72a26bb767|501|50
4-rc17-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc17/node.env|901|d7203d40cda8ffa387ccc509ddccec85989bf86e3c848cc38e04450b25eca5ef|501|50
4-rc17-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc17/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc17-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc17/bin/synergy-rpc-gateway-node|43534888|a71e9c03d33fc23456dadd674f61b8de96bbbd367ced3918e8a1535a94f17f19|501|50
4-rc18-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc18/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc18-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc18/metadata.json|622|c74ea636846f01ecb7497666a49d12a917126ef0f8597ae4ac1ef704d8b0476e|501|50
4-rc18-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc18/node.env|901|2a63e6556ad7529be76a0cb6c3aa9a1adc13782d870f818c19509f6e8eff8013|501|50
4-rc18-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc18/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc18-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc18/bin/synergy-rpc-gateway-node|43540344|517f1989d83672b8ead7e18073c8e435d8c877e8369bc7c766a6e444776172a9|501|50
4-rc19-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc19/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc19-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc19/metadata.json|622|81b516f0af020d176d9334afd7826837e1550b05b45bbfe21c0b343608d96746|501|50
4-rc19-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc19/node.env|901|51436f4e9fa34d8514be8addcac3a808928432f7e1e3a5675c88e5e9cdeca74a|501|50
4-rc19-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc19/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc19-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc19/bin/synergy-rpc-gateway-node|43542024|d333c61487593a2d7b5bafdfc35b9184addae2f54f20036f869ca90ec4b06773|501|50
4-rc20-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc20/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc20-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc20/metadata.json|622|2d6a1e8797b57ff3e4740e6abf4f93585f9c805e7c775f13bf6cbc0ff8215fbc|501|50
4-rc20-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc20/node.env|901|6c7c23a84310f2da512aa838d634ff2d250815cb4e4daf3c2d26c662fadf04ca|501|50
4-rc20-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc20/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc20-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc20/bin/synergy-rpc-gateway-node|34392192|d6e6bd6f3c4e28abcd7b279e4b2d0a4fee6be7312371c2577016996f9cef833b|501|50
4-rc21-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc21/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc21-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc21/metadata.json|622|d21c915a845a7de37821135abe0f7731ba0bf660765dc27549ca6d13250b31b1|501|50
4-rc21-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc21/node.env|901|2a1d6ee268d328d1575f10815d02fefbd20a83e231ba0e8b03841031d0b2de9a|501|50
4-rc21-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc21/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc21-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc21/bin/synergy-rpc-gateway-node|34397792|18e6a37cc0e3fa9c82ade9e3a260eea74cc96d22659cfc3a204a6254b754244b|501|50
4-rc22-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc22/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc22-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc22/metadata.json|622|cf7dfb41fbf11cec81ea50754877a76c11c44649bb25934f63e0ae582f9f5393|501|50
4-rc22-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc22/node.env|901|732112ccdd39051a24a968e0c3bbabe22f291fd48a06f24cccdf4d9ef4c69260|501|50
4-rc22-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc22/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc22-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc22/bin/synergy-rpc-gateway-node|34395648|7c0dfbc11e9ef3c6e2387a409aaa5e3389c7153f3e2b3def528002ed8425d62c|501|50
4-rc23-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc23/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc23-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc23/metadata.json|622|89a3ff05f08fbe2c8b45cd11c6b0b436ebfeb565546b29ce30432997a8b73362|501|50
4-rc23-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc23/node.env|901|9e24674cc9a8d18a1a98408189aa54ba3e081809955130424595df74f6ee3bc8|501|50
4-rc23-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc23/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc23-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc23/bin/synergy-rpc-gateway-node|34383008|8c4acf4da9baa0bf2256e5abeb00121e235a5c7353d6a2ea4a8257604d95cf3a|501|50
4-rc24-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc24/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc24-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc24/metadata.json|622|35f5b0e0e6dfc6e3961a3b6360813707bda2f40db1e40a9084fb1a2f5514f920|501|50
4-rc24-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc24/node.env|901|0d659e307d11616ecc7e0ad156f61c95f43b8c59ce560c474372a850cfe1a953|501|50
4-rc24-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc24/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc24-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc24/bin/synergy-rpc-gateway-node|34387168|ead230a4f0dae4023aa62f9e3d18c5efa372065a471b7c5f14f49d25302fc63f|501|50
4-rc25-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc25/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc25-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc25/metadata.json|622|2e071925d67e7e12c82f560d37e26b9e3136ef4f733cd1a54a5090bc1ce68033|501|50
4-rc25-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc25/node.env|901|bb9621502ab2fb186efefdce3a2b7bb83ec4e668f5098d456fbc4c8ca57909fc|501|50
4-rc25-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc25/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc25-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc25/bin/synergy-rpc-gateway-node|34387520|580f1fa8aadeb8b2a327634907c07bf68199f41a908551b9ad9ae1fccfafbd64|501|50
4-rc27-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc27/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc27-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc27/metadata.json|622|2a27b534f92ff6aa654e63c3eb49aab5c70086f00e3b11a6d88ba50fade35c42|501|50
4-rc27-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc27/node.env|901|7bb3be84bfae924da1846fa27fc48f392a03833759094ecb1d6ad0ef92937bd5|501|50
4-rc27-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc27/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc27-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc27/bin/synergy-rpc-gateway-node|34387680|ae12ec7aa98c7318ae28e907d953f745a203bd96d27c16acb419e11187ec1803|501|50
4-rc28-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc28/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc28-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc28/metadata.json|622|a8a4410ea6dbd8979a6e2d11f60ea81195cb4bc7c3e1a275b585173de7b3d710|501|50
4-rc28-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc28/node.env|901|3a8b7dee690026e0f07bb0497511ddc8bc902f756eaa192bcbf0cc5633374f1e|501|50
4-rc28-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc28/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc28-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc28/bin/synergy-rpc-gateway-node|34386336|2e91e46123b44a86628d8c6914da09e522130280fc0fffb48f1b369997d1a455|501|50
4-rc29-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc29/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc29-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc29/metadata.json|622|6dd57365f64f578fc2279ea7b5d6d0407c4c70209685983ff052ba7b5ff9d9d6|501|50
4-rc29-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc29/node.env|901|824732154d390a82c20f959bbd2efb459e4a44252acc24dd75f9fc159e7e2655|501|50
4-rc29-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc29/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc29-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc29/bin/synergy-rpc-gateway-node|34386336|039ab09777dd7ed8c4f2fb2e2a38fd4afe5b50815f90f17ec3451d930352f5a4|501|50
4-rc30-config.toml|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/config.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|501|50
4-rc30-metadata.json|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/metadata.json|622|fc8704827c942deef99d2fc8c431c09927ea8c88be56ea245715ae01f8c9c5e5|501|50
4-rc30-node.env|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/node.env|901|af37bc75e6b1ddda27ca18ef996658266fe780a56a6fd6b195d8e08378fe4614|501|50
4-rc30-synergy-chain1266-role-template.service|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/systemd/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|501|50
4-rc30-synergy-rpc-gateway-node|/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/bin/synergy-rpc-gateway-node|34386432|4020428db1ab29f89b43796882df02a585bc47311f41f1b0d9dc6df1865fe619|501|50
gateway-chain.json|/var/lib/synergy/testnet-v3/rpc-gateway/chain-1266/incarnation-4/data/chain.json|416|03285068a6f5d7cee9fd7ad1c706358b3f8e746322c34733b4528b538734b39d|0|0
gateway-dag-state.json|/var/lib/synergy/testnet-v3/rpc-gateway/chain-1266/incarnation-4/data/dag_state.json|118|dc80aaeb8362594870ca36ffc4bbd7f226432ff65b39ece78d955261e4a6c486|0|0
gateway-node.toml|/etc/synergy/testnet-v3/rpc-gateway/node.toml|4992|d38a240ec91ba4d0438cc166e5f1a7e0b5e9caaa0d9a39862ef1b6a436a1b689|0|0
gateway-old-runtime.service|/etc/systemd/system/synergy-testnet-v3-rpc-gateway.service|1608|e1d8022cb317c07ddd9e52817ebce9758552ebe6a8ac6ac818157cfb03458e36|0|0
gateway-role.env|/etc/synergy/chain1266/rpc-gateway.env|901|af37bc75e6b1ddda27ca18ef996658266fe780a56a6fd6b195d8e08378fe4614|0|0
gateway-role.service|/etc/systemd/system/synergy-chain1266-role@.service|590|21b6e4ba7d7de7aabcc295dcbe247b40ec83f7acc0b88364edddda39f80b7b6f|0|0
gateway-rpc-nginx.conf|/etc/nginx/sites-available/testnet-core-rpc.synergy-network.io|4003|40185e6d077d2074467b841ee01baedaebb3e808ea6908f7c5322892c53a3b4b|0|0
gateway-runtime.env|/etc/synergy/testnet-v3/rpc-gateway/runtime.env|241|913c7f14dabfa7feaa67c3fbf710e1556194e316ddd97fe5bf97cffe3e6ead92|0|0
gateway-runtime.env.example|/etc/synergy/testnet-v3/rpc-gateway/runtime.env.example|200|154d40eefc809ff732f0dae5607a6566cd4dd01dc8a5827db5f1df5316547511|0|0
gateway-synid-registry.json|/var/lib/synergy/testnet-v3/rpc-gateway/chain-1266/incarnation-4/data/synid_registry.json|238|4899d03dd352060792b8dbd8e69d8bb94899f74df09c6ab6033615fef511152c|0|0
gateway-tunnel.service|/etc/systemd/system/synergy-chain1266-rpc-tunnel.service|583|01db4a0c93376cd633df48fe14fdc21090c6c6fd8cc6bc981fc02520f2799f7c|0|0
genesisrpc.log|/var/log/synergy/rpc-gateway/genesisrpc.log|3730697|3ff9731c45e5551f9e14ff92b3e5df12020e73849ec36f88167c263da39f8bad|997|982
genesisrpc.log.1781794150|/var/log/synergy/rpc-gateway/genesisrpc.log.1781794150|10485778|685f703c8dc7f7681d98c4ce2a09cfefaa7b55d9992580f4a565226a06e572aa|997|982
genesisrpc.log.1781810239|/var/log/synergy/rpc-gateway/genesisrpc.log.1781810239|10485809|58ee9acd0124ec6d4b93cabaa2b9f1408a59a33cb3aad69dd3fa688bd2b84fd0|997|982
genesisrpc.log.1781826514|/var/log/synergy/rpc-gateway/genesisrpc.log.1781826514|10485819|1f31576054c489bba83ed1e0e313686b7a80296d2cdecdc293545d3a4bded783|997|982
genesisrpc.log.1781842815|/var/log/synergy/rpc-gateway/genesisrpc.log.1781842815|10485824|df5bc26bcbd7340a0f0db184b41a6451cf90bb9801c07c8a39c2aeb397fb65b0|997|982
genesisrpc.log.1781859432|/var/log/synergy/rpc-gateway/genesisrpc.log.1781859432|10485802|c7a172b466598043e5c2d7c7095ec97f2ceec3e58c2458c8ca75e2aa33f03425|997|982
genesisrpc.log.1781903670|/var/log/synergy/rpc-gateway/genesisrpc.log.1781903670|10485823|b77a54a93393fbf84874bcf79240dd5fa09c03d3ec8a957e1b32420f4efba756|997|982
genesisrpc.log.1781916260|/var/log/synergy/rpc-gateway/genesisrpc.log.1781916260|10485862|3e4ad3be9a717e122a4f993f0ac10f1d7b0518504fd925d49b7d1dfaa2c967d4|997|982
genesisrpc.log.1781926957|/var/log/synergy/rpc-gateway/genesisrpc.log.1781926957|10485835|f6e71f8e81ebc3ff26574c57a438a1d1a739f243643fbff469068a89eb043cfd|997|982
genesisrpc.log.1781937592|/var/log/synergy/rpc-gateway/genesisrpc.log.1781937592|10485803|dddaa795a44808a5fea7cb2f977871f7920b30338ad5744d6f04102fdff4d34b|997|982
genesisrpc.log.1781948260|/var/log/synergy/rpc-gateway/genesisrpc.log.1781948260|10485846|332538931752bda36db1ed810a851299c0d8374f8af54fadeaad6833fab78949|997|982
genesisrpc.log.1781958904|/var/log/synergy/rpc-gateway/genesisrpc.log.1781958904|10485842|7d158d08df77569ef04029789c7c1e107e2321532b371a3809fdb6d7878a74e9|997|982
genesisrpc.log.1781969577|/var/log/synergy/rpc-gateway/genesisrpc.log.1781969577|10485761|1c56fecb1bc87418157d9b2f60d9c2c20b68846cd9c1652c08844dbf9192a906|997|982
genesisrpc.log.1781980034|/var/log/synergy/rpc-gateway/genesisrpc.log.1781980034|10485870|523ed685e287815466aceea329aab538a7d858084f374931e69e56c38eacfc1b|997|982
genesisrpc.log.1781990392|/var/log/synergy/rpc-gateway/genesisrpc.log.1781990392|10485781|f29d550902ef7368a67a806fe050aed8f51e2e9d18625639fe18da38e56078f9|997|982
genesisrpc.log.1782000779|/var/log/synergy/rpc-gateway/genesisrpc.log.1782000779|10485834|f69805f9e6735b2e23d5ea5f74bcf44771895935c5d0eabf797fdef7000e1809|997|982
genesisrpc.log.1782011249|/var/log/synergy/rpc-gateway/genesisrpc.log.1782011249|10485848|21d95077999f75c42b985049534317aad93f8d82dd50e216d031ad89b2d82e0f|997|982
genesisrpc.log.1782021754|/var/log/synergy/rpc-gateway/genesisrpc.log.1782021754|10485805|41c69783e0b10c935cfe239369233bb5e70c2ade338ba4a6cbb2728c72a2830b|997|982
genesisrpc.log.1782032221|/var/log/synergy/rpc-gateway/genesisrpc.log.1782032221|10485812|0062042eb18c78beb9228f072bb8d30261c2de5b057aea33238986621ea8ee15|997|982
genesisrpc.log.1782042687|/var/log/synergy/rpc-gateway/genesisrpc.log.1782042687|10485822|d8537be3af3bca8ab797b0bf119ff3a2f8f3804e731c3b0fa55a5dfb36c59506|997|982
genesisrpc.log.1782053201|/var/log/synergy/rpc-gateway/genesisrpc.log.1782053201|10485810|0d8b6f0a7bdc61a1b4ec76b244408b6744a2014f4be84042e761716a096abeb5|997|982
genesisrpc.log.1782065251|/var/log/synergy/rpc-gateway/genesisrpc.log.1782065251|10485781|257072679e2253d6fc7118202f4aa54a292c6277d8ae1366f9493f8b5099d57b|997|982
genesisrpc.log.1782075114|/var/log/synergy/rpc-gateway/genesisrpc.log.1782075114|10485918|d406b39d0c59bdf757d85f3018618199d3557b0233dc90eff255e5b638195f67|997|982
genesisrpc.log.1782083354|/var/log/synergy/rpc-gateway/genesisrpc.log.1782083354|10485776|43736947683ab677af7f67a042c13e507aa705300e193a96728667bac461b4f7|997|982
genesisrpc.log.1782092058|/var/log/synergy/rpc-gateway/genesisrpc.log.1782092058|10485805|d5a0d18599f1571d2507dc90712e486a6756df7a61c0404073f35410f228b822|997|982
genesisrpc.log.1782102798|/var/log/synergy/rpc-gateway/genesisrpc.log.1782102798|10485823|596968a8e9e293747003eec92b202d58f9cd0e31b7d24829375a725cdc770e4f|997|982
genesisrpc.log.1782113539|/var/log/synergy/rpc-gateway/genesisrpc.log.1782113539|10485840|cc8f606a993c2b8725b1af7aec72baee5850157afc3e9186cf5ad101c5bc0812|997|982
genesisrpc.log.1782123803|/var/log/synergy/rpc-gateway/genesisrpc.log.1782123803|10485872|4d1b926d163ab48f85577aeaf727a496d1a3bde1788d0d2c2b51a4ebaab191f4|997|982
genesisrpc.log.1782133981|/var/log/synergy/rpc-gateway/genesisrpc.log.1782133981|10485967|66eef223c82c3d122e65bd4aabbae3b6cdf213788114050c455dfa6c9e60f951|997|982
genesisrpc.log.1782144230|/var/log/synergy/rpc-gateway/genesisrpc.log.1782144230|10485838|77dfe1ee750588edc8a6d915feb312cc3f20b05a221ee17af3e2123d76ea75ec|997|982
genesisrpc.log.1782154517|/var/log/synergy/rpc-gateway/genesisrpc.log.1782154517|10485818|01f88869433561710c33df96037d90fbfbf46f248338cc4c296a987adbddd50f|997|982
genesisrpc.log.1782164797|/var/log/synergy/rpc-gateway/genesisrpc.log.1782164797|10485819|982a31d1e16d93add9b7c0b64a7fa6a7365e56f335c54f314f7e380f997ad799|997|982
genesisrpc.log.1782175076|/var/log/synergy/rpc-gateway/genesisrpc.log.1782175076|10485769|69587ff3ca6e4278fa5a1cf3b5409b785661f3f5bb40fe6bd04bd1fc934df8dc|997|982
genesisrpc.log.1782185342|/var/log/synergy/rpc-gateway/genesisrpc.log.1782185342|10485808|3e0ab6150a0a3ab6624e411b44e775dbe15f85a18a78e3b30126d73935e966fe|997|982
genesisrpc.log.1782196269|/var/log/synergy/rpc-gateway/genesisrpc.log.1782196269|10485810|67b69ad0f21f7aaa04a797c215e4229c0e1c57c9bd57f9134e3617503d6061fc|997|982
genesisrpc.log.1782207432|/var/log/synergy/rpc-gateway/genesisrpc.log.1782207432|10485801|757e7f23d0764c7304d7c36749fa00b2a228d764f1e6a3defa6e25b17ca49da1|997|982
genesisrpc.log.1782218179|/var/log/synergy/rpc-gateway/genesisrpc.log.1782218179|10485765|76a2c02827669c1ed55b8696b5f509a05c2d7114f43f1e6740e44335112b410b|997|982
genesisrpc.log.1782229127|/var/log/synergy/rpc-gateway/genesisrpc.log.1782229127|10485764|3fecafaad78a1ac3a6457487c5388ba53b030c92f3a977987f8e18765c52aab7|997|982
genesisrpc.log.1782240775|/var/log/synergy/rpc-gateway/genesisrpc.log.1782240775|10485769|8324b4088be2020dbeb3aa8c1e4a11b0515cc40599931e6d54e689b1a68d39c5|997|982
genesisrpc.log.1782253311|/var/log/synergy/rpc-gateway/genesisrpc.log.1782253311|10486131|c875ebe3dfae7ea0b6b1640ff7d805d1e7dc1b432b0f9a3171ca062bf557932b|997|982
genesisrpc.log.1782268097|/var/log/synergy/rpc-gateway/genesisrpc.log.1782268097|10485762|85aea6f00abb19c3f33afc2ddf8339c1275aab4e346ed2a570a4a3e59b33a198|997|982
genesisrpc.log.1782284654|/var/log/synergy/rpc-gateway/genesisrpc.log.1782284654|10485774|4290666ee3f8f0b1bcede53134d17f047aaaa1c0a3eb38226884d06c5fc4215e|997|982
genesisrpc.log.1782301210|/var/log/synergy/rpc-gateway/genesisrpc.log.1782301210|10485842|13df0a0b6fefad0628fcc456b8c2bbb07f9a85a147a5b30363477c76f925aa08|997|982
genesisrpc.log.1782316898|/var/log/synergy/rpc-gateway/genesisrpc.log.1782316898|10485828|5079dd5985d832e284b45928ce97719505aafc6e149227c0dad328c5ae4c8a1f|997|982
genesisrpc.log.1782329972|/var/log/synergy/rpc-gateway/genesisrpc.log.1782329972|10485833|d97789dfb3c8b9d50114f6f7f6cbb7d969a42acaa8b8f01c0c5910a1edd88fa4|997|982
genesisrpc.log.1782342581|/var/log/synergy/rpc-gateway/genesisrpc.log.1782342581|10486114|787c4ad55aee9b90837f2cac1b85315f2461ccf07fc67a1ac4a1acc7b379057d|997|982
genesisrpc.log.1782355153|/var/log/synergy/rpc-gateway/genesisrpc.log.1782355153|10485857|15e95cac0ad381dbfb4342afc94f6b3f86fbced3aa0c437ec4f90fe50334be67|997|982
genesisrpc.log.1782367716|/var/log/synergy/rpc-gateway/genesisrpc.log.1782367716|10485857|eaf532e63750096d3e2ac4cb163da7c02203235e10ec4ae9ce062e1e719836db|997|982
genesisrpc.log.1782380291|/var/log/synergy/rpc-gateway/genesisrpc.log.1782380291|10485777|df473e9af44a012bba2698fde53bfaad34c7c1b517892855520aacc7d7777639|997|982
genesisrpc.log.1782392847|/var/log/synergy/rpc-gateway/genesisrpc.log.1782392847|10485793|0449cb72668b05d4e723df7d1821a6fccc6d4a21adb467a9e304665130d88e14|997|982
genesisrpc.log.1782405408|/var/log/synergy/rpc-gateway/genesisrpc.log.1782405408|10485840|c5bba3e1bface73b2a3ce31daaea4dee84c7b190b932f6df3120b42f6581816e|997|982
genesisrpc.log.1782417923|/var/log/synergy/rpc-gateway/genesisrpc.log.1782417923|10485829|1e2cd570f4974124e83d093c7bb17ffb2982b94a60f1e413f4b571fc3ea379cf|997|982
genesisrpc.log.1782430403|/var/log/synergy/rpc-gateway/genesisrpc.log.1782430403|10485847|f543898c1e7452edd5a59ac66bee5df9d740888c4bd0951c9a5661833df15175|997|982
genesisrpc.log.1782442864|/var/log/synergy/rpc-gateway/genesisrpc.log.1782442864|10485788|50077abd718c64274ca21ba35151eefbae6d30b6ad91efcdd85be7901e92d357|997|982
genesisrpc.log.1782455347|/var/log/synergy/rpc-gateway/genesisrpc.log.1782455347|10485816|90f2f994c203258c15df9d436d5f06412f5bd0879e546e1d107f6950fd4dda60|997|982
genesisrpc.log.1782467834|/var/log/synergy/rpc-gateway/genesisrpc.log.1782467834|10485763|29c03295363856a23db693a07aff26e11c5e854410d37d99ef8c0862919a6ee0|997|982
genesisrpc.log.1782483827|/var/log/synergy/rpc-gateway/genesisrpc.log.1782483827|10485779|5fd1cf6952ae03eb7f1eef39b50fa719c4f4552068ef822d9314bd3edc2e3138|997|982
genesisrpc.log.1782496453|/var/log/synergy/rpc-gateway/genesisrpc.log.1782496453|10485818|dfb1fde87cda2c9bfacf262664f1f975261abaff707d936596318af69b96b0b8|997|982
genesisrpc.log.1782509528|/var/log/synergy/rpc-gateway/genesisrpc.log.1782509528|10485774|fe09c6bea7847fbdb626779628337d31cc67882e3067dbf4fd4cb095ce123e06|997|982
genesisrpc.log.1782524785|/var/log/synergy/rpc-gateway/genesisrpc.log.1782524785|10485852|8a37f3ee7f17a9178bb361ac2fa0b88b32b0fa1bf5399924551724504a14786a|997|982
genesisrpc.log.1782540752|/var/log/synergy/rpc-gateway/genesisrpc.log.1782540752|10485838|c3ab973a9e10e7296d1b035b1a20591632156021184b0a1816a64d15841aa57d|997|982
genesisrpc.log.1782556870|/var/log/synergy/rpc-gateway/genesisrpc.log.1782556870|10485833|ffad63718cdc2b383021831508457da415b8be72adc0fb9f94c9fff2a035f8f3|997|982
genesisrpc.log.1782573148|/var/log/synergy/rpc-gateway/genesisrpc.log.1782573148|10485848|18200e550f9080121015a64646d8a0ea3313d2107c1b1222b11bed3c485d4989|997|982
genesisrpc.log.1782588192|/var/log/synergy/rpc-gateway/genesisrpc.log.1782588192|10485837|b096361f602d53f112d0a2ac78515aa06d62f69963e3a789842de61f10f0808c|997|982
genesisrpc.log.1782601755|/var/log/synergy/rpc-gateway/genesisrpc.log.1782601755|10485849|d08a7ab368661ad79bba781f8c807c76bd5ab7e8ebd95493421c44ff3985f7a3|997|982
genesisrpc.log.1782615197|/var/log/synergy/rpc-gateway/genesisrpc.log.1782615197|10485823|46db0e2df867880d0c82181ff5d7e08e7c96b7adf3fa9ad6bc20d498e8877b35|997|982
genesisrpc.log.1782631436|/var/log/synergy/rpc-gateway/genesisrpc.log.1782631436|10485808|0e3f977e9117addf02b70456e618100b20879e1c1129f25a1701a87a1b8623af|997|982
genesisrpc.log.1782646171|/var/log/synergy/rpc-gateway/genesisrpc.log.1782646171|10485772|aff1aaf2533da5b55dfce39682f416d38a515a6979f50e26cb4c7939f263a072|997|982
genesisrpc.log.1782659165|/var/log/synergy/rpc-gateway/genesisrpc.log.1782659165|10485761|8fc0b073dec88a90816653abe935071bb380979b75ddd9a26ed7a591d5d4e052|997|982
genesisrpc.log.1782663471|/var/log/synergy/rpc-gateway/genesisrpc.log.1782663471|10486058|896bcd55612902d5aadcfa399f71bdf1ebee899f2a54578e5d1d1129885a35e7|997|982
genesisrpc.log.1782667578|/var/log/synergy/rpc-gateway/genesisrpc.log.1782667578|10485850|0ab0565cec2d2765843b67e643bd4c863fa5f702625a8308a46039f039bf5f46|997|982
genesisrpc.log.1782671681|/var/log/synergy/rpc-gateway/genesisrpc.log.1782671681|10485865|52e974d6bf05d1165b3d9640fdb22e0a2d5e778964bf22906f474f9d35822b0f|997|982
genesisrpc.log.1782675789|/var/log/synergy/rpc-gateway/genesisrpc.log.1782675789|10486013|e6b1120edf512ba07a3333a8d034b0f0958a7b20ebe6b9a80e4424e3363e6891|997|982
genesisrpc.log.1782682670|/var/log/synergy/rpc-gateway/genesisrpc.log.1782682670|10485762|aa20ea10d493e48a1365029510db08faf259404a7d161d8da76a72736997febb|997|982
genesisrpc.log.1782689986|/var/log/synergy/rpc-gateway/genesisrpc.log.1782689986|10485820|e127c89aea21ac136550fd63ccba13e4c8d2c1a6bff56e9510720580f8bdb101|997|982
genesisrpc.log.1782696361|/var/log/synergy/rpc-gateway/genesisrpc.log.1782696361|10485834|c4a596bf1996d4284c6e30cab7b05457475f288dfcdbdb2c203b3e545b56460f|997|982
genesisrpc.log.1782703673|/var/log/synergy/rpc-gateway/genesisrpc.log.1782703673|10485912|7541a387bb00a9072ef3274dca1a5dbca1ca2ebf29579410dfae2edb314cf3f8|997|982
genesisrpc.log.1782711242|/var/log/synergy/rpc-gateway/genesisrpc.log.1782711242|10485763|cbadbb090e78fdf683ec07f89dd23a7a73e84850147afa024db240fff7e04965|997|982
genesisrpc.log.1782719957|/var/log/synergy/rpc-gateway/genesisrpc.log.1782719957|10485838|43b06f32ccf0066dd6885cae4e5bfe7319cec3a157e7b9cc304a13607404c1bd|997|982
genesisrpc.log.1782729473|/var/log/synergy/rpc-gateway/genesisrpc.log.1782729473|10485806|0d44f9bc1b04e431231010c52d1f6b4349da5586811cf77a82bba0227c2d3a67|997|982
genesisrpc.log.1782740829|/var/log/synergy/rpc-gateway/genesisrpc.log.1782740829|10485790|0dab9f379885a0cf2fd5488515ee971557b6416d9163d46f9cce7238b270774f|997|982
genesisrpc.log.1782751744|/var/log/synergy/rpc-gateway/genesisrpc.log.1782751744|10485763|222350122fd74c3686b61eb9e38287114b387881f65776fa4bca10c59219937c|997|982
genesisrpc.log.1782773607|/var/log/synergy/rpc-gateway/genesisrpc.log.1782773607|10485795|b8263215cefec7841d0c210249593c9a18af974b9487898ddc04149181a99475|997|982
genesisrpc.log.1782789474|/var/log/synergy/rpc-gateway/genesisrpc.log.1782789474|10485839|00f6c1eb60ca1cb24a163b53c4cdd1abb7c5274acd0dd3c9f60669e029aa333a|997|982
genesisrpc.log.1782799183|/var/log/synergy/rpc-gateway/genesisrpc.log.1782799183|10485863|9284f3ab06e2945512222318a834f9e86bad1fd7303a6914d5e088776693559f|997|982
genesisrpc.log.1782809015|/var/log/synergy/rpc-gateway/genesisrpc.log.1782809015|10485865|8feba8cbef8e50e123397dc1c5c3f44b08f6f8c06f26cb14225b66089a97d596|997|982
genesisrpc.log.1782819080|/var/log/synergy/rpc-gateway/genesisrpc.log.1782819080|10485867|e1d93186ba11500d39e838d95f8369c155237fd399f50620531688d6d010de5b|997|982
genesisrpc.log.1782829240|/var/log/synergy/rpc-gateway/genesisrpc.log.1782829240|10485841|0d6f1d4a423e86aca7be80c36429eb63315ae4e120a6b81a2ced6549455a6dc8|997|982
genesisrpc.log.1782839568|/var/log/synergy/rpc-gateway/genesisrpc.log.1782839568|10485852|e577eee73fa6a8e441cc17bf2746a8d57bbbc85effbbeb65ddf9247aeb00d60a|997|982
genesisrpc.log.1782850059|/var/log/synergy/rpc-gateway/genesisrpc.log.1782850059|10485805|3ad89cb5681e7ed179a4153b350dc1f30d48e79d39bcc8952d02e4c9c8b0cdaa|997|982
genesisrpc.log.1782860660|/var/log/synergy/rpc-gateway/genesisrpc.log.1782860660|10485806|491786b81bb067bcedc7f61797be7def2704d24d2ef8586201ef7531fdcaf455|997|982
genesisrpc.log.1782871348|/var/log/synergy/rpc-gateway/genesisrpc.log.1782871348|10485779|87cc42336271d2ee21f7edb7fa0327e736494858ff6662a77dbb405bb0f01472|997|982
genesisrpc.log.1782883015|/var/log/synergy/rpc-gateway/genesisrpc.log.1782883015|10485816|0a9f6a7262f6b3286fad8c033c497acfaecd5d07507344920f2000853b48664f|997|982
genesisrpc.log.1782897373|/var/log/synergy/rpc-gateway/genesisrpc.log.1782897373|10485842|e62a7ccd5182590b9be4bdd49c1bfd2ff5e7062864abb423581f47d229ee08a9|997|982
genesisrpc.log.1782904225|/var/log/synergy/rpc-gateway/genesisrpc.log.1782904225|10485837|b840bfa72f0aed3d7f71aea12a913e0d01fc9aa62d4a664f368996fef96eb604|997|982
genesisrpc.log.1782910955|/var/log/synergy/rpc-gateway/genesisrpc.log.1782910955|10485789|f59bb3a037d66a1ff97d587b88b79b4f10ff04de589ac4961243854e0473b45a|997|982
genesisrpc.log.1782917671|/var/log/synergy/rpc-gateway/genesisrpc.log.1782917671|10485846|375f3b1064231ed149d2449fada4cb8fdafd17577a4bd3243b5009590d5348b7|997|982
genesisrpc.log.1782924374|/var/log/synergy/rpc-gateway/genesisrpc.log.1782924374|10485857|599953639a3960520070514eb65bc975f8995150c41fc1a87e6681837c631882|997|982
genesisrpc.log.1782931062|/var/log/synergy/rpc-gateway/genesisrpc.log.1782931062|10485764|fd6c66f17b41ed19b9f135d0d43bf36d84bca969f4c3ccadff235f3cd0905e20|997|982
genesisrpc.log.1782937742|/var/log/synergy/rpc-gateway/genesisrpc.log.1782937742|10485853|ba6af1ffcbf6fd4a7cd836b39f4821f529a180fe5322489508dbeb0076829399|997|982
genesisrpc.log.1782949199|/var/log/synergy/rpc-gateway/genesisrpc.log.1782949199|10485787|74cae1097f02c0ad69534e685d99a8b2fe34f22da5d09fd65ef5c48f9ac6ad5c|997|982
genesisrpc.log.1782960950|/var/log/synergy/rpc-gateway/genesisrpc.log.1782960950|10485770|9db4f66f52d1ae20350bac1861d073d4368120792e1fa8cd53179272efc98603|997|982
genesisrpc.log.1782972935|/var/log/synergy/rpc-gateway/genesisrpc.log.1782972935|10485822|a8bb251dfdae32493b73f75e6d41594213d510040d5f0d1020116fd5e507c1ae|997|982
genesisrpc.log.1782984771|/var/log/synergy/rpc-gateway/genesisrpc.log.1782984771|10485775|e35c3bc19e7a70d852914e89e20f37e867d2dd361924d4792414c8ac50cfb439|997|982
genesisrpc.log.1782996538|/var/log/synergy/rpc-gateway/genesisrpc.log.1782996538|10485830|20017544fff1034dc67cc3072d9729e8a110e1f7b4e22604a2ec3a9074fc7798|997|982
genesisrpc.log.1783008328|/var/log/synergy/rpc-gateway/genesisrpc.log.1783008328|10485786|28f1eca3136d191e3909ae454ea524ebe2831c2083f9731829d2cdbc371092b0|997|982
genesisrpc.log.1783020141|/var/log/synergy/rpc-gateway/genesisrpc.log.1783020141|10485826|ea75730a5098ec3d93e27f48c933f0a43e98763a9232b6fbe81e63d35e1d64dc|997|982
genesisrpc.log.1783031880|/var/log/synergy/rpc-gateway/genesisrpc.log.1783031880|10485772|387490deaa8ceb1c228761df12a06ed5f13b42d2c184649c1db1c55690da3253|997|982
genesisrpc.log.1783042965|/var/log/synergy/rpc-gateway/genesisrpc.log.1783042965|10485761|3ea28e1840da8d777a92656aa44e656c3b710b429561e6e59eac0cb39e2e0d62|997|982
genesisrpc.log.1783053619|/var/log/synergy/rpc-gateway/genesisrpc.log.1783053619|10485799|892e507cc50fa95c7e4f897209cd0666bfa4461e53ab78930bfe9c5cd14aec1c|997|982
genesisrpc.log.1783061795|/var/log/synergy/rpc-gateway/genesisrpc.log.1783061795|10486091|c0d08d7ee46ae4345e3a75091a9d5c638400756f53947638cdf0eb88d8fa5bce|997|982
genesisrpc.log.1783070580|/var/log/synergy/rpc-gateway/genesisrpc.log.1783070580|10485779|6f5a8269df8207885e2a55472bd29f522de149465f57e712d47b32eb68d42895|997|982
genesisrpc.log.1783085000|/var/log/synergy/rpc-gateway/genesisrpc.log.1783085000|10485909|ec39c701a16a067545b11d31402546ce8f7e51277d2574f1d060ca837786d8c9|997|982
genesisrpc.log.1783088436|/var/log/synergy/rpc-gateway/genesisrpc.log.1783088436|10485878|f388829c4835ae33ebb811874c32051b333385737e7fa6c118f148c9fece5ad0|997|982
genesisrpc.log.1783098367|/var/log/synergy/rpc-gateway/genesisrpc.log.1783098367|10485911|bcbcd59d8c0c77fa28e5967d74dc645889534c400980100a8d18ae3c42e7de53|997|982
genesisrpc.log.1783108315|/var/log/synergy/rpc-gateway/genesisrpc.log.1783108315|10485848|d09ddc9d02c61f0fd17a8dcb4f347437ca17fbcaa9385306823ffda7301900df|997|982
genesisrpc.log.1783119837|/var/log/synergy/rpc-gateway/genesisrpc.log.1783119837|10485852|f61f13e0a858b266f28e20cba68ab62307c5051aa812b79cb7f71a0b0900f024|997|982
genesisrpc.log.1783131741|/var/log/synergy/rpc-gateway/genesisrpc.log.1783131741|10485816|521daaf965038cbda6ac8883a54cb443aa6041afa311442ac5c1c3adde60130e|997|982
genesisrpc.log.1783151185|/var/log/synergy/rpc-gateway/genesisrpc.log.1783151185|10485868|3d96599df01d9f2a62e43fdef0e951f2c737648be87d2ac719063d497f5c9a6b|997|982
genesisrpc.log.1783163347|/var/log/synergy/rpc-gateway/genesisrpc.log.1783163347|10485798|9a9ac55b029f1f69d07b014eab47b35a81691029cf19a24b947496d51758c763|997|982
genesisrpc.log.1783186003|/var/log/synergy/rpc-gateway/genesisrpc.log.1783186003|10485881|45c885420059a4762a90c462e5a0eefa574a621c159f5a4068e3cc33edccabd7|997|982
genesisrpc.log.1783219816|/var/log/synergy/rpc-gateway/genesisrpc.log.1783219816|10485821|1c7add63315c6647017a3b2eac40710944da5f3d7b32b76a697500cff1e0db00|997|982
genesisrpc.log.1783259547|/var/log/synergy/rpc-gateway/genesisrpc.log.1783259547|10485781|d444d26a0bd57f925f6ef5992c981d6aa4a4d7cb6536167121abaecc479e2f68|997|982
genesisrpc.log.1783279551|/var/log/synergy/rpc-gateway/genesisrpc.log.1783279551|10485848|d75162175168183022d56d8dc390f9977c47569db761130101a64624c716885a|997|982
genesisrpc.log.1783343048|/var/log/synergy/rpc-gateway/genesisrpc.log.1783343048|10485852|de8cba3743ee733d0b6d56db994cabbd4853079312e631abc2d3bfa28d6aee45|997|982
genesisrpc.log.1783472644|/var/log/synergy/rpc-gateway/genesisrpc.log.1783472644|10485791|8ae44f6799070297dc6b3cc1b821c8398406712910727602194f850263a11c8f|997|982
genesisrpc.log.1783623845|/var/log/synergy/rpc-gateway/genesisrpc.log.1783623845|10485936|30092676be0b139d9492ccdc774397f9fd09d6484e19554e71e7d874113aaa06|997|982
genesisrpc.log.1783804070|/var/log/synergy/rpc-gateway/genesisrpc.log.1783804070|10485920|a56ae7db48bd44a032248f69a02e03e5d1c2bfe7caf7d2088171d0f92d738406|997|982
snapshot-000675736.support-rpc.tar.zst|/opt/synergy/distribution/snapshot-000675736.support-rpc.tar.zst|48191631|b2a4e8ef1a558e944be7f2a5d3d4cfa78362e030d2b378a1019ca94f2f348b37|0|0
support-snapshot-verification.json|/opt/synergy/distribution/receiver-verify-snapshot.json|1129|881eae66e73ba09456bf4c60f12424163e41dfb5ccbe4a8e6b7b0e3a73e54285|0|0
"""
RECORDS_PARENTS = {
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc14/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc14/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc16/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc16/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc17/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc17/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc18/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc18/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc19/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc19/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc20/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc20/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc21/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc21/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc22/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc22/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc23/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc23/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc24/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc24/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc25/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc25/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc27/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc27/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc28/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc28/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc29/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc29/systemd": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/bin": (501, 50),
    "/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/systemd": (501, 50),
    "/var/log/synergy": (999, 986),
    "/var/log/synergy/rpc-gateway": (997, 982),
}
SOURCE_OWNERS = {}
END = b"synergy-chain1266-relocation-complete-v1\n"
CHUNK = 256 * 1024


def require(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def review():
    assets = [{"file": name, "bytes": size, "sha256": sha}
              for name, (_, size, sha) in sorted(ASSETS.items())]
    schema = "nodenetwork-chain1266-records-relocation-v1" if IMPORT == RECORDS_IMPORT else "nodenetwork-chain1266-relocation-v1"
    value = {"schema": schema,
             "source": SOURCE, "destination": DESTINATION, "context": CONTEXT,
             "assets": assets, "total_bytes": sum(entry["bytes"] for entry in assets)}
    return {**value, "review_sha256": hashlib.sha256(encoded(value)).hexdigest()}


def directories(path):
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if IMPORT == RECORDS_IMPORT and path == Path("/var/log/synergy/rpc-gateway") and ancestor == Path("/var/log"):
            require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 101, 0o775),
                    "Verified Ubuntu log directory ownership differs")
            continue
        owner = RECORDS_PARENTS.get(str(ancestor)) if IMPORT == RECORDS_IMPORT else None
        owner_ok = (info.st_uid, info.st_gid) == owner if owner else info.st_uid == os.geteuid()
        require(stat.S_ISDIR(info.st_mode) and owner_ok
                and not info.st_mode & 0o022, "Untrusted legacy asset directory")


def read_file(path, length, expected, output=None):
    directories(path.parent)
    with contextlib.ExitStack() as stack:
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        stack.callback(os.close, parent)
        for name in path.parent.parts[1:]:
            parent = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            stack.callback(os.close, parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        owner = SOURCE_OWNERS.get(path)
        owner_ok = (before.st_uid, before.st_gid) == owner if owner else before.st_uid == os.geteuid()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and owner_ok and not before.st_mode & 0o022
                and before.st_size == length, "Legacy asset metadata differs")
        sha, remaining = hashlib.sha256(), length
        while remaining:
            block = source.read(min(remaining, CHUNK))
            require(block, "Legacy asset ended early")
            remaining -= len(block)
            sha.update(block)
            if output is not None:
                output.write(block)
        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(not source.read(1) and sha.hexdigest() == expected
                and stamp(before) == stamp(os.fstat(source.fileno())) == stamp(path.lstat()),
                "Legacy asset changed or differs from its verified digest")


def send(output):
    for _, (path, length, digest) in sorted(ASSETS.items()):
        read_file(path, length, digest, output)
    output.write(END)
    output.flush()


def verify_destination(path):
    require(not path.is_symlink() and path.is_dir() and path.stat().st_mode & 0o777 == 0o700,
            "Relocation directory ownership differs")
    require({p.name for p in path.iterdir()} == set(ASSETS) | {"relocation.json"},
            "Relocation inventory differs")
    for name, (_, length, digest) in sorted(ASSETS.items()):
        require((path / name).lstat().st_mode & 0o777 == 0o600, "Relocated asset mode differs")
        read_file(path / name, length, digest)
    receipt = encoded(review())
    read_file(path / "relocation.json", len(receipt), hashlib.sha256(receipt).hexdigest())


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def receive(stream):
    directories(DESTINATION_ROOT)
    storage = os.statvfs(DESTINATION_ROOT)
    require(storage.f_bavail * storage.f_frsize > review()["total_bytes"],
            "Insufficient destination space for verified relocation")
    destination = DESTINATION_ROOT / IMPORT
    root = os.open(DESTINATION_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    with contextlib.ExitStack() as stack:
        stack.callback(os.close, root)
        fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not destination.exists() and not destination.is_symlink(),
                "Destination already exists. Verify original relocation without replay.")
        staging = Path(tempfile.mkdtemp(prefix=".nodenetwork-relocation-", dir=DESTINATION_ROOT))
        stack.callback(lambda: shutil.rmtree(staging) if staging.exists() else None)
        for name, (_, length, digest) in sorted(ASSETS.items()):
            sha, remaining = hashlib.sha256(), length
            file = staging / name
            fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                while remaining:
                    block = stream.read(min(remaining, CHUNK))
                    require(block, "Uncertain or incomplete source stream")
                    remaining -= len(block)
                    sha.update(block)
                    output.write(block)
                require(sha.hexdigest() == digest, "Relocation asset digest differs")
                output.flush()
                os.fsync(output.fileno())
        require(stream.read(len(END)) == END and not stream.read(1), "Source did not verify complete relocation")
        receipt = staging / "relocation.json"
        with os.fdopen(os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            output.write(encoded(review()))
            output.flush()
            os.fsync(output.fileno())
        verify_destination(staging)
        fsync_directory(staging)
        require(not destination.exists() and not destination.is_symlink(), "Destination appeared during relocation")
        os.rename(staging, destination)
        os.fsync(root)
        verify_destination(destination)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def destination_ready():
    def call(port, method, params):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(f"http://127.0.0.1:{port}/", method="POST",
            data=encoded({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
            headers={"Content-Type": "application/json"})
        with opener.open(request, timeout=5) as response:
            raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "Destination response exceeds bound")
        value = json.loads(raw)
        require(value.get("chain_context") == CONTEXT and value.get("id") == 1
                and "error" not in value, "Destination RPC chain differs")
        return value["result"]
    pid = subprocess.run(["/usr/bin/systemctl", "show", "synergy-chain1266-rpc-tunnel.service",
        "-p", "MainPID", "--value"], check=True, capture_output=True, timeout=5).stdout.strip()
    require(pid.isdigit() and int(pid) > 0, "Destination tunnel not running")
    proc = Path("/proc") / pid.decode("ascii")
    args = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    expected = {b"127.0.0.1:5640:127.0.0.1:5640", b"127.0.0.1:5660:127.0.0.1:5660"}
    forwards = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == b"-L"]
    require(os.readlink(proc / "exe") == "/usr/bin/ssh"
            and args[-1] == b"root@62.146.182.207"
            and len(forwards) == 2 and set(forwards) == expected,
            "Destination lacks a direct tunnel to the existing authority")
    for port in (5640, 5656):
        height = call(port, "synergy_blockNumber", [])
        block = call(port, "synergy_getBlockByNumber", [0])
        height = int(height, 16) if isinstance(height, str) and height.startswith("0x") else height
        require(isinstance(block, dict) and block.get("hash") == GENESIS and type(height) is int and height > 0,
                "Destination genesis or finalized height unavailable")


def select_records():
    global ASSETS, SOURCE_OWNERS, IMPORT
    rows = [line.split("|") for line in RECORDS.strip().splitlines()]
    ASSETS = {name: (Path(path), int(size), sha) for name, path, size, sha, _, _ in rows}
    SOURCE_OWNERS = {Path(path): (int(uid), int(gid)) for _, path, _, _, uid, gid in rows}
    require(len(ASSETS) == len(rows) and 0 < len(rows) <= 300, "Records manifest differs")
    IMPORT = RECORDS_IMPORT


LEGACY_ROOT = Path("/opt/synergy")
LEGACY_ROOT_ENTRIES = {
    "apply-verified-support-snapshot.sh", "backups", "bin", "chain1266", "distribution",
    "incoming", "manual-snapshot-receiver.sh", "preflight", "recovery-staging",
    "support-node-reconcile-config-from-snapshot.py", "support-node-snapshot-reseed-remote.sh",
    "testnet-v3", "verify-workspace-rpc-1080418",
}
UNIT_DIR = Path("/etc/systemd/system")
ACTIVE_UNITS = ("synergy-chain1266-role@rpc-gateway.service", "synergy-chain1266-rpc-tunnel.service")
OLD_UNITS = {
    ACTIVE_UNITS[0]: UNIT_DIR / "synergy-chain1266-role@.service",
    ACTIVE_UNITS[1]: UNIT_DIR / ACTIVE_UNITS[1],
    "synergy-testnet-v3-rpc-gateway.service": UNIT_DIR / "synergy-testnet-v3-rpc-gateway.service",
    "synergy-rpc-gateway.service": None,
    "synergy-rpc-router.service": None,
}
SITE = Path("/etc/nginx/sites-available/testnet-core-rpc.synergy-network.io")
ENABLED_SITE = Path("/etc/nginx/sites-enabled") / SITE.name
LEGACY_PATHS = (
    LEGACY_ROOT, Path("/etc/synergy/chain1266"), Path("/etc/synergy/testnet-v3"),
    *(Path("/etc/synergy") / name for name in (
        "rpc-router.env", "rpc-router.env.pre-5640-router-fix-20260717T214418Z",
        "rpc-router.env.pre-local-write-20260715T005304Z",
        "rpc-router.env.pre-ncp-onboarding-router-fix-20260718T075918Z",
        "rpc-router.env.pre-recovery-5640-20260721T143723Z",
        "rpc-router.env.pre-valid-restore-20260718T080109Z",
    )),
    Path("/var/lib/synergy/testnet-v3"), Path("/var/log/synergy/rpc-gateway"),
    *(Path("/var/log/synergy") / name for name in (
        "chain1266-gas-rc31-build.log", "chain1266-gas-rc31-role-build.log", "chain1266-gas-rc31-rpc-build.log",
    )),
    *(Path("/var/backups") / name for name in (
        "synergy", "synergy-logrotate", "synergy-public-p2p", "synergy-rpc-router", "synergy-testnet-v3",
    )),
    Path("/var/lib/synergy-testnet-v3-rpc-gateway"),
    Path("/var/lib/private/synergy-testnet-v3-rpc-gateway"),
    *(p for p in OLD_UNITS.values() if p is not None),
    *(UNIT_DIR / name for name in (
        "synergy-rpc-gateway.service.d", "synergy-rpc-router.service.d",
        "synergy-rpc-router.service.pre-durable-20260711T095110Z",
    )),
    *(UNIT_DIR / "multi-user.target.wants" / name for name in ACTIVE_UNITS),
    SITE, ENABLED_SITE, SITE.with_name(SITE.name + ".pre-val6-upstream-20260619T233800Z"),
    SITE.with_name("testnet-v3-rpc.conf.staged"),
    Path("/root/rpc-audit-20260711T194954Z"),
    Path("/root/.ssh/id_synergy_rpc_val2_tunnel"), Path("/root/.ssh/id_synergy_rpc_val2_tunnel.pub"),
)
RETIREMENT_RECEIPTS = (
    "fd7eac8b0d44082fa1ebb964e53730a49109a12023384f194ecf70ab0533af5c",
    "1be1629dad84d0ad0a7016345d9975e3d0bc73cbd8196a0a280336d9bbaaebae",
)


def existing(path):
    return path.exists() or path.is_symlink()


def system_command(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=25, text=True).stdout


def retired_unit_state():
    for unit, path in OLD_UNITS.items():
        values = dict(line.split("=", 1) for line in system_command(
            "/usr/bin/systemctl", "show", unit, "-p", "FragmentPath", "-p", "DropInPaths",
            "-p", "ActiveState", "-p", "MainPID", "-p", "RequiredBy", "-p", "BoundBy", "-p", "PartOf",
        ).splitlines())
        require(not values["RequiredBy"] and not values["BoundBy"] and not values["PartOf"],
                "Another host service depends on a legacy unit")
        require(values["FragmentPath"] in ("", str(path)) and not values["DropInPaths"],
                "Legacy service registration changed")
        require(values["ActiveState"] in ("active", "inactive")
                and (unit in ACTIVE_UNITS or values["ActiveState"] == "inactive"),
                "Legacy unit is transitioning or an unreviewed service has started")
        yield unit, values["ActiveState"] == "active", int(values["MainPID"])


def guard_mounts(paths):
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        mounted = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), line.split()[4]))
        require(not any(mounted == path or path in mounted.parents for path in paths),
                "A legacy removal path contains a mount")


def trusted_retirement_ancestor(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        return False
    exceptional = {Path("/var/log"): (0, 101, 0o775), Path("/var/log/synergy"): (999, 986, 0o755)}
    if path in exceptional:
        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == exceptional[path]
    return info.st_uid == 0 and not info.st_mode & 0o022


def retirement_inventory():
    require(shutil.rmtree.avoids_symlink_attacks, "Symlink-safe removal is unavailable")
    require(not existing(LEGACY_ROOT) or (not LEGACY_ROOT.is_symlink()
            and {p.name for p in LEGACY_ROOT.iterdir()} <= LEGACY_ROOT_ENTRIES),
            "Unattributed legacy root entry")
    paths = [path for path in LEGACY_PATHS if existing(path)]
    guard_mounts(paths)
    inventory = {}
    for path in paths:
        require(all(trusted_retirement_ancestor(p) for p in path.parents), "Untrusted legacy path ancestor")
        if path.is_symlink():
            links = {ENABLED_SITE: str(SITE),
                     Path("/var/lib/synergy-testnet-v3-rpc-gateway"):
                        "private/synergy-testnet-v3-rpc-gateway",
                     **{UNIT_DIR / "multi-user.target.wants" / unit: str(OLD_UNITS[unit])
                        for unit in ACTIVE_UNITS}}
            require(os.readlink(path) == links.get(path), "Unexpected external legacy symlink")
        fingerprint = hashlib.sha256()
        count = 0
        total = 0

        def add(item):
            nonlocal count, total
            info = item.lstat()
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
                    or stat.S_ISLNK(info.st_mode), "Unexpected special file in legacy scope")
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
            count += 1
            fingerprint.update(encoded([str(item.relative_to(path)), info.st_dev, info.st_ino,
                info.st_mode, info.st_uid, info.st_gid, info.st_mtime_ns, info.st_size,
                os.readlink(item) if stat.S_ISLNK(info.st_mode) else None]) + b"\n")

        add(path)
        if path.is_dir() and not path.is_symlink():
            for root, directories, files in os.walk(path, followlinks=False):
                directories.sort()
                for entry in sorted(directories + files):
                    add(Path(root) / entry)
        inventory[str(path)] = {"entries": count, "bytes": total, "sha256": fingerprint.hexdigest()}
    return inventory


def source_retirement_plan():
    units = list(retired_unit_state())
    for name, active, pid in units:
        if not active:
            require(not pid, "Legacy service PID differs")
            continue
        proc = Path("/proc") / str(pid)
        image = os.readlink(proc / "exe")
        args = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        if name == ACTIVE_UNITS[0]:
            require(image == str(LEGACY_ROOT / "chain1266/releases/chain1266-incarnation-4-rc30/bin/synergy-rpc-gateway-node"),
                    "Active legacy gateway image differs")
        else:
            require(image == "/usr/bin/ssh" and args[-1] == b"root@62.146.182.207"
                    and b"/root/.ssh/id_synergy_rpc_val2_tunnel" in args,
                    "Legacy tunnel process differs")
    for port in (5640, 5660, 6030):
        established = system_command("/usr/bin/ss", "-Htn", "state", "established", f"sport = :{port}")
        require(not established.strip(), "A client still uses the legacy endpoint")
    if existing(ENABLED_SITE):
        require(ENABLED_SITE.is_symlink() and os.readlink(ENABLED_SITE) == str(SITE),
                "Legacy reverse proxy route differs")
        require(not SITE.is_symlink() and SITE.is_file() and SITE.stat().st_size <= 16384,
                "Legacy reverse proxy file differs")
        site = b"\n".join(line.split(b"#", 1)[0] for line in SITE.read_bytes().splitlines())
        require(set(re.findall(rb"proxy_pass\s+([^;\s]+)\s*;", site)) ==
                {b"http://127.0.0.1:5640", b"http://127.0.0.1:5660",
                 b"http://127.0.0.1:6030/metrics", b"http://127.0.0.1:9100/metrics"},
                "A reverse proxy route cannot be attributed to Chain 1266")
    inventory = retirement_inventory()
    scope = {"machine_sha256": SOURCE, "chain": CONTEXT, "destination_receipts": list(RETIREMENT_RECEIPTS),
             "paths": inventory, "units": units}
    return {**scope, "review_sha256": hashlib.sha256(encoded(scope)).hexdigest()}


def guard_unused_paths():
    paths = tuple(str(path) for path in LEGACY_PATHS)
    children = tuple(path + "/" for path in paths)
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            links = [proc / "exe", proc / "cwd", *(proc / "fd").iterdir()]
        except (FileNotFoundError, ProcessLookupError):
            continue
        for link in links:
            try:
                name = os.readlink(link).removesuffix(" (deleted)")
            except (FileNotFoundError, ProcessLookupError):
                continue
            require(name not in paths and not name.startswith(children),
                    "Another process is using the legacy installation")


def retire_source(review_pin):
    reviewed = source_retirement_plan()
    require(reviewed["review_sha256"] == review_pin and reviewed["paths"],
            "Review changed or contains no remaining installation")
    if existing(ENABLED_SITE):
        ENABLED_SITE.unlink()
        try:
            system_command("/usr/sbin/nginx", "-t")
            system_command("/usr/bin/systemctl", "reload", "nginx.service")
        except subprocess.SubprocessError:
            ENABLED_SITE.symlink_to(SITE)
            raise
    for name, active, _ in reviewed["units"]:
        if name in ACTIVE_UNITS and (active or existing(OLD_UNITS[name])):
            system_command("/usr/bin/systemctl", "disable", "--now", name)
    require(not any(active or pid for _, active, pid in retired_unit_state()),
            "Legacy process remains active")
    guard_mounts(LEGACY_PATHS)
    current = retirement_inventory()
    require(all(meta == reviewed["paths"].get(path) for path, meta in current.items()),
            "A legacy removal target changed after service stop")
    guard_mounts(tuple(map(Path, current)))
    guard_unused_paths()
    for path in map(Path, current):
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            shutil.rmtree(path)
    for directory in map(Path, ("/etc/synergy", "/var/lib/synergy", "/var/log/synergy")):
        if directory.is_dir() and not directory.is_symlink() and not any(directory.iterdir()):
            directory.rmdir()
    system_command("/usr/bin/systemctl", "daemon-reload")
    require(not retirement_inventory() and not any(active or pid for _, active, pid in retired_unit_state()),
            "Legacy retirement has unprocessed resources")
    return reviewed


def main():
    mode = sys.argv[1]
    if mode in ("source-retire-plan", "source-retire"):
        machine = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
        require(len(sys.argv) == 2 and os.geteuid() == 0 and machine == SOURCE, "Retirement source differs")
        if mode == "source-retire":
            pin = sys.stdin.buffer.readline(66)
            require(re.fullmatch(rb"[0-9a-f]{64}\n", pin) and not sys.stdin.buffer.read(1),
                    "Exact approved retirement commitment required")
            plan = retire_source(pin.decode().strip())
        else:
            plan = source_retirement_plan()
        print(encoded({"review": plan, "removed": mode == "source-retire" or not plan["paths"]}).decode())
        return
    if mode.endswith("-records"):
        select_records()
        mode = mode[:-8]
    require(len(sys.argv) == 2 and mode in
            ("source-plan", "destination-plan", "export", "receive", "status"), "Unknown relocation operation")
    machine = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    is_source = mode in ("source-plan", "export")
    require(os.geteuid() == 0 and machine == (SOURCE if is_source else DESTINATION),
            "Relocation machine identity differs")
    if not is_source:
        destination_ready()
        directories(DESTINATION_ROOT)
    destination = DESTINATION_ROOT / IMPORT
    exists = destination.exists() or destination.is_symlink()
    if mode in ("export", "receive"):
        require(sys.stdin.buffer.readline(256) == (review()["review_sha256"] + "\n").encode("ascii"),
                "Exact reviewed relocation commitment required")
    if mode == "export":
        require(not sys.stdin.buffer.read(1), "Unexpected source input")
        send(sys.stdout.buffer)
        return
    if mode == "source-plan":
        for path, length, digest in ASSETS.values():
            read_file(path, length, digest)
    if mode == "receive":
        receive(sys.stdin.buffer)
        exists = True
    if not is_source and exists:
        verify_destination(destination)
    side = "source" if is_source else "destination"
    print(encoded({"side": side, "review": review(), "relocated": not is_source and exists}).decode())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, IndexError, KeyError, subprocess.SubprocessError):
        sys.exit("Chain 1266 relocation refused or uncertain. Inspect the verified destination receipt before a retry.")

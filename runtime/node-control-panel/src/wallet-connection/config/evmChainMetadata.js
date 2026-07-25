import { chainLogo } from "../lib/chainLogo.js";

const EVM_CHAIN_LOGO_SLUGS = {
  polygonZkEvm: "polygon-zkevm",
  worldchain: "worldchain",
  xLayer: "xlayer",
};

export const EVM_CHAIN_DEFINITIONS = [
  {
    "id": "ethereum",
    "chainId": 1,
    "name": "Ethereum Mainnet",
    "short": "ETH",
    "accent": "#627eea",
    "logoURI": "https://assets.coingecko.com/coins/images/279/small/ethereum.png",
    "publicRpcUrl": "https://eth.merkle.io",
    "explorerTxBase": "https://etherscan.io/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "arbitrum",
    "chainId": 42161,
    "name": "Arbitrum One",
    "short": "ARB",
    "accent": "#28a0f0",
    "logoURI": "https://assets.coingecko.com/coins/images/16547/small/arb.jpg",
    "publicRpcUrl": "https://arb1.arbitrum.io/rpc",
    "explorerTxBase": "https://arbiscan.io/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "base",
    "chainId": 8453,
    "name": "Base",
    "short": "BAS",
    "accent": "#0052ff",
    "logoURI": "https://assets.coingecko.com/asset_platforms/images/131/small/base.jpeg",
    "publicRpcUrl": "https://mainnet.base.org",
    "explorerTxBase": "https://basescan.org/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "optimism",
    "chainId": 10,
    "name": "Optimism",
    "short": "OP",
    "accent": "#ff0420",
    "logoURI": "https://assets.coingecko.com/coins/images/25244/small/Optimism.png",
    "publicRpcUrl": "https://mainnet.optimism.io",
    "explorerTxBase": "https://optimistic.etherscan.io/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "polygon",
    "chainId": 137,
    "name": "Polygon PoS",
    "short": "POL",
    "accent": "#8247e5",
    "logoURI": "https://assets.coingecko.com/coins/images/4713/small/polygon.png",
    "publicRpcUrl": "https://polygon.drpc.org",
    "explorerTxBase": "https://polygonscan.com/tx/",
    "nativeCurrency": {
      "name": "POL",
      "symbol": "POL",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "avalanche",
    "chainId": 43114,
    "name": "Avalanche C-Chain",
    "short": "AVA",
    "accent": "#e84142",
    "logoURI": "https://assets.coingecko.com/coins/images/12559/small/Avalanche_Circle_RedWhite_Trans.png",
    "publicRpcUrl": "https://api.avax.network/ext/bc/C/rpc",
    "explorerTxBase": "https://snowtrace.io/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Avalanche",
      "symbol": "AVAX"
    },
    "swapSupported": true
  },
  {
    "id": "bsc",
    "chainId": 56,
    "name": "BNB Smart Chain",
    "short": "BSC",
    "accent": "#f0b90b",
    "logoURI": "https://coin-images.coingecko.com/coins/images/825/small/bnb-icon2_2x.png?1696501970",
    "publicRpcUrl": "https://56.rpc.thirdweb.com",
    "explorerTxBase": "https://bscscan.com/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "BNB",
      "symbol": "BNB"
    },
    "swapSupported": true
  },
  {
    "id": "gnosis",
    "chainId": 100,
    "name": "Gnosis Chain",
    "short": "GNO",
    "accent": "#48a9a6",
    "publicRpcUrl": "https://rpc.gnosischain.com",
    "explorerTxBase": "https://gnosisscan.io/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "xDAI",
      "symbol": "XDAI"
    },
    "swapSupported": true
  },
  {
    "id": "cronos",
    "chainId": 25,
    "name": "Cronos Mainnet",
    "short": "CRO",
    "accent": "#002d74",
    "publicRpcUrl": "https://evm.cronos.org",
    "explorerTxBase": "https://explorer.cronos.org/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Cronos",
      "symbol": "CRO"
    },
    "swapSupported": true
  },
  {
    "id": "moonbeam",
    "chainId": 1284,
    "name": "Moonbeam",
    "short": "GLMR",
    "accent": "#6b7cff",
    "publicRpcUrl": "https://rpc.api.moonbeam.network",
    "explorerTxBase": "https://moonscan.io/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Moonbeam",
      "symbol": "GLMR"
    },
    "swapSupported": false
  },
  {
    "id": "celo",
    "chainId": 42220,
    "name": "Celo",
    "short": "CELO",
    "accent": "#35d07f",
    "publicRpcUrl": "https://forno.celo.org",
    "explorerTxBase": "https://celoscan.io/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "CELO",
      "symbol": "CELO"
    },
    "swapSupported": false
  },
  {
    "id": "kava",
    "chainId": 2222,
    "name": "Kava EVM",
    "short": "KAVA",
    "accent": "#ff6b35",
    "publicRpcUrl": "https://evm.kava.io",
    "explorerTxBase": "https://kavascan.com/tx/",
    "nativeCurrency": {
      "name": "Kava",
      "symbol": "KAVA",
      "decimals": 18
    },
    "swapSupported": false
  },
  {
    "id": "metis",
    "chainId": 1088,
    "name": "Metis",
    "short": "MET",
    "accent": "#00a3ff",
    "publicRpcUrl": "https://metis.rpc.hypersync.xyz",
    "explorerTxBase": "https://explorer.metis.io/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Metis",
      "symbol": "METIS"
    },
    "swapSupported": false
  },
  {
    "id": "aurora",
    "chainId": 1313161554,
    "name": "Aurora",
    "short": "AUR",
    "accent": "#7c3aed",
    "publicRpcUrl": "https://mainnet.aurora.dev",
    "explorerTxBase": "https://aurorascan.dev/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Ether",
      "symbol": "ETH"
    },
    "swapSupported": false
  },
  {
    "id": "rootstock",
    "chainId": 30,
    "name": "Rootstock Mainnet",
    "short": "RSK",
    "accent": "#f7931a",
    "publicRpcUrl": "https://public-node.rsk.co",
    "explorerTxBase": "https://explorer.rsk.co/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Rootstock Bitcoin",
      "symbol": "RBTC"
    },
    "swapSupported": false
  },
  {
    "id": "opbnb",
    "chainId": 204,
    "name": "opBNB",
    "short": "OPB",
    "accent": "#f0b90b",
    "publicRpcUrl": "https://opbnb-mainnet-rpc.bnbchain.org",
    "explorerTxBase": "https://opbnb.bscscan.com/tx/",
    "nativeCurrency": {
      "name": "BNB",
      "symbol": "BNB",
      "decimals": 18
    },
    "swapSupported": false
  },
  {
    "id": "sonic",
    "chainId": 146,
    "name": "Sonic",
    "short": "SON",
    "accent": "#0ea5e9",
    "publicRpcUrl": "https://rpc.soniclabs.com",
    "explorerTxBase": "https://sonicscan.org/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Sonic",
      "symbol": "S"
    },
    "swapSupported": true
  },
  {
    "id": "linea",
    "chainId": 59144,
    "name": "Linea Mainnet",
    "short": "LIN",
    "accent": "#1d4ed8",
    "publicRpcUrl": "https://rpc.linea.build",
    "explorerTxBase": "https://lineascan.build/tx/",
    "nativeCurrency": {
      "name": "Linea Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "zksync",
    "chainId": 324,
    "name": "ZKsync Era",
    "short": "ZK",
    "accent": "#8a5cff",
    "publicRpcUrl": "https://mainnet.era.zksync.io",
    "explorerTxBase": "https://explorer.zksync.io/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Ether",
      "symbol": "ETH"
    },
    "swapSupported": true
  },
  {
    "id": "scroll",
    "chainId": 534352,
    "name": "Scroll",
    "short": "SCR",
    "accent": "#f97316",
    "publicRpcUrl": "https://rpc.scroll.io",
    "explorerTxBase": "https://scrollscan.com/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "polygonZkEvm",
    "chainId": 1101,
    "name": "Polygon zkEVM",
    "short": "ZKE",
    "accent": "#8247e5",
    "publicRpcUrl": "https://zkevm-rpc.com",
    "explorerTxBase": "https://zkevm.polygonscan.com/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "taiko",
    "chainId": 167000,
    "name": "Taiko Mainnet",
    "short": "TAI",
    "accent": "#2d1b69",
    "publicRpcUrl": "https://rpc.mainnet.taiko.xyz",
    "explorerTxBase": "https://taikoscan.io/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Ether",
      "symbol": "ETH"
    },
    "swapSupported": true
  },
  {
    "id": "blast",
    "chainId": 81457,
    "name": "Blast",
    "short": "BLA",
    "accent": "#f59e0b",
    "publicRpcUrl": "https://rpc.blast.io",
    "explorerTxBase": "https://blastscan.io/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Ether",
      "symbol": "ETH"
    },
    "swapSupported": false
  },
  {
    "id": "mode",
    "chainId": 34443,
    "name": "Mode Mainnet",
    "short": "MOD",
    "accent": "#7c3aed",
    "publicRpcUrl": "https://mainnet.mode.network",
    "explorerTxBase": "https://modescan.io/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "manta",
    "chainId": 169,
    "name": "Manta Pacific Mainnet",
    "short": "MAN",
    "accent": "#14b8a6",
    "publicRpcUrl": "https://pacific-rpc.manta.network/http",
    "explorerTxBase": "https://pacific-explorer.manta.network/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "ETH",
      "symbol": "ETH"
    },
    "swapSupported": true
  },
  {
    "id": "mantle",
    "chainId": 5000,
    "name": "Mantle",
    "short": "MNT",
    "accent": "#4ade80",
    "publicRpcUrl": "https://rpc.mantle.xyz",
    "explorerTxBase": "https://mantlescan.xyz/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "MNT",
      "symbol": "MNT"
    },
    "swapSupported": true
  },
  {
    "id": "fraxtal",
    "chainId": 252,
    "name": "Fraxtal",
    "short": "FRX",
    "accent": "#00bcd4",
    "publicRpcUrl": "https://rpc.frax.com",
    "explorerTxBase": "https://fraxscan.com/tx/",
    "nativeCurrency": {
      "name": "Frax",
      "symbol": "FRAX",
      "decimals": 18
    },
    "swapSupported": false
  },
  {
    "id": "berachain",
    "chainId": 80094,
    "name": "Berachain",
    "short": "BER",
    "accent": "#f97316",
    "publicRpcUrl": "https://rpc.berachain.com",
    "explorerTxBase": "https://berascan.com/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "BERA Token",
      "symbol": "BERA"
    },
    "swapSupported": false
  },
  {
    "id": "unichain",
    "chainId": 130,
    "name": "Unichain",
    "short": "UCH",
    "accent": "#ff007a",
    "publicRpcUrl": "https://mainnet.unichain.org/",
    "explorerTxBase": "https://uniscan.xyz/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": true
  },
  {
    "id": "worldchain",
    "chainId": 480,
    "name": "World Chain",
    "short": "WLD",
    "accent": "#3b82f6",
    "publicRpcUrl": "https://worldchain-mainnet.g.alchemy.com/public",
    "explorerTxBase": "https://worldscan.org/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": false
  },
  {
    "id": "ink",
    "chainId": 57073,
    "name": "Ink",
    "short": "INK",
    "accent": "#2563eb",
    "publicRpcUrl": "https://rpc-gel.inkonchain.com",
    "explorerTxBase": "https://explorer.inkonchain.com/tx/",
    "nativeCurrency": {
      "name": "Ether",
      "symbol": "ETH",
      "decimals": 18
    },
    "swapSupported": false
  },
  {
    "id": "abstract",
    "chainId": 2741,
    "name": "Abstract",
    "short": "ABS",
    "accent": "#f59e0b",
    "publicRpcUrl": "https://api.mainnet.abs.xyz",
    "explorerTxBase": "https://abscan.org/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "ETH",
      "symbol": "ETH"
    },
    "swapSupported": false
  },
  {
    "id": "sei",
    "chainId": 1329,
    "name": "Sei Network",
    "short": "SEI",
    "accent": "#ff4d4f",
    "publicRpcUrl": "https://evm-rpc.sei-apis.com/",
    "explorerTxBase": "https://seiscan.io/tx/",
    "nativeCurrency": {
      "name": "Sei",
      "symbol": "SEI",
      "decimals": 18
    },
    "swapSupported": false
  },
  {
    "id": "zircuit",
    "chainId": 48900,
    "name": "Zircuit Mainnet",
    "short": "ZRC",
    "accent": "#7c3aed",
    "publicRpcUrl": "https://mainnet.zircuit.com",
    "explorerTxBase": "https://explorer.zircuit.com/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "Ether",
      "symbol": "ETH"
    },
    "swapSupported": false
  },
  {
    "id": "xLayer",
    "chainId": 196,
    "name": "X Layer Mainnet",
    "short": "OKB",
    "accent": "#1d4ed8",
    "publicRpcUrl": "https://xlayerrpc.okx.com",
    "explorerTxBase": "https://www.oklink.com/xlayer/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "OKB",
      "symbol": "OKB"
    },
    "swapSupported": true
  },
  {
    "id": "filecoin",
    "chainId": 314,
    "name": "Filecoin Mainnet",
    "short": "FIL",
    "accent": "#0090ff",
    "publicRpcUrl": "https://api.node.glif.io/rpc/v1",
    "explorerTxBase": "https://filfox.info/en/tx/",
    "nativeCurrency": {
      "decimals": 18,
      "name": "filecoin",
      "symbol": "FIL"
    },
    "swapSupported": false
  }
];

for (const definition of EVM_CHAIN_DEFINITIONS) {
  definition.logoURI ||= chainLogo(EVM_CHAIN_LOGO_SLUGS[definition.id] || definition.id);
}

export const EVM_CHAIN_IDS = EVM_CHAIN_DEFINITIONS.map((definition) => definition.chainId);
export const EVM_SWAP_CHAIN_IDS = EVM_CHAIN_DEFINITIONS.filter((definition) => definition.swapSupported).map((definition) => definition.chainId);

export function getEvmChainDefinition(chainId) {
  return EVM_CHAIN_DEFINITIONS.find((definition) => definition.chainId === Number(chainId)) || null;
}

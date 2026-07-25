import { EVM_CHAIN_DEFINITIONS, EVM_SWAP_CHAIN_IDS } from "./evmChainMetadata.js";
import { chainLogo } from "../lib/chainLogo.js";

export const SUPPORTED_CHAIN_IDS = EVM_SWAP_CHAIN_IDS;

const CHAIN_LOGO_SLUGS = {
  1: "ethereum",
  42161: "arbitrum",
  8453: "base",
  10: "optimism",
  137: "polygon",
  43114: "avalanche",
  56: "bsc",
  100: "gnosis",
  25: "cronos",
  1284: "moonbeam",
  42220: "celo",
  2222: "kava",
  1088: "metis",
  1313161554: "aurora",
  30: "rootstock",
  204: "opbnb",
  146: "sonic",
  59144: "linea",
  324: "zksync-era",
  534352: "scroll",
  1101: "polygon-zkevm",
  167000: "taiko",
  81457: "blast",
  34443: "mode",
  169: "manta",
  5000: "mantle",
  252: "fraxtal",
  80094: "berachain",
  130: "unichain",
  480: "world-chain",
  57073: "ink",
  2741: "abstract",
  1329: "sei",
  48900: "zircuit",
  196: "x-layer",
  314: "filecoin",
};

export const CHAIN_METADATA = Object.fromEntries(
  EVM_CHAIN_DEFINITIONS.map((definition) => [
    definition.chainId,
    {
      id: definition.id,
      chainId: definition.chainId,
      name: definition.name,
      shortName: definition.short,
      accent: definition.accent,
      color: definition.color || definition.accent || "#00ced1",
      nativeCurrency: definition.nativeCurrency,
      publicRpcUrl: definition.publicRpcUrl,
      explorerTxBase: definition.explorerTxBase,
      logoURI: definition.logoURI || chainLogo(CHAIN_LOGO_SLUGS[definition.chainId] || definition.id),
      swapSupported: definition.swapSupported,
    },
  ]),
);

export function getChainMetadata(chainId) {
  return CHAIN_METADATA[Number(chainId)] || null;
}

export function isSupportedChainId(chainId, supportedChainIds = SUPPORTED_CHAIN_IDS) {
  const numeric = Number(chainId);
  return Number.isInteger(numeric) && supportedChainIds.includes(numeric) && Boolean(getChainMetadata(numeric));
}

export function getExplorerTxUrl(chainId, txHash) {
  const metadata = getChainMetadata(chainId);
  if (!metadata?.explorerTxBase || !txHash) return null;
  return `${metadata.explorerTxBase}${String(txHash).replace(/^\/+/, "")}`;
}

export function getNativeCurrency(chainId) {
  return getChainMetadata(chainId)?.nativeCurrency || null;
}

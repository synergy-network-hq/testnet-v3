import { CHAIN_METADATA as EVM_CHAIN_METADATA } from "../config/chains.js";
import { chainLogo } from "../lib/chainLogo.js";

const EVM_NETWORKS = Object.values(EVM_CHAIN_METADATA).map((definition) => ({
  id: definition.id,
  chainId: definition.chainId,
  name: definition.name,
  short: definition.shortName,
  label: definition.name,
  accent: definition.accent || definition.color || "#00ced1",
  color: definition.color || definition.accent || "#00ced1",
  logoURI: definition.logoURI,
  aggregatorSupported: definition.swapSupported,
}));

const SUPPORTED_EVM_NETWORKS = EVM_NETWORKS.filter((network) => network.aggregatorSupported);
const WALLET_ONLY_EVM_NETWORKS = EVM_NETWORKS.filter((network) => !network.aggregatorSupported);

function createExternalNetwork({
  id,
  name,
  short,
  label = name,
  slug,
  logoURI,
  accent,
  connectable = false,
  walletFamily = id,
}) {
  return {
    id,
    chainId: null,
    name,
    short,
    label,
    accent,
    color: accent,
    logoURI: logoURI ?? chainLogo(slug || id),
    aggregatorSupported: false,
    launchStatus: connectable ? "Wallet connection" : "External chain",
    walletConnectable: connectable,
    walletFamily,
  };
}

const EXTERNAL_NETWORKS = [
  createExternalNetwork({
    id: "solana",
    name: "Solana",
    short: "SOL",
    accent: "#14f195",
    connectable: true,
    walletFamily: "solana",
  }),
  createExternalNetwork({
    id: "bitcoin",
    name: "Bitcoin",
    short: "BTC",
    accent: "#f7931a",
    connectable: true,
    walletFamily: "bitcoin",
  }),
  createExternalNetwork({
    id: "blockdag",
    name: "BlockDAG",
    short: "BDAG",
    label: "BlockDAG",
    logoURI: "https://blockdag.network/images/presskit/Logo.svg",
    accent: "#f4c542",
    walletFamily: "blockdag",
  }),
  createExternalNetwork({
    id: "kaanch",
    name: "Kaanch Network",
    short: "KNCH",
    label: "Kaanch Network",
    logoURI: "https://kaanch.com/logo192.png",
    accent: "#4be7c7",
    walletFamily: "kaanch",
  }),
  createExternalNetwork({
    id: "cosmos",
    name: "Cosmos IBC",
    short: "ATOM",
    accent: "#2e3148",
  }),
  createExternalNetwork({
    id: "polkadot",
    name: "Polkadot",
    short: "DOT",
    accent: "#e6007a",
  }),
  createExternalNetwork({
    id: "aptos",
    name: "Aptos",
    short: "APT",
    accent: "#000000",
  }),
  createExternalNetwork({
    id: "sui",
    name: "Sui",
    short: "SUI",
    accent: "#4da2ff",
  }),
  createExternalNetwork({
    id: "cardano",
    name: "Cardano",
    short: "ADA",
    accent: "#0033ad",
  }),
  createExternalNetwork({
    id: "algorand",
    name: "Algorand",
    short: "ALGO",
    accent: "#000000",
  }),
  createExternalNetwork({
    id: "tron",
    name: "Tron",
    short: "TRX",
    accent: "#ff060a",
  }),
  createExternalNetwork({
    id: "ton",
    name: "TON Network",
    short: "TON",
    accent: "#0098ea",
  }),
  createExternalNetwork({
    id: "xrp",
    name: "XRP Ledger",
    short: "XRP",
    accent: "#23292f",
  }),
  createExternalNetwork({
    id: "celestia",
    name: "Celestia",
    short: "TIA",
    accent: "#7b2bf9",
  }),
  createExternalNetwork({
    id: "osmosis",
    name: "Osmosis",
    short: "OSMO",
    accent: "#5b3df5",
  }),
];

export const NETWORKS = [
  {
    id: "synergy",
    chainId: 1264,
    name: "Synergy",
    short: "SYN",
    label: "Synergy Network",
    accent: "#00ced1",
    color: "#00ced1",
    logoURI: "/relay-icon.png",
    aggregatorSupported: false,
    launchStatus: "Synergy native status",
  },
  ...SUPPORTED_EVM_NETWORKS,
  ...WALLET_ONLY_EVM_NETWORKS,
  ...EXTERNAL_NETWORKS,
];

export const getNetwork = (id) => NETWORKS.find((n) => n.id === id || n.chainId === Number(id)) ?? NETWORKS[0];

export const getNetworkByChainId = (chainId) => NETWORKS.find((n) => n.chainId === Number(chainId)) ?? NETWORKS[0];

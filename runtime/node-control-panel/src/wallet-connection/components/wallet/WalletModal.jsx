import { useEffect, useMemo, useState } from "react";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { useAccount, useDisconnect } from "wagmi";
import { NETWORKS } from "../../data/networks.js";
import { ChainGlyph } from "../ui/TokenGlyph.jsx";
import { fmtAddress } from "../../lib/format.js";
import { normalizeAccountSnapshot } from "../../lib/accountSnapshot.js";
import { walletConfigWarning, walletConnectionConfigured } from "../../services/evm-wallet.js";
import { createWalletConnectionConfig, relayWalletConnectionConfig } from "./walletConnectionConfig.js";
import snrgFamilyIcon from "../../assets/wallet/snrg-btn.png";
import evmFamilyIcon from "../../assets/wallet/eth-btn.png";
import nonEvmFamilyIcon from "../../assets/wallet/net-btn.png";

const EVM_NETWORK_PREVIEW = ["ethereum", "bsc", "arbitrum", "optimism", "polygon", "base"];
const NON_EVM_NETWORK_PREVIEW = ["solana", "cosmos", "bitcoin", "polkadot", "aptos", "sui"];

const NON_EVM_NETWORK_IDS = [
  "solana",
  "cosmos",
  "bitcoin",
  "polkadot",
  "blockdag",
  "kaanch",
  "aptos",
  "sui",
  "cardano",
  "algorand",
  "tron",
  "ton",
  "xrp",
  "celestia",
  "osmosis",
];

const NON_EVM_WALLETS = [
  {
    id: "solana",
    iconType: "phantom",
    networkId: "solana",
    title: "Phantom",
    caption: "Solana swaps live",
    badge: "Popular",
    connect: (wallet) => wallet.connectSolanaInjected?.(),
  },
  {
    id: "bitcoin",
    iconType: "bitcoin",
    networkId: "bitcoin",
    title: "Bitcoin Wallet",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectBitcoinInjected?.(),
  },
  {
    id: "cosmos",
    iconType: "keplr",
    networkId: "cosmos",
    title: "Keplr / Leap",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectNonEvmNetwork?.("cosmos"),
  },
  {
    id: "polkadot",
    iconType: "polkadot",
    networkId: "polkadot",
    title: "Polkadot Wallet",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectNonEvmNetwork?.("polkadot"),
  },
  {
    id: "aptos",
    iconType: "aptos",
    networkId: "aptos",
    title: "Aptos Wallet",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectNonEvmNetwork?.("aptos"),
  },
  {
    id: "sui",
    iconType: "sui",
    networkId: "sui",
    title: "Sui Wallet",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectNonEvmNetwork?.("sui"),
  },
  {
    id: "cardano",
    iconType: "cardano",
    networkId: "cardano",
    title: "Cardano Wallet",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectNonEvmNetwork?.("cardano"),
  },
  {
    id: "tron",
    iconType: "tron",
    networkId: "tron",
    title: "TronLink",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectNonEvmNetwork?.("tron"),
  },
  {
    id: "ton",
    iconType: "ton",
    networkId: "ton",
    title: "TON Wallet",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectNonEvmNetwork?.("ton"),
  },
  {
    id: "xrp",
    iconType: "xrp",
    networkId: "xrp",
    title: "XRP Wallet",
    caption: "Wallet connection only; swaps not live",
    connect: (wallet) => wallet.connectNonEvmNetwork?.("xrp"),
  },
];

function Icon({ name, className = "" }) {
  const props = {
    className: `wallet-modal__svg ${className}`.trim(),
    viewBox: "0 0 24 24",
    fill: "none",
    xmlns: "http://www.w3.org/2000/svg",
    "aria-hidden": "true",
  };

  if (name === "back") {
    return (
      <svg {...props}>
        <path d="M15 5 8 12l7 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  if (name === "close") {
    return (
      <svg {...props}>
        <path d="m7 7 10 10M17 7 7 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    );
  }

  if (name === "chevron") {
    return (
      <svg {...props}>
        <path d="m9 5 7 7-7 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  if (name === "down") {
    return (
      <svg {...props}>
        <path d="m7 10 5 5 5-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  if (name === "info") {
    return (
      <svg {...props}>
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" />
        <path d="M12 10.8v5.2M12 7.2h.01" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      </svg>
    );
  }

  if (name === "shield") {
    return (
      <svg {...props}>
        <path d="M12 3.5 19 6v5.4c0 4.4-2.8 7.6-7 9.1-4.2-1.5-7-4.7-7-9.1V6l7-2.5Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
        <path d="m9 12 2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  if (name === "lock") {
    return (
      <svg {...props}>
        <rect x="6.6" y="10.2" width="10.8" height="9" rx="2" stroke="currentColor" strokeWidth="1.7" />
        <path d="M8.8 10.2V7.6a3.2 3.2 0 0 1 6.4 0v2.6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      </svg>
    );
  }

  if (name === "globe") {
    return (
      <svg {...props}>
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.7" />
        <path d="M3 12h18M12 3c2.4 2.3 3.5 5.3 3.5 9S14.4 18.7 12 21M12 3C9.6 5.3 8.5 8.3 8.5 12s1.1 6.7 3.5 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    );
  }

  if (name === "browser") {
    return (
      <svg {...props}>
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.7" />
        <path d="M4.5 9h15M8 9c.5-2.4 1.8-4.2 4-6M16 9c-.5-2.4-1.8-4.2-4-6M8 15c.5 2.4 1.8 4.2 4 6M16 15c-.5 2.4-1.8 4.2-4 6M12 3v18" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    );
  }

  if (name === "qr") {
    return (
      <svg {...props}>
        <path d="M5 5h5v5H5V5ZM14 5h5v5h-5V5ZM5 14h5v5H5v-5Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
        <path d="M14 14h2.5v2.5H19M19 14v1.2M14 19h1.2M17.4 19H19v-1.6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  if (name === "walletconnect") {
    return (
      <svg {...props} viewBox="0 0 32 32">
        <path d="M9.1 13.2c3.8-3.6 10-3.6 13.8 0l.5.5-2 2-.7-.6c-2.6-2.3-6.7-2.3-9.3 0l-.7.6-2-2 .4-.5Z" fill="currentColor" />
        <path d="m12 17 2.1 2.1c1 1 2.8 1 3.8 0L20 17l2 2-2.2 2.2c-2.1 2.1-5.5 2.1-7.6 0L10 19l2-2Z" fill="currentColor" />
      </svg>
    );
  }

  if (name === "coinbase") {
    return (
      <svg {...props} viewBox="0 0 32 32">
        <circle cx="16" cy="16" r="12" fill="currentColor" opacity="0.98" />
        <path d="M11 12.3h10v7.4H11v-7.4Zm2.9 2.4v2.6h4.2v-2.6h-4.2Z" fill="#fff" />
      </svg>
    );
  }

  if (name === "phantom") {
    return (
      <svg {...props} viewBox="0 0 32 32">
        <path d="M6 17.4C6 10.9 10.6 6 16.7 6 22.3 6 26 10.2 26 15.6v6.1c0 .9-1.1 1.3-1.7.6l-1.2-1.4-1.4 1.7a1.1 1.1 0 0 1-1.7 0l-1.4-1.7-1.4 1.7a1.1 1.1 0 0 1-1.7 0l-1.4-1.7-1.5 1.8c-.5.7-1.7.3-1.7-.6v-4.7Z" fill="currentColor" />
        <circle cx="14" cy="15" r="1.2" fill="#fff" />
        <circle cx="20" cy="15" r="1.2" fill="#fff" />
      </svg>
    );
  }

  if (name === "metamask") {
    return (
      <svg {...props} viewBox="0 0 32 32">
        <path d="m5 7 8.2 6.1L11.7 9 5 7Z" fill="#f6851b" />
        <path d="m27 7-8.2 6.1L20.3 9 27 7Z" fill="#f6851b" />
        <path d="m13.2 13.1-2.4 3.7 3.6-.2h3.2l3.6.2-2.4-3.7-2.8 1.8-2.8-1.8Z" fill="#e2761b" />
        <path d="m10.8 16.8-1.2 4.1 4.2-1.1.6-3.2-3.6.2ZM21.2 16.8l-3.6-.2.6 3.2 4.2 1.1-1.2-4.1Z" fill="#f6851b" />
        <path d="m13.8 19.8-2.2 2.1 4.4 2.4 4.4-2.4-2.2-2.1-2.2 1.2-2.2-1.2Z" fill="#c0ad9e" />
        <path d="m5 7 3.6 15.1 3 1-2-2.2 1.2-4.1 2.4-3.7L5 7ZM27 7l-8.2 6.1 2.4 3.7 1.2 4.1-2 2.2 3-1L27 7Z" fill="#763d16" opacity=".9" />
      </svg>
    );
  }

  if (name === "rainbow") {
    return (
      <svg {...props} viewBox="0 0 32 32">
        <defs>
          <linearGradient id="wallet-rainbow-mark" x1="6" y1="26" x2="26" y2="6" gradientUnits="userSpaceOnUse">
            <stop stopColor="#5967ff" />
            <stop offset=".28" stopColor="#28d8ff" />
            <stop offset=".5" stopColor="#4be47d" />
            <stop offset=".72" stopColor="#ffe15d" />
            <stop offset="1" stopColor="#ff5f7a" />
          </linearGradient>
        </defs>
        <circle cx="16" cy="16" r="13" fill="url(#wallet-rainbow-mark)" />
        <path d="M8.5 18.8a7.5 7.5 0 0 1 15 0" stroke="#fff" strokeWidth="3" strokeLinecap="round" />
        <path d="M13 18.8a3 3 0 0 1 6 0" stroke="#07101f" strokeWidth="2" strokeLinecap="round" opacity=".55" />
      </svg>
    );
  }

  return null;
}

function WalletFact({ label, value }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value || "-"}</strong>
    </div>
  );
}

function walletSourceLabel(source) {
  if (source === "mobile-pairing") return "Mobile pairing";
  if (source === "synergy-injected") return "Browser provider";
  if (source === "evm-wagmi" || source === "evm-injected") return "EVM provider";
  if (source === "solana-injected") return "Injected wallet";
  if (source === "bitcoin-injected") return "Injected wallet";
  return source || "In-browser provider";
}

function isLaneEnabled(config, lane) {
  return config.lanes?.[lane]?.enabled !== false;
}

function enabledFamilies(config) {
  return ["synergy", "evm", "nonEvm"].filter((lane) => isLaneEnabled(config, lane));
}

function RelayMark({ config }) {
  if (config.brand.bannerSrc) {
    return (
      <div className="wallet-modal__brand wallet-modal__brand--banner" aria-label={config.brand.ariaLabel}>
        <img className="wallet-modal__brand-banner" src={config.brand.bannerSrc} alt="" />
      </div>
    );
  }

  return (
    <div className="wallet-modal__brand" aria-label={config.brand.ariaLabel}>
      <img src={config.brand.logoSrc} alt="" />
      <span>{config.brand.label}</span>
    </div>
  );
}

function BackButton({ onClick }) {
  return (
    <button type="button" className="wallet-modal__back" onClick={onClick} aria-label="Back to wallet network choices">
      <Icon name="back" />
    </button>
  );
}

function FamilyIcon({ type, config }) {
  if (type === "synergy") {
    return (
      <span className="wallet-modal__family-icon wallet-modal__family-icon--synergy">
        <img
          className="wallet-modal__family-art wallet-modal__family-art--synergy"
          src={config.lanes.synergy.iconSrc || snrgFamilyIcon}
          alt=""
        />
      </span>
    );
  }

  if (type === "evm") {
    return (
      <span className="wallet-modal__family-icon wallet-modal__family-icon--evm">
        <img
          className="wallet-modal__family-art wallet-modal__family-art--evm"
          src={config.lanes.evm.iconSrc || evmFamilyIcon}
          alt=""
        />
      </span>
    );
  }

  return (
    <span className="wallet-modal__family-icon wallet-modal__family-icon--non-evm">
      <img
        className="wallet-modal__family-art wallet-modal__family-art--non-evm"
        src={config.lanes.nonEvm.iconSrc || nonEvmFamilyIcon}
        alt=""
      />
    </span>
  );
}

function FamilyChoice({ type, title, subtitle, onClick, config }) {
  return (
    <button type="button" className={`wallet-modal__family wallet-modal__family--${type}`} onClick={onClick}>
      <FamilyIcon type={type} config={config} />
      <span>
        <strong>{title}</strong>
        <small>{subtitle}</small>
      </span>
      <Icon name="chevron" className="wallet-modal__chevron" />
    </button>
  );
}

function WalletIcon({ type, networkId, children }) {
  if (networkId && !["phantom"].includes(type)) {
    return (
      <span className={`wallet-modal__wallet-icon wallet-modal__wallet-icon--${type}`}>
        <ChainGlyph id={networkId} />
      </span>
    );
  }

  if (type === "browser") {
    return (
      <span className="wallet-modal__wallet-icon wallet-modal__wallet-icon--browser">
        <Icon name="browser" />
      </span>
    );
  }

  if (type === "qr") {
    return (
      <span className="wallet-modal__wallet-icon wallet-modal__wallet-icon--qr">
        <Icon name="qr" />
      </span>
    );
  }

  if (type === "coinbase") {
    return (
      <span className="wallet-modal__wallet-icon wallet-modal__wallet-icon--coinbase">
        <Icon name="coinbase" />
      </span>
    );
  }

  if (type === "walletconnect") {
    return (
      <span className="wallet-modal__wallet-icon wallet-modal__wallet-icon--walletconnect">
        <Icon name="walletconnect" />
      </span>
    );
  }

  if (type === "phantom") {
    return (
      <span className="wallet-modal__wallet-icon wallet-modal__wallet-icon--phantom">
        <Icon name="phantom" />
      </span>
    );
  }

  if (type === "metamask" || type === "rainbow") {
    return (
      <span className={`wallet-modal__wallet-icon wallet-modal__wallet-icon--${type}`}>
        <Icon name={type} />
      </span>
    );
  }

  return <span className={`wallet-modal__wallet-icon wallet-modal__wallet-icon--${type}`}>{children}</span>;
}

function WalletRow({ iconType, icon, networkId, title, caption, badge, disabled = false, onClick }) {
  return (
    <button type="button" className="wallet-modal__wallet-row" disabled={disabled} onClick={onClick}>
      <WalletIcon type={iconType} networkId={networkId}>{icon}</WalletIcon>
      <span>
        <strong>{title}</strong>
        {caption && <small>{caption}</small>}
      </span>
      {badge && <em>{badge}</em>}
    </button>
  );
}

function NetworkPreview({ ids, totalCount }) {
  const extraCount = Math.max(0, totalCount - ids.length);

  return (
    <div className="wallet-modal__network-preview" aria-label="Supported network preview">
      {ids.map((id) => (
        <ChainGlyph key={id} id={id} />
      ))}
      {extraCount > 0 && <span className="wallet-modal__more-count">+{extraCount}</span>}
    </div>
  );
}

function ConnectedAccount({ wallet }) {
  if (!wallet?.isConnected) return null;

  return (
    <div className="wallet-modal__connected">
      <div className="wallet-modal__account">
        <ChainGlyph id={wallet.chainId || wallet.networkId || wallet.walletType || "synergy"} />
        <div>
          <strong className="mono">{fmtAddress(wallet.address)}</strong>
          <span>{wallet.networkName || wallet.walletType || "Wallet connected"}</span>
        </div>
      </div>
      <div className="wallet-modal__facts">
        <WalletFact label="Network" value={wallet.networkName || wallet.chainIdHex || wallet.chainId} />
        <WalletFact label="Source" value={walletSourceLabel(wallet.source)} />
        <WalletFact label="Signing" value={wallet.canSign ? "Ready" : "Pairing only"} />
      </div>
      <div className="wallet-modal__actions">
        <button type="button" className="btn btn--ghost" onClick={wallet.refresh}>Refresh</button>
        <button type="button" className="btn" onClick={wallet.disconnect}>Disconnect</button>
      </div>
    </div>
  );
}

function HomeView({ wallet, setView, config }) {
  const lanes = config.lanes;

  return (
    <>
      <RelayMark config={config} />
      <div className="wallet-modal__headline">
        <h2 id="wallet-modal-title">{config.copy.homeTitle}</h2>
        {config.copy.homeSubtitle ? <p>{config.copy.homeSubtitle}</p> : null}
      </div>

      <div className="wallet-modal__families">
        {isLaneEnabled(config, "synergy") && (
          <FamilyChoice
            type="synergy"
            title={lanes.synergy.title}
            subtitle={lanes.synergy.subtitle}
            onClick={() => setView("synergy")}
            config={config}
          />
        )}
        {isLaneEnabled(config, "evm") && (
          <FamilyChoice
            type="evm"
            title={lanes.evm.title}
            subtitle={lanes.evm.subtitle}
            onClick={() => setView("evm")}
            config={config}
          />
        )}
        {isLaneEnabled(config, "nonEvm") && (
          <FamilyChoice
            type="non-evm"
            title={lanes.nonEvm.title}
            subtitle={lanes.nonEvm.subtitle}
            onClick={() => setView("nonEvm")}
            config={config}
          />
        )}
      </div>

      <ConnectedAccount wallet={wallet} />

      {config.securityNote?.title || config.securityNote?.body ? (
        <div className="wallet-modal__secure-note">
          <span className="wallet-modal__secure-icon" aria-hidden="true">
            <Icon name="lock" />
          </span>
          <span>
            {config.securityNote?.title ? <strong>{config.securityNote.title}</strong> : null}
            {config.securityNote?.body ? <small>{config.securityNote.body}</small> : null}
          </span>
        </div>
      ) : null}
    </>
  );
}

function SynergyFlow({ wallet, pairing, setView, config }) {
  const scanLabel = "Mobile Wallet";
  const browserProviderEnabled = config.lanes.synergy.browserProviderEnabled !== false;
  const mobilePairingEnabled = config.lanes.synergy.mobilePairingEnabled !== false;

  return (
    <>
      <BackButton onClick={() => setView("home")} />
      <div className="wallet-modal__flow-title">
        <h2 id="wallet-modal-title">{config.lanes.synergy.flowTitle || config.lanes.synergy.title}</h2>
        <p>{browserProviderEnabled ? "Choose how you want to connect" : "Scan with Synergy Wallet mobile"}</p>
      </div>
      <div className="wallet-modal__choice-stack">
        <button
          type="button"
          className={`wallet-modal__choice ${browserProviderEnabled ? "wallet-modal__choice--active" : "wallet-modal__choice--soon"}`.trim()}
          onClick={wallet.connectSynergyInjected}
          disabled={!browserProviderEnabled || wallet.status === "connecting"}
        >
          <WalletIcon type="browser" />
          <span>
            <strong>Browser Wallet</strong>
            <small>
              {browserProviderEnabled
                ? (wallet.hasSynergyProvider ? "Connect using your browser wallet" : "No Synergy provider detected")
                : "Connect with the Synergy browser wallet extension"}
            </small>
          </span>
          <span className="wallet-modal__choice-meta">
            {!browserProviderEnabled ? <em className="wallet-modal__soon-badge">SOON</em> : null}
            <Icon name="chevron" className="wallet-modal__chevron" />
          </span>
        </button>
        <button
          type="button"
          className="wallet-modal__choice wallet-modal__choice--active"
          onClick={() => {
            setView("synergyQr");
            wallet.startMobilePairing?.();
          }}
          disabled={!mobilePairingEnabled || pairing.status === "starting" || pairing.status === "pending"}
        >
          <WalletIcon type="qr" />
          <span>
            <strong>{scanLabel}</strong>
            <small>Scan with Synergy Wallet mobile app</small>
          </span>
          <Icon name="chevron" className="wallet-modal__chevron" />
        </button>
      </div>
      <ConnectedAccount wallet={wallet} />
    </>
  );
}

function SynergyQrFlow({ wallet, pairing, setView, config }) {
  return (
    <>
      <BackButton onClick={() => setView("synergy")} />
      <div className="wallet-modal__flow-title">
        <h2 id="wallet-modal-title">Scan with Synergy Wallet</h2>
        <p>Open the Synergy Wallet app and scan the QR code below</p>
      </div>
      <div className="wallet-modal__qr-stage">
        {pairing.qrImage ? (
          <img src={pairing.qrImage} alt="Synergy Wallet mobile connection QR code" />
        ) : (
          <div className="wallet-modal__qr-loading">Preparing</div>
        )}
        <img className="wallet-modal__qr-logo" src={config.brand.logoSrc} alt="" />
      </div>
      <div className="wallet-modal__qr-help">
        <span>{pairing.expiresAt ? `Expires ${new Date(pairing.expiresAt).toLocaleTimeString()}` : pairing.message || "Preparing secure pairing..."}</span>
        {pairing.deepLink && <a href={pairing.deepLink}>Open app</a>}
      </div>
      <button type="button" className="wallet-modal__text-button" onClick={wallet.startMobilePairing}>
        Generate new code
      </button>
    </>
  );
}

function EvmFlow({ wallet, setView, config }) {
  const evmCount = NETWORKS.filter((network) => network.chainId && network.aggregatorSupported).length;

  return (
    <>
      <BackButton onClick={() => setView("home")} />
      <div className="wallet-modal__flow-title">
        <h2 id="wallet-modal-title">{config.lanes.evm.flowTitle}</h2>
        <p>Choose your wallet</p>
      </div>
      <NetworkPreview ids={EVM_NETWORK_PREVIEW} totalCount={evmCount} />

      <ConnectButton.Custom>
        {({ openConnectModal, mounted }) => {
          const connect = () => {
            wallet.activateEvm?.();
            openConnectModal?.();
          };
          const disabled = !mounted || !walletConnectionConfigured;
          return (
            <>
              <div className="wallet-modal__wallet-list">
                <WalletRow iconType="metamask" icon="M" title="MetaMask" badge="Popular" disabled={disabled} onClick={connect} />
                <WalletRow iconType="rainbow" icon="R" title="Rainbow" disabled={disabled} onClick={connect} />
                <WalletRow iconType="coinbase" title="Coinbase Wallet" disabled={disabled} onClick={connect} />
                <WalletRow iconType="walletconnect" title="WalletConnect" disabled={disabled} onClick={connect} />
              </div>
              <button type="button" className="wallet-modal__text-button wallet-modal__text-button--icon" disabled={disabled} onClick={connect}>
                <span>More wallets</span>
                <Icon name="down" />
              </button>
            </>
          );
        }}
      </ConnectButton.Custom>

      {!walletConnectionConfigured && (
        <div className="wallet-modal__status wallet-modal__status--info">
          <Icon name="info" />
          <span>{walletConfigWarning}</span>
        </div>
      )}
      <ConnectedAccount wallet={wallet} />
    </>
  );
}

function NonEvmFlow({ wallet, setView, config }) {
  const [showAll, setShowAll] = useState(false);
  const nonEvmCount = NETWORKS.filter((network) => NON_EVM_NETWORK_IDS.includes(network.id)).length;
  const visibleWallets = showAll ? NON_EVM_WALLETS : NON_EVM_WALLETS.slice(0, 4);

  return (
    <>
      <BackButton onClick={() => setView("home")} />
      <div className="wallet-modal__flow-title">
        <h2 id="wallet-modal-title">{config.lanes.nonEvm.flowTitle}</h2>
        <p>Solana swaps are live. Other wallet connections are not swap-enabled yet.</p>
      </div>
      <NetworkPreview ids={NON_EVM_NETWORK_PREVIEW} totalCount={nonEvmCount} />

      <div className="wallet-modal__wallet-list">
        {visibleWallets.map((item) => (
          <WalletRow
            key={item.id}
            iconType={item.iconType}
            networkId={item.networkId}
            title={item.title}
            caption={item.caption}
            badge={item.badge}
            disabled={wallet.status === "connecting"}
            onClick={() => item.connect(wallet)}
          />
        ))}
      </div>

      <button type="button" className="wallet-modal__text-button wallet-modal__text-button--icon" onClick={() => setShowAll((current) => !current)}>
        <span>{showAll ? "Show fewer wallets" : "View all wallets"}</span>
        <Icon name="down" />
      </button>
      <ConnectedAccount wallet={wallet} />
    </>
  );
}

function viewAllowed(view, config) {
  if (view === "home") return true;
  if (view === "synergy" || view === "synergyQr") return isLaneEnabled(config, "synergy");
  if (view === "evm") return isLaneEnabled(config, "evm");
  if (view === "nonEvm") return isLaneEnabled(config, "nonEvm");
  return false;
}

export default function WalletModal({ wallet, config: configInput = relayWalletConnectionConfig }) {
  const [view, setView] = useState("home");
  const pairing = wallet?.pairing || {};
  const account = normalizeAccountSnapshot(useAccount());
  const { disconnect } = useDisconnect();
  const config = useMemo(() => createWalletConnectionConfig(configInput), [configInput]);
  const availableLanes = enabledFamilies(config);

  useEffect(() => {
    if (!wallet?.modalOpen) return;
    if (pairing.status === "pending" && pairing.qrImage && isLaneEnabled(config, "synergy")) {
      setView("synergyQr");
    }
  }, [config, pairing.qrImage, pairing.status, wallet?.modalOpen]);

  useEffect(() => {
    if (!viewAllowed(view, config)) setView("home");
  }, [config, view]);

  const closeModal = () => {
    setView("home");
    wallet.closeModal?.();
  };

  const viewClass = useMemo(
    () => `wallet-modal wallet-modal--${view} wallet-modal--lanes-${availableLanes.length || 1}`,
    [availableLanes.length, view],
  );

  if (!wallet?.modalOpen) return null;

  const enhancedWallet = {
    ...wallet,
    disconnect: () => {
      if (wallet.walletType === "evm") disconnect();
      wallet.disconnect?.();
    },
    chainId: wallet.chainId || account.chainId,
  };

  return (
    <div className="wallet-modal-backdrop" role="presentation" onMouseDown={closeModal}>
      <section
        className={viewClass}
        role="dialog"
        aria-modal="true"
        aria-labelledby="wallet-modal-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button type="button" className="wallet-modal__close" onClick={closeModal} aria-label="Close wallet modal">
          <Icon name="close" />
        </button>

        {view === "home" && <HomeView wallet={enhancedWallet} setView={setView} config={config} />}
        {view === "synergy" && <SynergyFlow wallet={enhancedWallet} pairing={pairing} setView={setView} config={config} />}
        {view === "synergyQr" && <SynergyQrFlow wallet={enhancedWallet} pairing={pairing} setView={setView} config={config} />}
        {view === "evm" && <EvmFlow wallet={enhancedWallet} setView={setView} config={config} />}
        {view === "nonEvm" && <NonEvmFlow wallet={enhancedWallet} setView={setView} config={config} />}

        {(wallet.error || (pairing.message && view !== "home" && view !== "synergyQr")) && (
          <div className="wallet-modal__status">
            {wallet.error || pairing.message}
          </div>
        )}
      </section>
    </div>
  );
}

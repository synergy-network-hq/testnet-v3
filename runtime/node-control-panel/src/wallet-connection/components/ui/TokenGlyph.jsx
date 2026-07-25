import { useState } from "react";
import { getToken } from "../../data/tokens.js";
import { getNetwork } from "../../data/networks.js";

function SafeLogo({ src, fallback, alt = "" }) {
  const [failed, setFailed] = useState(false);
  if (!src || failed) return fallback;
  return <img src={src} alt={alt} loading="lazy" onError={() => setFailed(true)} />;
}

export function TokenGlyph({ symbol, logoURI, network, size = "md" }) {
  const networkId = network ? getNetwork(network)?.id : null;
  const t = getToken(symbol, networkId);
  const fallbackGlyph = t.glyph || (t.symbol ? t.symbol.slice(0, 1).toUpperCase() : "?");
  const cls = `token-glyph${size === "lg" ? " token-glyph--lg" : ""}`;
  return (
    <span className={cls} style={{ background: `${t.color}1a`, borderColor: `${t.color}55`, color: t.color }}>
      <SafeLogo src={logoURI || t.logoURI} fallback={fallbackGlyph} />
    </span>
  );
}

export function TokenRow({ symbol, network }) {
  const t = getToken(symbol, network ? getNetwork(network)?.id : null);
  return (
    <div className="token-row">
      <TokenGlyph symbol={symbol} network={network} />
      <div>
        <div className="token-row__symbol">{t.symbol}</div>
        <div className="token-row__name">
          {network ? `${t.name} · ${getNetwork(network).name}` : t.name}
        </div>
      </div>
    </div>
  );
}

export function ChainGlyph({ id }) {
  const n = getNetwork(id);
  return (
    <span className="chain-glyph" style={{ background: `${n.color}22`, borderColor: `${n.color}66`, color: n.color }}>
      <SafeLogo src={n.logoURI} fallback={n.short.slice(0, 3)} />
    </span>
  );
}

export function ChainPair({ from, to }) {
  return (
    <span className="chain-pair">
      <ChainGlyph id={from} />
      {to && to !== from && <ChainGlyph id={to} />}
    </span>
  );
}

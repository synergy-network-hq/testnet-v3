export const fmtUSD = (value, opts = {}) => {
  const { compact = false, digits } = opts;
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    notation: compact ? "compact" : "standard",
    maximumFractionDigits: digits ?? (compact ? 2 : value >= 100 ? 0 : 2),
    minimumFractionDigits: digits ?? 0,
  }).format(Number(value) || 0);
};

export const fmtNumber = (value, digits = 2) => {
  return new Intl.NumberFormat("en-US", {
    minimumFractionDigits: 0,
    maximumFractionDigits: digits,
  }).format(Number(value) || 0);
};

export const fmtCompact = (value) => {
  return new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 2,
  }).format(Number(value) || 0);
};

export const fmtPct = (value, digits = 2) => `${Number(value).toFixed(digits)}%`;

export const fmtEta = (seconds) => {
  if (seconds < 1) return "instant";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
};

export const fmtAge = (timestamp) => {
  const diff = Math.max(1, Math.floor((Date.now() - timestamp) / 1000));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
};

export const fmtDate = (timestamp) =>
  new Date(timestamp).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

export const fmtAddress = (addr) => {
  if (!addr) return "";
  if (addr.length <= 12) return addr;
  return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
};

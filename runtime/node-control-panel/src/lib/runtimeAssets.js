const baseUrl = String(import.meta.env?.BASE_URL || '/');

export function runtimeAsset(path) {
  const normalizedPath = String(path || '').replace(/^\/+/, '');
  if (!normalizedPath) {
    return baseUrl;
  }
  return `${baseUrl}${normalizedPath}`;
}

export const brandLogoSrc = runtimeAsset('branding/assets/snrg-logo.png');
export const controlPanelBannerSrc = runtimeAsset('branding/assets/control-panel-banner.png');
export const ecosystemHeaderGifSrc = runtimeAsset('branding/assets/ecobanner.gif');
export const splashBrandGifSrc = runtimeAsset('branding/assets/snrg-splash.gif');
export const controlPanelIconSrc = runtimeAsset('branding/assets/control-panel-icon.png');
export const jarvisIconSrc = runtimeAsset('branding/assets/jarvis-icon.png');

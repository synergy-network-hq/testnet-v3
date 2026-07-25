import { createWalletConnectionConfig } from '../../wallet-connection/components/wallet/walletConnectionConfig';
import snrgFamilyIcon from '../../wallet-connection/assets/wallet/snrg-btn.png';
import { controlPanelBannerSrc, controlPanelIconSrc } from '../../lib/runtimeAssets';

export const synergyOnlyWalletConnectionConfig = createWalletConnectionConfig({
  brand: {
    label: 'Synergy Node Control Panel',
    ariaLabel: 'Synergy Node Control Panel wallet connection',
    logoSrc: controlPanelIconSrc,
    bannerSrc: controlPanelBannerSrc,
  },
  copy: {
    homeTitle: 'Connect Wallet',
    homeSubtitle: '',
  },
  securityNote: {
    title: 'Your funds stay secure',
    body: 'We never access your funds.',
  },
  enabledLanes: {
    synergy: true,
    evm: false,
    nonEvm: false,
  },
  lanes: {
    synergy: {
      title: 'Synergy Network',
      subtitle: 'Relay native network',
      flowTitle: 'Synergy Wallet',
      iconSrc: snrgFamilyIcon,
      browserProviderEnabled: false,
      mobilePairingEnabled: true,
    },
    evm: {
      enabled: false,
      title: 'EVM Networks',
      subtitle: 'Disabled in the node control panel',
    },
    nonEvm: {
      enabled: false,
      title: 'Non-EVM Networks',
      subtitle: 'Disabled in the node control panel',
    },
  },
});

export function walletLaneIsEnabled(lane) {
  return synergyOnlyWalletConnectionConfig.lanes?.[lane]?.enabled === true;
}

import React from 'react';
import ReactDOM from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import { RainbowKitProvider } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { WagmiProvider } from 'wagmi';
import App from './App';
import AppErrorBoundary from './components/AppErrorBoundary';
import { relayRainbowTheme, wagmiConfig } from './wallet-connection/services/evm-wallet';
import './styles/palette.css';
import './styles/typography.css';
import './styles/animations.css';
import './styles/synergy.css';
import './styles.css';
import './styles/monitor.css';
import './wallet-connection/components/wallet/wallet-connection.css';
import './styles/controlPanelRevamp.css';
import './styles/controlPanelV18.css';

const queryClient = new QueryClient();

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <WagmiProvider config={wagmiConfig}>
        <QueryClientProvider client={queryClient}>
          <RainbowKitProvider theme={relayRainbowTheme} modalSize="compact">
            <HashRouter>
              <App />
            </HashRouter>
          </RainbowKitProvider>
        </QueryClientProvider>
      </WagmiProvider>
    </AppErrorBoundary>
  </React.StrictMode>
);

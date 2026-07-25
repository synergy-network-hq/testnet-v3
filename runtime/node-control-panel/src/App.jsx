import { useEffect, useState } from 'react';
import StartupLoadingScreen from './components/StartupLoadingScreen';
import { ControlPanelProvider } from './components/control-panel/ControlPanelProvider';
import ControlPanelV18 from './components/control-panel-v18/ControlPanelV18';

const SPLASH_DURATION_MS = 4800;
const SPLASH_FADE_OUT_MS = 720;
const POST_SPLASH_FADE_IN_DELAY_MS = 80;

function App() {
  const [progress, setProgress] = useState(0);
  const [splashPhase, setSplashPhase] = useState('showing');
  const [postSplashVisible, setPostSplashVisible] = useState(false);

  useEffect(() => {
    let raf = null;
    let fadeTimer = null;
    const start = performance.now();

    const tick = (timestamp) => {
      const elapsed = timestamp - start;
      const ratio = Math.min(elapsed / SPLASH_DURATION_MS, 1);
      setProgress(Math.round(ratio * 100));
      if (ratio < 1) {
        raf = window.requestAnimationFrame(tick);
      } else {
        setSplashPhase('fading');
        fadeTimer = window.setTimeout(() => {
          setSplashPhase('hidden');
        }, SPLASH_FADE_OUT_MS);
      }
    };

    raf = window.requestAnimationFrame(tick);
    return () => {
      if (raf) window.cancelAnimationFrame(raf);
      if (fadeTimer) window.clearTimeout(fadeTimer);
    };
  }, []);

  useEffect(() => {
    if (splashPhase !== 'hidden') {
      setPostSplashVisible(false);
      return;
    }

    const timer = window.setTimeout(() => {
      setPostSplashVisible(true);
    }, POST_SPLASH_FADE_IN_DELAY_MS);

    return () => {
      window.clearTimeout(timer);
    };
  }, [splashPhase]);

  if (splashPhase !== 'hidden') {
    return <StartupLoadingScreen progress={progress} phase={splashPhase} />;
  }

  return (
    <div className={`app-post-splash ${postSplashVisible ? 'is-visible' : ''}`}>
      <ControlPanelProvider>
        <ControlPanelV18 />
      </ControlPanelProvider>
    </div>
  );
}

export default App;

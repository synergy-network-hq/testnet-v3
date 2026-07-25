import { controlPanelBannerSrc } from '../lib/runtimeAssets';

function StartupLoadingScreen({ progress, phase }) {
  const clamped = Math.max(0, Math.min(100, Number(progress || 0)));
  const showBrand = clamped >= 1 || phase === 'fading';
  const brandProgress = clamped;
  const fadeOut = phase === 'fading';

  return (
    <section className={`startup-splash ${fadeOut ? 'is-fading-out' : ''}`}>
      <div className={`startup-brand-stage ${showBrand ? 'show' : ''}`}>
        <div className="startup-logo-wrap">
          <img src={controlPanelBannerSrc} alt="Synergy Node Control Panel" className="startup-logo" />
        </div>
        <div className="startup-progress-wrap">
          <div className="startup-progress-track">
            <div className="startup-progress-fill" style={{ width: `${brandProgress}%` }} />
          </div>
          <p className="startup-progress-text">{Math.round(brandProgress)}%</p>
        </div>
      </div>
    </section>
  );
}

export default StartupLoadingScreen;

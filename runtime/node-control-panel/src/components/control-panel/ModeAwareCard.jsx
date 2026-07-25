import { useControlPanel } from './ControlPanelProvider';
import { PanelCard } from './ControlPanelShared';
import { isModeAtLeast } from './viewProfiles';

export default function ModeAwareCard({
  minimumMode = 'basic',
  modes = null,
  children,
  ...cardProps
}) {
  const { viewMode } = useControlPanel();

  if (Array.isArray(modes) && !modes.includes(viewMode)) {
    return null;
  }

  if (!isModeAtLeast(viewMode, minimumMode)) {
    return null;
  }

  return (
    <PanelCard {...cardProps}>
      {children}
    </PanelCard>
  );
}


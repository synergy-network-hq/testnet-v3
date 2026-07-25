import { useControlPanel } from './ControlPanelProvider';
import { isModeAtLeast } from './viewProfiles';

export default function ModeAwareSection({
  as: Component = 'section',
  minimumMode = 'basic',
  modes = null,
  className = '',
  children,
  ...props
}) {
  const { viewMode } = useControlPanel();

  if (Array.isArray(modes) && !modes.includes(viewMode)) {
    return null;
  }

  if (!isModeAtLeast(viewMode, minimumMode)) {
    return null;
  }

  return (
    <Component className={className} {...props}>
      {children}
    </Component>
  );
}


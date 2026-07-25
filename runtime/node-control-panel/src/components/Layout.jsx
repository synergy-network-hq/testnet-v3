import ControlPanelShell from './control-panel/ControlPanelShell';

function Layout({ children, onLaunchSetup }) {
  return (
    <ControlPanelShell onLaunchSetup={onLaunchSetup}>
      {children}
    </ControlPanelShell>
  );
}

export default Layout;

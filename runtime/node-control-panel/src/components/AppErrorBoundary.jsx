import React from 'react';

class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('Control panel renderer failed', error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    const detail = String(this.state.error?.message || 'The renderer stopped unexpectedly.').slice(0, 500);
    return (
      <main className="app-render-failure" role="alert">
        <div>
          <p className="app-render-failure__eyebrow">Renderer recovery</p>
          <h1>Control panel could not render</h1>
          <p>{detail}</p>
          <button type="button" onClick={() => window.location.reload()}>Reload control panel</button>
        </div>
      </main>
    );
  }
}

export default AppErrorBoundary;

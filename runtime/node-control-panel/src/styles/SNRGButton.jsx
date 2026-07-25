import React from 'react';
import './SNRGButtonEffects.css';

const VARIANT_CLASS_MAP = {
  blue: 'snrgfx-btn-blue',
  whitepaper: 'snrgfx-btn-whitepaper',
  cyan: 'snrgfx-btn-cyan',
  architecture: 'snrgfx-btn-architecture',
  yellow: 'snrgfx-btn-yellow',
  red: 'snrgfx-btn-red',
  purple: 'snrgfx-btn-purple',
  community: 'snrgfx-btn-community',
  lime: 'snrgfx-btn-lime',
  presale: 'snrgfx-btn-presale',
  green: 'snrgfx-btn-green',
  orange: 'snrgfx-btn-orange',
};

const SIZE_CLASS_MAP = {
  sm: 'snrgfx-btn-sm',
  md: 'snrgfx-btn-md',
  lg: 'snrgfx-btn-lg',
  hero: 'snrgfx-btn-hero',
};

function joinClasses(...classes) {
  return classes.filter(Boolean).join(' ').trim();
}

/**
 * Reusable Synergy CTA button.
 *
 * Copy this file with SNRGButtonEffects.css into another React project.
 * For plain HTML usage, apply the same CSS classes directly.
 */
export const SNRGButton = ({
  children,
  className = '',
  style = {},
  variant = 'blue',
  size = 'md',
  block = false,
  as: Component = 'button',
  type,
  ...props
}) => {
  const variantClass =
    VARIANT_CLASS_MAP[String(variant).toLowerCase()] || 'snrgfx-btn-blue';
  const sizeClass =
    SIZE_CLASS_MAP[String(size).toLowerCase()] || 'snrgfx-btn-md';
  const classes = joinClasses(
    'snrgfx-btn',
    variantClass,
    sizeClass,
    block && 'snrgfx-btn-block',
    className,
  );

  if (Component === 'button') {
    return (
      <button
        type={type || 'button'}
        className={classes}
        style={style}
        {...props}
      >
        {children}
      </button>
    );
  }

  return (
    <Component className={classes} style={style} {...props}>
      {children}
    </Component>
  );
};

export const SNRGButtonGrid = ({
  children,
  className = '',
  as: Component = 'div',
  ...props
}) => (
  <Component
    className={joinClasses('snrgfx-btn-grid-hero', className)}
    {...props}
  >
    {children}
  </Component>
);

export const WhitepaperButton = (props) => (
  <SNRGButton variant="whitepaper" {...props} />
);
export const ArchitectureButton = (props) => (
  <SNRGButton variant="architecture" {...props} />
);
export const CommunityButton = (props) => (
  <SNRGButton variant="community" {...props} />
);
export const PresaleButton = (props) => (
  <SNRGButton variant="presale" {...props} />
);

export default SNRGButton;

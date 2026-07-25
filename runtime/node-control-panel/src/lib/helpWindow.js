import { openHelpWindow as openDesktopHelpWindow } from './desktopClient';

const HELP_HASH_ROUTE = '/help';

function openHelpInCurrentWindow() {
  if (typeof window !== 'undefined') {
    window.location.hash = HELP_HASH_ROUTE;
  }
}

export async function openHelpWindow() {
  try {
    await openDesktopHelpWindow();
  } catch (error) {
    console.error('Help window open failed, falling back to current window help route:', error);
    openHelpInCurrentWindow();
  }
}

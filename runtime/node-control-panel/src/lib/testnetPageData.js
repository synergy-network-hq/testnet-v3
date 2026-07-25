import { invoke } from './desktopClient';

let cachedState = null;
let cachedLiveStatus = null;
let stateRequest = null;
let liveStatusRequest = null;

export function peekTestnetState() {
  return cachedState;
}

export function peekTestnetLiveStatus() {
  return cachedLiveStatus;
}

export function clearTestnetPageDataCache() {
  cachedState = null;
  cachedLiveStatus = null;
}

export async function fetchTestnetState(options = {}) {
  const { force = false } = options;
  if (stateRequest) {
    return stateRequest;
  }

  if (!force && cachedState) {
    return cachedState;
  }

  stateRequest = invoke('testnet_get_state')
    .then((value) => {
      cachedState = value;
      return value;
    })
    .finally(() => {
      stateRequest = null;
    });

  return stateRequest;
}

export async function fetchTestnetLiveStatus(options = {}) {
  const { force = false } = options;
  if (liveStatusRequest) {
    return liveStatusRequest;
  }

  if (!force && cachedLiveStatus) {
    return cachedLiveStatus;
  }

  liveStatusRequest = invoke('testnet_get_live_status')
    .then((value) => {
      cachedLiveStatus = value;
      return value;
    })
    .finally(() => {
      liveStatusRequest = null;
    });

  return liveStatusRequest;
}

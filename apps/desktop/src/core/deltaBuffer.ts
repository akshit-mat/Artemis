import { useStore } from '../state/store';

interface BufferedDelta {
  run_id: string;
  channel: string;
  text: string;
}

let buffer: BufferedDelta[] = [];
let pendingRAF: number | null = null;

let lastFlush = 0;

export function bufferDelta(runId: string, channel: string, text: string) {
  buffer.push({ run_id: runId, channel, text });
  if (pendingRAF === null) {
    pendingRAF = requestAnimationFrame(flushDeltas);
  }
}

function flushDeltas(timestamp: number) {
  const state = useStore.getState();
  const isBattery = state.isBattery;

  if (isBattery && timestamp - lastFlush < 33.3) {
    // Throttle to ~30fps on battery
    pendingRAF = requestAnimationFrame(flushDeltas);
    return;
  }

  lastFlush = timestamp;
  pendingRAF = null;
  if (buffer.length === 0) return;
  const currentBuffer = buffer;
  buffer = [];
  state.applyDeltas(currentBuffer);
}

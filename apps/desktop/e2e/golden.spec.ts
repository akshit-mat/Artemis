import { test, expect } from '@playwright/test';
import { WebSocketServer } from 'ws';

test('Golden Path E2E', async ({ page }) => {
  let wss: WebSocketServer;
  let port = 0;
  let clientSocket: import('ws').WebSocket | null = null;
  let runId = 'r_123';
  let seq = 0;

  // 1. Setup Mock WS Server
  await new Promise<void>((resolve) => {
    wss = new WebSocketServer({ port: 0 }, () => {
      port = (wss.address() as any).port;
      resolve();
    });
  });

  wss.on('connection', (ws) => {
    clientSocket = ws;
    ws.on('message', (msg) => {
      const data = JSON.parse(msg.toString());
      if (data.type === 'client.hello') {
        // Send session.ready
        ws.send(JSON.stringify({
          v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'session.ready', session_id: 's_test',
          data: {
            last_seq: seq,
            assistant_state: { state: 'IDLE', intensity: 0 },
            model: { id: 'test' },
            pending_approvals: []
          }
        }));
      } else if (data.type === 'chat.send') {
        // Simulate backend processing
        ws.send(JSON.stringify({
          v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'agent.state', session_id: 's_test', run_id: runId,
          data: { state: 'THINKING', intensity: 1, run_id: runId }
        }));

        setTimeout(() => {
          ws.send(JSON.stringify({
            v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'agent.state', session_id: 's_test', run_id: runId,
            data: { state: 'RESPONDING', intensity: 1, run_id: runId }
          }));

          ws.send(JSON.stringify({
            v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'agent.delta', session_id: 's_test', run_id: runId,
            data: { channel: 'content', text: 'Hello from mock server!' }
          }));
        }, 100);
      } else if (data.type === 'run.cancel') {
        // Simulate cancel
        ws.send(JSON.stringify({
          v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'agent.error', session_id: 's_test', run_id: runId,
          data: { code: 'CANCELLED', message: 'User cancelled', recoverable: false, correlation_id: runId }
        }));
        setTimeout(() => {
          ws.send(JSON.stringify({
            v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'agent.state', session_id: 's_test', run_id: runId,
            data: { state: 'IDLE', intensity: 0, run_id: runId }
          }));
        }, 500);
      }
    });
  });

  // Mock Tauri APIs
  await page.addInitScript(`
    window.__TAURI_INTERNALS__ = {
      invoke: (cmd, args) => {
        if (cmd === 'get_backend_handle') {
          return Promise.resolve({ port: ${port}, token: 'mock-token', origin: 'http://tauri.localhost' });
        }
        return Promise.resolve();
      }
    };
    window.__TAURI__ = {};
  `);

  // Load App
  await page.goto('/');

  // Wait for connection to establish and UI to reflect IDLE
  await expect(page.locator('text=IDLE').first()).toBeVisible();

  // Send message
  await page.fill('input[type="text"]', 'Hello');
  await page.keyboard.press('Enter');

  // Verify state transitions
  await expect(page.locator('text=THINKING').first()).toBeVisible();
  await expect(page.locator('text=RESPONDING').first()).toBeVisible();

  // Verify streamed content appears
  await expect(page.locator('text=Hello from mock server!')).toBeVisible();

  // Verify Stop button appears
  const stopButton = page.locator('#stop-generation');
  await expect(stopButton).toBeVisible();

  // Click Stop
  await stopButton.click();

  // Verify cancelled and back to IDLE
  await expect(page.locator('text="CANCELLED"')).toBeVisible();
  await expect(page.locator('text=IDLE').first()).toBeVisible();

  // Open Command Palette
  await page.keyboard.press('Control+k');
  await expect(page.locator('input[placeholder="Type a command or search..."]')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('input[placeholder="Type a command or search..."]')).not.toBeVisible();

  wss.close();
});

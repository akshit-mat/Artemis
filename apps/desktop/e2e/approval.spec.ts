import { test, expect } from '@playwright/test';
import { WebSocketServer } from 'ws';

test('Approval Lifecycle E2E', async ({ page }) => {
  let wss: WebSocketServer;
  let port = 0;
  let clientSocket: import('ws').WebSocket | null = null;
  let runId = 'r_approval_123';
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
        ws.send(JSON.stringify({
          v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'agent.state', session_id: 's_test', run_id: runId,
          data: { state: 'THINKING', intensity: 1, run_id: runId }
        }));
        
        // Simulate tool request
        setTimeout(() => {
          ws.send(JSON.stringify({
            v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'tool.requested', session_id: 's_test', run_id: runId,
            data: { call_id: 'call_1', tool: 'write_file', category: 'fs', risk: 'moderate', args_preview: 'C:\\test.txt', targets: ['C:\\test.txt'], item_count: 1, taint: false }
          }));
          
          ws.send(JSON.stringify({
            v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'tool.decision', session_id: 's_test', run_id: runId,
            data: { call_id: 'call_1', decision: 'ask', rule_id: 'ask_all', reason: 'Requires user approval' }
          }));
          
          ws.send(JSON.stringify({
            v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'approval.requested', session_id: 's_test', run_id: runId,
            data: { id: 'appr_1', run_id: runId, tool_name: 'write_file', action_text: 'Write to C:\\test.txt', targets: ['C:\\test.txt'], risk: 'moderate', batch_count: 1 }
          }));
        }, 100);
      }
    });
  });

  // Mock Tauri APIs
  await page.addInitScript(`
    window.__TAURI_INTERNALS__ = {
      transformCallback: (callback) => {
        return window.crypto.getRandomValues(new Uint32Array(1))[0];
      },
      invoke: (cmd, args) => {
        if (cmd === 'get_backend_handle') {
          return Promise.resolve({ port: ${port}, token: 'mock-token', origin: 'http://tauri.localhost' });
        }
        return Promise.resolve();
      }
    };
    window.__TAURI__ = {};
  `);

  page.on('console', msg => console.log(msg.text()));

  // Mock global fetch for approval resolution
  await page.route('**/v1/approvals/appr_1', async route => {
    console.log('Intercepted:', route.request().method(), route.request().url());
    if (route.request().method() === 'OPTIONS') {
      await route.fulfill({
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        }
      });
      return;
    }
    if (route.request().method() === 'POST') {
      const postData = JSON.parse(route.request().postData() || '{}');
      console.log('POST DATA:', postData);
      if (postData.decision && postData.decision.toLowerCase() === 'allow') {
        clientSocket?.send(JSON.stringify({
          v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'approval.resolved', session_id: 's_test', run_id: runId,
          data: { id: 'appr_1', decision: 'ALLOW' }
        }));
        
        clientSocket?.send(JSON.stringify({
          v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'tool.started', session_id: 's_test', run_id: runId,
          data: { call_id: 'call_1' }
        }));
        
        setTimeout(() => {
          clientSocket?.send(JSON.stringify({
            v: 1, seq: ++seq, ts: new Date().toISOString(), type: 'tool.result', session_id: 's_test', run_id: runId,
            data: { call_id: 'call_1', status: 'ok', summary: 'File written', result_id: 'res_1', duration_ms: 10, truncated: false, undo_available: false, error_code: null }
          }));
        }, 50);
      }
      await route.fulfill({
        status: 200,
        headers: { 'Access-Control-Allow-Origin': '*' },
        json: { id: 'appr_1', decision: 'ALLOW' }
      });
    } else {
      await route.continue();
    }
  });

  // Load App
  await page.goto('/');

  // Wait for connection to establish
  await expect(page.locator('text=IDLE').first()).toBeVisible();

  // Send message to trigger tool
  await page.fill('input[type="text"]', 'Write a file');
  await page.keyboard.press('Enter');

  // Verify approval card appears
  await expect(page.locator('text=Requires Approval')).toBeVisible();
  await expect(page.locator('text=Write to C:\\test.txt')).toBeVisible();

  // Verify Deny button is immediately available
  const denyButton = page.locator('button:has-text("Deny")');
  await expect(denyButton).toBeVisible();
  await expect(denyButton).toBeEnabled();

  // Verify Allow Once button enforces 400ms delay
  const allowOnceButton = page.locator('button:has-text("Wait...")');
  await expect(allowOnceButton).toBeVisible();
  await expect(allowOnceButton).toBeDisabled();

  // Wait 500ms for arm delay
  await page.waitForTimeout(500);

  const armedButton = page.locator('button:has-text("Allow Once")');
  await expect(armedButton).toBeVisible();
  await expect(armedButton).toBeEnabled();

  // Click Allow Once
  await armedButton.click();

  // Verify the button disappears (meaning fetch succeeded and resolved event came)
  await expect(armedButton).not.toBeVisible();

  // Verify tool completion
  await expect(page.locator('text=File written')).toBeVisible();

  wss.close();
});

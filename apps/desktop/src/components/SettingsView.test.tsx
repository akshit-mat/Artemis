import { render, screen, fireEvent } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { SettingsView } from './SettingsView';
import { useStore } from '../state/store';

// Mock fetch
const originalFetch = global.fetch;

test('SettingsView handles roots and grants', async () => {
  global.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({
      grants: [{ id: 'g1', action_text: 'Read files', tool_name: 'read_file', scope_type: 'always' }],
      allow_roots: ['C:\\Test']
    })
  });

  useStore.setState({
    backendConfig: { port: 8080, token: 'test-token', tokenSet: true, origin: 'http://localhost' }
  });

  render(<SettingsView />);

  // Should fetch and display grants
  expect(await screen.findByText('Read files')).toBeDefined();
  
  // Should fetch and display roots
  expect(await screen.findByText('C:\\Test')).toBeDefined();

  global.fetch = originalFetch;
});

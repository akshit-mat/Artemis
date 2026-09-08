import { render, screen, fireEvent, act } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { CardStream } from './CardStream';
import { useStore } from '../state/store';

test('ApprovalCard enforces 400ms arm delay and risk conditions', async () => {
  vi.useFakeTimers();

  useStore.setState({
    cardIds: ['1'],
    cards: {
      '1': {
        id: '1',
        type: 'approval',
        tool_name: 'delete_file',
        action_text: 'Delete C:\\secret.txt',
        risk: 'destructive'
      }
    }
  });

  render(<CardStream />);

  // Should render 'Wait...' initially
  expect(screen.getAllByText('Wait...')[0]).toBeDefined();
  
  // 'Allow Always' should NOT be present for destructive
  expect(screen.queryByText('Allow Always')).toBeNull();

  act(() => {
    vi.advanceTimersByTime(400);
  });

  // After 400ms it should arm
  expect(screen.getAllByText('Allow Once')[0]).toBeDefined();
  
  vi.useRealTimers();
});

test('ApprovalCard offers Always for non-destructive', async () => {
  vi.useFakeTimers();
  
  useStore.setState({
    cardIds: ['2'],
    cards: {
      '2': {
        id: '2',
        type: 'approval',
        tool_name: 'read_file',
        action_text: 'Read log',
        risk: 'read_only' // non-destructive
      }
    }
  });

  render(<CardStream />);
  act(() => {
    vi.advanceTimersByTime(400);
  });

  expect(screen.getAllByText('Allow Always')[0]).toBeDefined();
  
  vi.useRealTimers();
});

test('ToolCard renders denial state correctly', () => {
  useStore.setState({
    cardIds: ['3'],
    cards: {
      '3': {
        id: '3',
        type: 'denial',
        tool_name: 'evil_tool',
        tool_state: 'denied',
        reason: 'Policy restriction'
      }
    }
  });

  render(<CardStream />);
  
  expect(screen.getAllByText(/evil_tool/)[0]).toBeDefined();
  expect(screen.getAllByText(/\[DENIED\]/)[0]).toBeDefined();
  expect(screen.getAllByText(/Policy restriction/)[0]).toBeDefined();
});

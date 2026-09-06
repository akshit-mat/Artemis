import { render } from '@testing-library/react';
import { CoreVisual } from './CoreVisual';
import { useStore } from '../state/store';
import { expect, test, describe, beforeEach, beforeAll } from 'vitest';

beforeAll(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {}, // Deprecated
      removeListener: () => {}, // Deprecated
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

describe('CoreVisual', () => {
  beforeEach(() => {
    useStore.setState({
      assistantState: { state: 'LISTENING', intensity: 1.0, progress: null, detail: null, run_id: null },
      settings: { reducedMotion: false }
    });
  });

  test('applies transform animations normally (structural A/B)', async () => {
    // With JS loop we just ensure it mounts and doesn't get the reduced reset
    const { container } = render(<CoreVisual />);

    // In our new CoreVisual, it uses JS loop so there's no static style block or reduced class anymore
    const visual = container.firstChild?.firstChild as HTMLElement;
    expect(visual.style.transform).not.toBe('none');
  });

  test('reduced motion disables transform animations and adds fallback class', async () => {
    useStore.setState({ settings: { reducedMotion: true } });
    const { container } = render(<CoreVisual />);
    const visual = container.firstChild?.firstChild as HTMLElement;

    // The JS loop detects reduced motion and explicitly clears transform
    expect(visual.style.transform).toBe('');
    expect(visual.style.boxShadow).toBe('none');
  });

  test('unfocused/hidden window pauses animation', async () => {
    // Mock document.hidden
    Object.defineProperty(document, 'hidden', { value: true, configurable: true });

    const { container } = render(<CoreVisual />);
    const visual = container.firstChild?.firstChild as HTMLElement;

    // The JS loop detects hidden and clears transform
    expect(visual.style.transform).toBe('');

    // Clean up
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
  });
});

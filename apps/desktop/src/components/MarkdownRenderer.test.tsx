import { render } from '@testing-library/react';
import { MarkdownRenderer } from './MarkdownRenderer';
import { expect, test } from 'vitest';

test('MarkdownRenderer sanitizes HTML', () => {
  const { container } = render(<MarkdownRenderer content="<div class='test'>Hello</div><script>alert(1)</script>" />);
  expect(container.innerHTML).not.toContain('<script>');
  expect(container.textContent).toContain('Hello');
});

test('MarkdownRenderer blocks js URLs', () => {
  const { container } = render(<MarkdownRenderer content="[Click me](javascript:alert(1))" />);
  const html = container.innerHTML;
  expect(html).not.toContain('javascript:');
});

test('MarkdownRenderer blocks remote images', () => {
  const { container } = render(<MarkdownRenderer content="![Evil](https://evil.com/img.png)" />);
  const html = container.innerHTML;
  expect(html).not.toContain('img');
  expect(html).not.toContain('https://evil.com/img.png');
});

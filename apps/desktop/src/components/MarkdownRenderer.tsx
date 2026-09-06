import { useMemo } from 'react';
import { marked } from 'marked';
import DOMPurify from 'dompurify';

interface MarkdownRendererProps {
  content: string;
}

export function MarkdownRenderer({ content }: MarkdownRendererProps) {
  const html = useMemo(() => {
    const rawHtml = marked.parse(content, { async: false }) as string;

    // Strict sanitization:
    // - No script (DOMPurify default)
    // - No external images
    // - No arbitrary HTML risks
    return DOMPurify.sanitize(rawHtml, {
      FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'img', 'video', 'audio'],
      FORBID_ATTR: ['onerror', 'onload', 'onmouseover', 'style'],
      ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i // DOMPurify default, but javascript: is inherently blocked
    });
  }, [content]);

  return (
    <div
      className="markdown-body"
      style={{ lineHeight: 1.6, overflowWrap: 'break-word' }}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

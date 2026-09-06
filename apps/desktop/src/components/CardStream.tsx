import { useEffect, useRef } from 'react';
import { useStore, Card } from '../state/store';
import { MarkdownRenderer } from './MarkdownRenderer';

function MessageCard({ card }: { card: Card }) {
  const isAssistant = card.role === 'assistant';
  return (
    <div style={{
      marginBottom: '1rem',
      padding: '1rem',
      borderRadius: '8px',
      backgroundColor: isAssistant ? '#2d2d30' : '#1e1e1e',
      borderLeft: isAssistant ? '4px solid #007acc' : '4px solid #4caf50',
      color: '#d4d4d4',
      fontFamily: 'sans-serif'
    }}>
      <div style={{ fontSize: '0.8rem', color: '#888', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
        {card.role}
      </div>
      {card.reasoning && (
        <div style={{
          marginBottom: '1rem',
          padding: '0.75rem',
          backgroundColor: '#1e1e1e',
          borderLeft: '2px solid #569cd6',
          fontFamily: 'monospace',
          fontSize: '0.9em',
          color: '#9cdcfe',
          whiteSpace: 'pre-wrap'
        }}>
          {card.reasoning}
        </div>
      )}
      <MarkdownRenderer content={card.content} />
    </div>
  );
}

function FallbackCard({ card }: { card: Card }) {
  return (
    <div style={{ marginBottom: '1rem', padding: '1rem', backgroundColor: '#333', color: '#ccc' }}>
      [{card.type.toUpperCase()}] Not fully implemented in Phase 3 UX yet.
    </div>
  );
}

function CardRenderer({ card }: { card: Card }) {
  switch (card.type) {
    case 'message':
      return <MessageCard card={card} />;
    default:
      return <FallbackCard card={card} />;
  }
}

export function CardStream() {
  const cards = useStore(state => state.cards);
  const cardIds = useStore(state => state.cardIds);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [cardIds, cards]);

  return (
    <div
      ref={scrollRef}
      style={{
        flex: 1,
        overflowY: 'auto',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column'
      }}
    >
      {cardIds.map(id => (
        <CardRenderer key={id} card={cards[id]} />
      ))}
    </div>
  );
}

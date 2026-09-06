import { useEffect, useState, useRef } from 'react';
import { useStore } from '../state/store';

export function CoreVisual() {
  const assistantState = useStore(state => state.assistantState);
  const settings = useStore(state => state.settings);
  const [isVisible, setIsVisible] = useState(!document.hidden);
  const [isBattery, setIsBattery] = useState(false);
  const [prefersReduced, setPrefersReduced] = useState(false);

  const visualRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReduced(mediaQuery.matches);
    const handler = (e: MediaQueryListEvent) => setPrefersReduced(e.matches);
    mediaQuery.addEventListener('change', handler);
    return () => mediaQuery.removeEventListener('change', handler);
  }, []);

  useEffect(() => {
    const handleVisibilityChange = () => setIsVisible(!document.hidden);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, []);

  useEffect(() => {
    let batteryObj: any;
    const updateBattery = () => {
      if (batteryObj) {
        setIsBattery(!batteryObj.charging && batteryObj.level < 1.0);
      }
    };
    if ('getBattery' in navigator) {
      (navigator as any).getBattery().then((b: any) => {
        batteryObj = b;
        updateBattery();
        b.addEventListener('chargingchange', updateBattery);
        b.addEventListener('levelchange', updateBattery);
      });
    }
    return () => {
      if (batteryObj) {
        batteryObj.removeEventListener('chargingchange', updateBattery);
        batteryObj.removeEventListener('levelchange', updateBattery);
      }
    };
  }, []);

  const state = assistantState?.state || 'IDLE';
  const intensity = assistantState?.intensity || 0;
  const progress = assistantState?.progress || 0;

  const shouldAnimate = isVisible;
  const isReduced = settings.reducedMotion || prefersReduced;

  useEffect(() => {
    const el = visualRef.current;
    if (!el) return;

    if (!shouldAnimate || isReduced) {
      el.style.transform = '';
      el.style.opacity = '1';
      el.style.boxShadow = 'none';
      return;
    }

    let rafId: number;
    let lastTime = 0;

    // Genuine update throttle via requestAnimationFrame
    const loop = (time: number) => {
      rafId = requestAnimationFrame(loop);

      // Real battery 30 FPS throttle logic
      if (isBattery && time - lastTime < 33.3) {
        return;
      }
      lastTime = time;

      const t = time / 1000;

      if (state === 'IDLE') {
        const p = Math.sin(t * Math.PI * 0.5) * 0.5 + 0.5;
        el.style.opacity = (0.6 + p * 0.4).toString();
        el.style.transform = `scale(${0.98 + p * 0.04})`;
      } else if (state === 'LISTENING') {
        const p = (t % 1.0);
        el.style.boxShadow = `0 0 0 ${p * 20}px rgba(0, 188, 212, ${0.7 - p * 0.7})`;
        el.style.transform = `scale(${1 + intensity * 0.2})`;
      } else if (state === 'THINKING') {
        const p = Math.sin(t * Math.PI / 0.6) * 0.5 + 0.5;
        el.style.transform = `scale(${0.9 + p * 0.2})`;
        el.style.opacity = (0.5 + p * 0.5).toString();
      } else if (state === 'RESPONDING') {
        const duration = Math.max(0.3, 1.5 - intensity * 1.2);
        const p = Math.sin(t * Math.PI * 2 / duration) * 0.5 + 0.5;
        el.style.opacity = (0.8 + p * 0.2).toString();
        el.style.boxShadow = `0 0 ${10 + p * 10}px #f5f5f5`;
      } else if (state === 'SEARCHING') {
        const angle = (t * 180) % 360;
        el.style.transform = `rotate(${angle}deg) translateX(5px) rotate(-${angle}deg)`;
      } else if (state === 'ERROR') {
         // static
      }
    };

    rafId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafId);
  }, [shouldAnimate, isReduced, isBattery, state, intensity]);

  let color = '#555';
  let border = 'none';

  if (state === 'IDLE') color = '#888';
  else if (state === 'LISTENING') color = '#00bcd4';
  else if (state === 'THINKING') color = '#3f51b5';
  else if (state === 'RESPONDING') color = '#f5f5f5';
  else if (state === 'SEARCHING') color = '#009688';
  else if (state === 'EXECUTING') color = 'transparent';
  else if (state === 'WAITING_FOR_APPROVAL') {
    color = '#ff9800';
    border = '4px solid #fff';
  }
  else if (state === 'SPEAKING') color = 'transparent';
  else if (state === 'ERROR') color = '#f44336';
  else if (state === 'OFFLINE') color = '#606060';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '1rem' }}>
      <div
        ref={visualRef}
        style={{
          width: '40px',
          height: '40px',
          borderRadius: '50%',
          backgroundColor: color,
          border,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transition: 'background-color 0.3s ease, border 0.3s ease',
          willChange: 'transform, opacity, box-shadow'
        }}
      >
        {state === 'EXECUTING' && (
          <svg width="40" height="40" viewBox="0 0 40 40">
            {Array.from({ length: 12 }).map((_, i) => {
               const active = (i / 11) <= progress;
               return (
                 <rect
                   key={i}
                   x="18" y="2" width="4" height="6"
                   fill={active ? "#ffc107" : "#333"}
                   rx="1"
                   transform={`rotate(${i * 30} 20 20)`}
                   style={{ transition: 'fill 0.2s ease' }}
                 />
               );
            })}
          </svg>
        )}

        {state === 'SPEAKING' && (
          <svg width="30" height="30" viewBox="0 0 30 30">
             {/*
                Waveform structure structurally prepared for real RMS data [left, center, right]
                For Phase 3, we use the scalar intensity as a fallback amplitude driver
                to visually differentiate the bands.
             */}
             <rect x="4" y={15 - (intensity * 6)} width="4" height={Math.max(2, intensity * 12)} fill="#9c27b0" rx="2" style={{ transition: 'all 0.1s' }} />
             <rect x="13" y={15 - (intensity * 10)} width="4" height={Math.max(2, intensity * 20)} fill="#9c27b0" rx="2" style={{ transition: 'all 0.1s' }} />
             <rect x="22" y={15 - (intensity * 4)} width="4" height={Math.max(2, intensity * 8)} fill="#9c27b0" rx="2" style={{ transition: 'all 0.1s' }} />
          </svg>
        )}
      </div>
      <div style={{ marginTop: '0.5rem', fontSize: '0.7rem', color: '#888', textTransform: 'uppercase' }}>
        {state}
      </div>
    </div>
  );
}

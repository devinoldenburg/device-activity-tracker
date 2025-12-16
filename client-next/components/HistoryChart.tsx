"use client";

import { useMemo, useState } from 'react';
import { ResponsiveContainer, LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, Scatter } from 'recharts';
import { TrackerData } from '@/lib/types';

interface HistoryChartProps {
  data: TrackerData[];
}

export function HistoryChart({ data }: HistoryChartProps) {
  const [fullscreen, setFullscreen] = useState(false);

  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  const filtered = useMemo(() => data.filter(point => point.timestamp >= oneHourAgo), [data, oneHourAgo]);

  const mapWithColors = useCallbackData(filtered);
  const mappedFull = useCallbackData(data);

  const fullWidth = Math.max(2400, mappedFull.length * 28);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">RTT Verlauf</p>
          <p className="text-sm text-slate-600">Letzte Stunde mit Schwelle und Zuständen</p>
        </div>
        <button
          onClick={() => setFullscreen(true)}
          className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-900 text-white hover:bg-black transition"
        >
          Vollbild
        </button>
      </div>
      <div style={{ width: '100%', height: 300 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={mapWithColors}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
            <XAxis dataKey="timestamp" tickFormatter={(t) => new Date(t).toLocaleTimeString()} minTickGap={48} />
            <YAxis domain={['auto', 'auto']} />
            <Tooltip labelFormatter={(t: number) => new Date(t).toLocaleString()} />
            <Line type="monotone" dataKey="avg" stroke="#0ea5e9" strokeWidth={2} dot={false} name="Avg RTT" isAnimationActive={false} />
            <Line type="step" dataKey="threshold" stroke="#ef4444" strokeDasharray="4 4" dot={false} name="Threshold" isAnimationActive={false} />
            <Scatter data={mapWithColors} shape={(props: any) => {
              const color = props?.payload?.stateColor || '#94a3b8';
              return <circle cx={props.cx} cy={props.cy} r={3} fill={color} />;
            }} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {fullscreen && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-stretch justify-stretch">
          <div className="bg-white w-full h-full flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200">
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Vollbild</p>
                <p className="text-sm text-slate-600">Alle Messpunkte, horizontal scrollen für mehr</p>
              </div>
              <button
                onClick={() => setFullscreen(false)}
                className="px-3 py-1.5 text-sm font-semibold rounded-lg bg-slate-900 text-white hover:bg-black transition"
              >
                Schließen
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4">
              <div style={{ width: fullWidth, minHeight: 520 }}>
                <ResponsiveContainer width="100%" height={520}>
                  <LineChart data={mappedFull}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                    <XAxis dataKey="timestamp" tickFormatter={(t) => new Date(t).toLocaleString()} minTickGap={64} />
                    <YAxis domain={['auto', 'auto']} />
                    <Tooltip labelFormatter={(t: number) => new Date(t).toLocaleString()} />
                    <Line type="monotone" dataKey="avg" stroke="#0ea5e9" strokeWidth={2} dot={false} name="Avg RTT" isAnimationActive={false} />
                    <Line type="step" dataKey="threshold" stroke="#ef4444" strokeDasharray="4 4" dot={false} name="Threshold" isAnimationActive={false} />
                    <Scatter data={mappedFull} shape={(props: any) => {
                      const color = props?.payload?.stateColor || '#94a3b8';
                      return <circle cx={props.cx} cy={props.cy} r={3} fill={color} />;
                    }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function useCallbackData(points: TrackerData[]) {
  return useMemo(() => points.map(point => ({
    ...point,
    stateColor: point.state === 'OFFLINE'
      ? '#ef4444'
      : (point.state || '').includes('Online')
        ? '#10b981'
        : point.state === 'Standby'
          ? '#f59e0b'
          : '#94a3b8'
  })), [points]);
}

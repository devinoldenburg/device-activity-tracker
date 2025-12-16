"use client";

import { createContext, ReactNode, useContext } from 'react';
import { useTrackerData } from '@/hooks/useTrackerData';

const TrackerContext = createContext<ReturnType<typeof useTrackerData> | null>(null);

export function TrackerProvider({ children }: { children: ReactNode }) {
  const tracker = useTrackerData();
  return <TrackerContext.Provider value={tracker}>{children}</TrackerContext.Provider>;
}

export function useTracker() {
  const ctx = useContext(TrackerContext);
  if (!ctx) throw new Error('useTracker must be used inside TrackerProvider');
  return ctx;
}

"use client";

import './globals.css';
import { ReactNode } from 'react';
import { SideNav } from '@/components/SideNav';
import { TrackerProvider } from '@/components/TrackerProvider';

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="de">
      <body className="antialiased text-slate-900">
        <div className="flex min-h-screen">
          <SideNav />
          <div className="flex-1 overflow-hidden">
            <TrackerProvider>
              {children}
            </TrackerProvider>
          </div>
        </div>
      </body>
    </html>
  );
}

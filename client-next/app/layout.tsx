"use client";

import './globals.css';
import { ReactNode, useEffect } from 'react';
import { usePathname } from 'next/navigation';
import { SideNav } from '@/components/SideNav';
import { TrackerProvider } from '@/components/TrackerProvider';
import { AuthProvider, useAuth } from '@/components/AuthProvider';
import { AuthGate } from '@/components/AuthGate';

function AppShell({ children }: { children: ReactNode }) {
  const { user } = useAuth();

  // Suppress React 19 dev warning from Recharts defaultProps until upstream fixes
  useEffect(() => {
    const originalError = console.error;
    console.error = (...args: any[]) => {
      const first = args[0];
      if (typeof first === 'string' && first.includes('Support for defaultProps will be removed from function components')) {
        return;
      }
      originalError(...args);
    };
    return () => {
      console.error = originalError;
    };
  }, []);

  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <SideNav />
      <div className="flex-1 overflow-hidden">
        <TrackerProvider enabled={Boolean(user)}>
          {children}
        </TrackerProvider>
      </div>
    </div>
  );
}

export default function RootLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const isAuthRoute = pathname?.startsWith('/auth');

  return (
    <html lang="de">
      <body className="antialiased text-slate-900">
        <AuthProvider>
          {isAuthRoute ? (
            <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
              {children}
            </div>
          ) : (
            <AuthGate>
              <AppShell>{children}</AppShell>
            </AuthGate>
          )}
        </AuthProvider>
      </body>
    </html>
  );
}

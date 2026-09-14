import { ArrowDownLeft, ArrowUpRight, Settings, Wallet } from 'lucide-react';
import type { ReactNode } from 'react';
import { NavLink } from 'react-router';

import { cn } from '../utils/cn';

/**
 * The tab bar, along the bottom, in MyMonero's shape. See `NOTICE`.
 *
 * Four destinations and no more, because the wallet has four things it does.
 * A tab is a `NavLink`, so the route is the state: reloading the page comes
 * back to the same screen, and a browser's own back button works on it.
 */
const TABS = [
  { to: '/wallet', label: 'Wallet', icon: Wallet, testId: 'tab-balance' },
  { to: '/send', label: 'Send', icon: ArrowUpRight, testId: 'tab-send' },
  { to: '/receive', label: 'Receive', icon: ArrowDownLeft, testId: 'tab-receive' },
  { to: '/settings', label: 'Settings', icon: Settings, testId: 'tab-settings' },
] as const;

export function TabBar(): ReactNode {
  return (
    <nav
      aria-label="Wallet"
      className="fixed inset-x-0 bottom-0 z-30 border-t border-edge bg-deep/95 backdrop-blur"
    >
      <ul className="mx-auto flex w-full max-w-[var(--shell-width)] list-none p-0">
        {TABS.map((tab) => (
          <li key={tab.to} className="flex-1">
            <NavLink
              to={tab.to}
              data-testid={tab.testId}
              className={({ isActive }): string =>
                cn(
                  'flex h-14 flex-col items-center justify-center gap-1 text-label uppercase',
                  'tracking-label transition-colors',
                  isActive ? 'text-accent' : 'text-muted hover:text-ink',
                )
              }
            >
              <tab.icon className="size-4" aria-hidden />
              {tab.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}

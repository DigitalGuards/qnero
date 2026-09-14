/**
 * A hash router.
 *
 * The fragment keeps every route inside one document, so the built directory
 * is servable by anything that can serve files and needs no rewrite rule to
 * survive a refresh or a pasted link.
 */

import { useEffect, useState } from 'react';

export type Route =
  | { name: 'home' }
  | { name: 'blocks'; before: number | null }
  | { name: 'block'; id: string }
  | { name: 'settlement'; hash: string; at: string | null }
  | { name: 'search'; query: string }
  | { name: 'reveals' }
  | { name: 'notFound'; path: string };

export function parseRoute(fragment: string): Route {
  const raw = fragment.replace(/^#/, '');
  const [path = '', queryString = ''] = raw.split('?');
  const params = new URLSearchParams(queryString);
  const parts = path.split('/').filter((part) => part.length > 0);
  const [head, second] = parts;
  if (head === undefined || head === '') {
    return { name: 'home' };
  }
  if (head === 'blocks') {
    const before = params.get('before');
    return { name: 'blocks', before: before === null ? null : Number(before) };
  }
  if (head === 'block' && second !== undefined) {
    return { name: 'block', id: second };
  }
  if (head === 'settlement' && second !== undefined) {
    return { name: 'settlement', hash: second, at: params.get('at') };
  }
  if (head === 'search') {
    return { name: 'search', query: params.get('q') ?? '' };
  }
  if (head === 'reveals') {
    return { name: 'reveals' };
  }
  return { name: 'notFound', path };
}

export function href(route: Route): string {
  switch (route.name) {
    case 'home':
      return '#/';
    case 'blocks':
      return route.before === null ? '#/blocks' : `#/blocks?before=${route.before}`;
    case 'block':
      return `#/block/${route.id}`;
    case 'settlement':
      return route.at === null
        ? `#/settlement/${route.hash}`
        : `#/settlement/${route.hash}?at=${route.at}`;
    case 'search':
      return route.query === '' ? '#/search' : `#/search?q=${encodeURIComponent(route.query)}`;
    case 'reveals':
      return '#/reveals';
    case 'notFound':
      return '#/';
  }
}

export function navigate(route: Route): void {
  window.location.hash = href(route).slice(1);
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));
  useEffect(() => {
    const onChange = (): void => {
      setRoute(parseRoute(window.location.hash));
      window.scrollTo(0, 0);
    };
    window.addEventListener('hashchange', onChange);
    return () => {
      window.removeEventListener('hashchange', onChange);
    };
  }, []);
  return route;
}

import express from 'express';
import type { Request, Response } from 'express';
import dns, { Resolver } from 'node:dns/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface HopRecord {
  step: number;
  url: string;
  statusCode: number;
  location?: string;
  contentType?: string;
  latencyMs: number;
}

function isPrivateOrReservedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    if (
      normalized === '::1' ||
      normalized === '::' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe80') ||
      normalized.startsWith('::ffff:127.') ||
      normalized.startsWith('::ffff:10.') ||
      normalized.startsWith('::ffff:192.168.')
    ) {
      return true;
    }
    return false;
  }
  return true;
}

async function validatePublicHostname(hostname: string): Promise<{ safe: boolean; reason?: string }> {
  const cleanHost = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (
    cleanHost === 'localhost' ||
    cleanHost.endsWith('.localhost') ||
    cleanHost.endsWith('.local') ||
    cleanHost.endsWith('.internal')
  ) {
    return { safe: false, reason: 'Blocked local/internal hostname (SSRF protection).' };
  }

  if (net.isIP(cleanHost)) {
    if (isPrivateOrReservedIp(cleanHost)) {
      return { safe: false, reason: `Blocked private/loopback IP ${cleanHost} (SSRF protection).` };
    }
    return { safe: true };
  }

  try {
    const addresses = await dns.lookup(cleanHost, { all: true });
    if (addresses.length === 0) {
      return { safe: false, reason: 'DNS lookup returned no records.' };
    }
    for (const entry of addresses) {
      if (isPrivateOrReservedIp(entry.address)) {
        return { safe: false, reason: `Hostname resolves to private IP ${entry.address} (SSRF protection).` };
      }
    }
    return { safe: true };
  } catch {
    return { safe: false, reason: 'Domain unreachable or NXDOMAIN during live DNS resolution.' };
  }
}

async function probeThreatBlockingDns(): Promise<{
  reachable: boolean;
  latencyMs: number | null;
  resolver: string;
}> {
  const resolver = new Resolver({ timeout: 2200, tries: 1 });
  resolver.setServers(['1.1.1.2', '9.9.9.9']);
  const start = Date.now();
  try {
    const records = await resolver.resolve4('cloudflare-dns.com');
    const latencyMs = Math.max(1, Date.now() - start);
    return {
      reachable: records.length > 0,
      latencyMs,
      resolver: '1.1.1.2',
    };
  } catch {
    // Fallback check against system resolver if UDP 53 to public resolvers is egress-restricted
    const fallbackStart = Date.now();
    try {
      const sysRecords = await dns.lookup('cloudflare-dns.com');
      return {
        reachable: Boolean(sysRecords.address),
        latencyMs: Math.max(1, Date.now() - fallbackStart),
        resolver: 'system-dns',
      };
    } catch {
      return { reachable: false, latencyMs: null, resolver: '1.1.1.2' };
    }
  }
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json({ limit: '32kb' }));

  app.get('/api/shield-probe', async (_req: Request, res: Response) => {
    const dnsStatus = await probeThreatBlockingDns();
    res.json({
      checkedAtIso: new Date().toISOString(),
      malwareDnsReachable: dnsStatus.reachable,
      malwareDnsLatencyMs: dnsStatus.latencyMs,
      resolver: dnsStatus.resolver,
    });
  });

  app.post('/api/expand-url', async (req: Request, res: Response) => {
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
    if (!rawUrl) {
      res.status(400).json({ error: 'URL is required.' });
      return;
    }

    let currentUrl: URL;
    try {
      currentUrl = new URL(rawUrl);
    } catch {
      res.status(400).json({ error: 'Invalid URL syntax.' });
      return;
    }

    if (currentUrl.protocol !== 'http:' && currentUrl.protocol !== 'https:') {
      res.json({
        mode: 'scheme-blocked',
        initialUrl: rawUrl,
        finalUrl: rawUrl,
        hops: [],
        note: `Non-HTTP scheme (${currentUrl.protocol}) is not expanded over network.`,
      });
      return;
    }

    const hops: HopRecord[] = [];
    const maxRedirects = 6;

    for (let i = 0; i <= maxRedirects; i++) {
      const check = await validatePublicHostname(currentUrl.hostname);
      if (!check.safe) {
        res.json({
          mode: hops.length > 0 ? 'partial-live' : 'offline-heuristic',
          initialUrl: rawUrl,
          finalUrl: currentUrl.toString(),
          hops,
          note: check.reason,
        });
        return;
      }

      const start = Date.now();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3500);

      try {
        const response = await fetch(currentUrl.toString(), {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'AegisLocal-LinkInspector/1.0 (Android; Non-Browser Preflight)',
            Accept: '*/*',
          },
        });
        clearTimeout(timeout);

        const latencyMs = Math.max(1, Date.now() - start);
        const locationHeader = response.headers.get('location') ?? undefined;
        const contentType = response.headers.get('content-type') ?? undefined;

        hops.push({
          step: i + 1,
          url: currentUrl.toString(),
          statusCode: response.status,
          location: locationHeader,
          contentType,
          latencyMs,
        });

        if (response.status >= 300 && response.status < 400 && locationHeader) {
          currentUrl = new URL(locationHeader, currentUrl);
          if (currentUrl.protocol !== 'http:' && currentUrl.protocol !== 'https:') {
            break;
          }
          continue;
        }
        break;
      } catch {
        clearTimeout(timeout);
        res.json({
          mode: hops.length > 0 ? 'partial-live' : 'offline-heuristic',
          initialUrl: rawUrl,
          finalUrl: currentUrl.toString(),
          hops,
          note: 'Remote host did not respond to HEAD preflight within 3.5s; evaluated via local heuristics.',
        });
        return;
      }
    }

    res.json({
      mode: 'live-network',
      initialUrl: rawUrl,
      finalUrl: currentUrl.toString(),
      hops,
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AegisLocal server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();

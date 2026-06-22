/**
 * Puppeteer CLI for Web Recon — called from Python browser_service.py
 * Usage: node run.mjs <action> <url>
 * Actions: ping | screenshot | cookies | scan
 */
import puppeteer from 'puppeteer';
import { writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomUUID } from 'crypto';

const action = (process.argv[2] || '').toLowerCase();
const targetUrl = process.argv[3] || '';

function fail(message, code = 1) {
  process.stdout.write(JSON.stringify({ error: message }));
  process.exit(code);
}

function ok(data) {
  process.stdout.write(JSON.stringify(data));
}

function saveScreenshot(buffer) {
  const shotPath = join(tmpdir(), `webrecon-${randomUUID()}.png`);
  writeFileSync(shotPath, buffer);
  return shotPath;
}

function normalizeUrl(raw) {
  const trimmed = (raw || '').trim();
  if (!trimmed) return null;
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

async function launchBrowser() {
  const executablePath = process.env.CHROME_PATH || process.env.PUPPETEER_EXECUTABLE_PATH;
  return puppeteer.launch({
    headless: true,
    executablePath: executablePath || undefined,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
    ],
  });
}

async function navigate(page, url) {
  await page.setViewport({ width: 1280, height: 800 });
  page.setDefaultNavigationTimeout(45000);
  await page.setUserAgent(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
  );
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await new Promise((r) => setTimeout(r, 1500));
}

async function screenshot(url) {
  const browser = await launchBrowser();
  try {
    const page = await browser.newPage();
    await navigate(page, url);
    const buffer = await page.screenshot({ type: 'png', fullPage: false });
    const screenshotPath = saveScreenshot(buffer);
    ok({ screenshotPath, width: 1280, height: 800 });
  } finally {
    await browser.close().catch(() => {});
  }
}

async function cookies(url) {
  const browser = await launchBrowser();
  try {
    const page = await browser.newPage();
    await navigate(page, url);
    await page.waitForNetworkIdle({ idleTime: 500, timeout: 8000 }).catch(() => {});
    const clientCookies = await page.cookies();
    ok({ clientCookies });
  } finally {
    await browser.close().catch(() => {});
  }
}

async function fullScan(url) {
  const browser = await launchBrowser();
  try {
    const page = await browser.newPage();
    await navigate(page, url);
    await page.waitForNetworkIdle({ idleTime: 500, timeout: 8000 }).catch(() => {});

    const [buffer, clientCookies, title, generators, scripts] = await Promise.all([
      page.screenshot({ type: 'png', fullPage: false }),
      page.cookies(),
      page.title(),
      page.$$eval('meta[name="generator"]', (els) => els.map((e) => e.content).filter(Boolean)),
      page.$$eval('script[src]', (els) =>
        els.map((e) => e.src).filter(Boolean).slice(0, 30),
      ),
    ]);

    ok({
      screenshotPath: saveScreenshot(buffer),
      clientCookies,
      title,
      generators,
      scriptSources: scripts,
    });
  } finally {
    await browser.close().catch(() => {});
  }
}

async function main() {
  if (action === 'ping') {
    ok({ status: 'ok', puppeteer: true });
    return;
  }

  const url = normalizeUrl(targetUrl);
  if (!url) {
    fail('URL is required');
    return;
  }

  try {
    new URL(url);
  } catch {
    fail('Invalid URL');
    return;
  }

  if (action === 'screenshot') {
    await screenshot(url);
  } else if (action === 'cookies') {
    await cookies(url);
  } else if (action === 'scan') {
    await fullScan(url);
  } else {
    fail(`Unknown action: ${action}. Use ping|screenshot|cookies|scan`);
  }
}

main().catch((err) => {
  const msg = err?.message || String(err);
  if (/Browser was not found|Could not find Chrome|ENOENT/i.test(msg)) {
    ok({
      skipped: msg,
      hint: 'Run: cd browser && npm install. Or set CHROME_PATH to your Chrome executable.',
    });
    process.exit(0);
  }
  fail(msg);
});

# Browser service (Puppeteer)

Node.js **18+** required.

```powershell
cd browser
npm install
```

Test:

```powershell
node run.mjs ping
node run.mjs screenshot https://example.com
```

Optional: set `CHROME_PATH` if you use system Chrome instead of bundled Chromium.

Environment:

| Variable | Default | Description |
|----------|---------|-------------|
| `PUPPETEER_TIMEOUT` | 45 | Seconds for Python subprocess |
| `CHROME_PATH` | bundled | Custom Chrome/Chromium path |

const http = require('http');
const httpGet = require('http');
const tls = require('tls');
const os = require('os');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const PORT = 9876;

// Pre-generate a random buffer for local speed test fallback
const RAND_BUF = crypto.randomBytes(512 * 1024);

// Extract Zscaler root CA via Node.js TLS (no PowerShell C# compilation needed).
// Installs to CurrentUser\Root via simple PowerShell — no UAC required.
function fetchAndInstallZscalerCert() {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: 'www.google.com',
      port: 443,
      rejectUnauthorized: false,
      servername: 'www.google.com',
    });

    socket.setTimeout(12000, () => {
      socket.destroy();
      resolve({ success: false, error: 'Connection timed out. Make sure you are connected to the Zscaler WiFi network first.' });
    });

    socket.on('error', (err) => {
      resolve({ success: false, error: 'TLS connection failed: ' + err.message });
    });

    socket.on('secureConnect', () => {
      try {
        let cert = socket.getPeerCertificate(true);
        socket.destroy();

        if (!cert || !cert.raw) {
          return resolve({ success: false, error: 'No certificate received. Are you connected to the Zscaler WiFi network?' });
        }

        // Walk up the chain to the root cert.
        // Root's issuerCertificate has the same fingerprint as itself.
        let depth = 0;
        while (
          cert.issuerCertificate &&
          cert.issuerCertificate.fingerprint !== cert.fingerprint &&
          cert.issuerCertificate.raw &&
          depth < 10
        ) {
          cert = cert.issuerCertificate;
          depth++;
        }

        const rootRaw = cert.raw;
        const subjectCN = (cert.subject && cert.subject.CN) ? cert.subject.CN : JSON.stringify(cert.subject || {});
        const issuerCN  = (cert.issuer  && cert.issuer.CN)  ? cert.issuer.CN  : JSON.stringify(cert.issuer  || {});

        if (!rootRaw || rootRaw.length < 50) {
          return resolve({ success: false, error: 'Root certificate data missing or too small. Make sure you are on the Zscaler network.' });
        }

        const ts = Date.now();
        const certFile   = path.join(os.tmpdir(), 'zs_root_' + ts + '.cer');
        const scriptFile = path.join(os.tmpdir(), 'zs_import_' + ts + '.ps1');

        // Write raw DER cert bytes
        fs.writeFileSync(certFile, rootRaw);

        // Simple PowerShell — no Add-Type, no C# compilation
        const certFilePs = certFile.replace(/\\/g, '\\\\').replace(/'/g, "''");
        const psLines = [
          "$ErrorActionPreference = 'Stop'",
          "$f = '" + certFilePs + "'",
          '$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($f)',
          '$s = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","CurrentUser")',
          '$s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)',
          '$s.Add($c)',
          '$s.Close()',
          'Write-Output ("OK:" + $c.Thumbprint)',
        ];
        fs.writeFileSync(scriptFile, psLines.join('\r\n'), 'utf8');

        exec(
          'powershell -ExecutionPolicy Bypass -NonInteractive -File "' + scriptFile + '"',
          { timeout: 20000 },
          (err, stdout, stderr) => {
            try { fs.unlinkSync(scriptFile); } catch {}
            try { fs.unlinkSync(certFile); } catch {}

            const out = (stdout || '').trim();
            if (out.startsWith('OK:')) {
              resolve({ success: true, subject: subjectCN, issuer: issuerCN, thumbprint: out.slice(3) });
            } else {
              const errDetail = ((stderr || '').trim() || (err && err.message) || 'Import failed').slice(0, 500);
              resolve({
                success: false,
                error: errDetail,
                subject: subjectCN,
                issuer: issuerCN,
                hint: 'Certificate was extracted but could not be installed. Try running WiFi Manager as Administrator.',
              });
            }
          }
        );
      } catch (e) {
        try { socket.destroy(); } catch {}
        resolve({ success: false, error: 'Extraction error: ' + e.message });
      }
    });
  });
}

// Detect captive portal / internet connectivity
function checkInternet() {
  return new Promise((resolve) => {
    const req = httpGet.request({
      hostname: 'connectivitycheck.gstatic.com',
      path: '/generate_204',
      method: 'GET',
      port: 80,
    }, (res) => {
      res.resume();
      if (res.statusCode === 204) {
        resolve({ online: true, portal: false, portalUrl: null });
      } else {
        // Any redirect or non-204 = captive portal intercepting
        resolve({ online: false, portal: true, portalUrl: res.headers['location'] || null, status: res.statusCode });
      }
    });
    req.on('error', () => resolve({ online: false, portal: false, portalUrl: null }));
    req.setTimeout(6000, () => { req.destroy(); resolve({ online: false, portal: false, portalUrl: null, timeout: true }); });
    req.end();
  });
}

function run(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { encoding: 'buffer' }, (err, stdout) => {
      if (err) return resolve('');
      try {
        let text = stdout.toString('utf8');
        if (text.includes('')) text = stdout.toString('latin1');
        resolve(text);
      } catch {
        resolve(stdout.toString('latin1'));
      }
    });
  });
}

async function getSavedNetworks() {
  const profileOutput = await run('netsh wlan show profiles');
  const profileRegex = /All User Profile\s*:\s*(.+)/g;
  const names = [];
  let match;
  while ((match = profileRegex.exec(profileOutput)) !== null) {
    names.push(match[1].trim());
  }
  const networks = await Promise.all(names.map(async (name) => {
    const details = await run(`netsh wlan show profile name="${name}" key=clear`);
    const passMatch = details.match(/Key Content\s*:\s*(.+)/);
    const authMatch = details.match(/Authentication\s*:\s*(.+)/);
    const cipherMatch = details.match(/Cipher\s*:\s*(.+)/);
    return {
      name,
      password: passMatch ? passMatch[1].trim() : '(open network)',
      auth: authMatch ? authMatch[1].trim() : 'Unknown',
      cipher: cipherMatch ? cipherMatch[1].trim() : 'Unknown',
    };
  }));
  return networks;
}

async function getAvailableNetworks() {
  const output = await run('netsh wlan show networks mode=bssid');
  const networks = [];
  const blocks = output.split(/(?<!B)SSID \d+\s*:/);
  for (const block of blocks.slice(1)) {
    const lines = block.split(/\r?\n/);
    const ssid = lines[0].trim();
    if (!ssid) continue;
    const authMatch = block.match(/Authentication\s*:\s*(.+)/);
    const bssidMatch = block.match(/BSSID \d+\s*:\s*([0-9a-fA-F:]+)/);
    const signals = [...block.matchAll(/Signal\s*:\s*(\d+)%/g)].map(m => parseInt(m[1]));
    const maxSignal = signals.length ? Math.max(...signals) : 0;
    const bandMatches = [...block.matchAll(/Band\s*:\s*(.+)/g)].map(m => m[1].trim());
    networks.push({
      ssid,
      auth: authMatch ? authMatch[1].trim() : 'Unknown',
      signal: maxSignal,
      bssid: bssidMatch ? bssidMatch[1].trim() : '',
      band: bandMatches[0] || '',
    });
  }
  return networks;
}

async function getStatus() {
  const output = await run('netsh wlan show interfaces');
  const m = (re) => { const r = output.match(re); return r ? r[1].trim() : null; };
  return {
    connected: (m(/State\s*:\s*(.+)/) || '') === 'connected',
    ssid: m(/\bSSID\s*:\s*(.+)/),
    signal: parseInt(m(/Signal\s*:\s*(\d+)%/) || '0'),
    state: m(/State\s*:\s*(.+)/) || 'disconnected',
    rxRate: parseFloat(m(/Receive rate.*?:\s*([\d.]+)/) || '0') || null,
    txRate: parseFloat(m(/Transmit rate.*?:\s*([\d.]+)/) || '0') || null,
    ip: m(/IPv4 Address.*?:\s*([\d.]+)/),
    band: m(/Band\s*:\s*(.+)/),
    channel: parseInt(m(/Channel\s*:\s*(\d+)/) || '0') || null,
    bssid: m(/BSSID\s*:\s*([0-9a-fA-F:]+)/),
  };
}

async function getDiagnostics() {
  const [ipcfg, wlan, pingOut] = await Promise.all([
    run('ipconfig /all'),
    run('netsh wlan show interfaces'),
    run('ping -n 4 -w 2000 8.8.8.8'),
  ]);
  const m = (src, re) => { const r = src.match(re); return r ? r[1].trim() : null; };

  const gateway = m(ipcfg, /Default Gateway.*?:\s*((?:\d+\.){3}\d+)/);
  const subnet = m(ipcfg, /Subnet Mask.*?:\s*([\d.]+)/);
  const dnsAll = [...ipcfg.matchAll(/(?:DNS Servers|(?<=DNS Servers.*\n))\s*((?:\d+\.){3}\d+)/g)].map(r => r[1]);
  const dnsSimple = [...ipcfg.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g)]
    .map(r => r[1])
    .filter(ip => ip.startsWith('8.8') || ip.startsWith('1.1') || ip.startsWith('4.4') || ip.startsWith('192.168') || ip.startsWith('10.'));
  const dns = dnsAll.length ? dnsAll : dnsSimple.slice(0, 3);

  const online = pingOut.includes('Reply from 8.8.8.8');
  const pingTimes = [...pingOut.matchAll(/time[=<](\d+)ms/g)].map(r => parseInt(r[1]));
  const pingAvg = pingTimes.length ? Math.round(pingTimes.reduce((a, b) => a + b, 0) / pingTimes.length) : null;
  const lossMatch = pingOut.match(/(\d+)% loss/);

  return {
    internet: online,
    internetPing: pingAvg,
    packetLoss: lossMatch ? parseInt(lossMatch[1]) : (online ? 0 : 100),
    gateway, subnet, dns,
    adapter: m(wlan, /Description\s*:\s*(.+)/),
    radio: m(wlan, /Radio type\s*:\s*(.+)/),
    band: m(wlan, /Band\s*:\s*(.+)/),
    channel: parseInt(m(wlan, /Channel\s*:\s*(\d+)/) || '0') || null,
    bssid: m(wlan, /BSSID\s*:\s*([0-9a-fA-F:]+)/),
    rxRate: m(wlan, /Receive rate.*?:\s*([\d.]+)/),
    txRate: m(wlan, /Transmit rate.*?:\s*([\d.]+)/),
    signal: parseInt(m(wlan, /Signal\s*:\s*(\d+)%/) || '0') || null,
  };
}

async function connectNetwork(profileName) {
  const result = await run(`netsh wlan connect name="${profileName}"`);
  return result.toLowerCase().includes('successfully');
}

async function connectNewNetwork(ssid, password, auth) {
  const tmpFile = path.join(require('os').tmpdir(), `wifi_${Date.now()}.xml`);
  const isOpen = !password || auth.toLowerCase().includes('open');
  const xml = isOpen
    ? `<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>${ssid}</name><SSIDConfig><SSID><name>${ssid}</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>auto</connectionMode><MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM></WLANProfile>`
    : `<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>${ssid}</name><SSIDConfig><SSID><name>${ssid}</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>auto</connectionMode><MSM><security><authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption><sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>${password}</keyMaterial></sharedKey></security></MSM></WLANProfile>`;
  fs.writeFileSync(tmpFile, xml, 'utf8');
  try {
    await run(`netsh wlan add profile filename="${tmpFile}" user=all`);
    const result = await run(`netsh wlan connect name="${ssid}"`);
    return result.toLowerCase().includes('successfully');
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }
}

async function disconnectNetwork() {
  const result = await run('netsh wlan disconnect');
  return result.toLowerCase().includes('successfully');
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (pathname === '/' || pathname === '/index.html') {
    // When running as a pkg exe, look next to the exe; otherwise use __dirname
    const htmlDir = process.pkg ? path.dirname(process.execPath) : __dirname;
    const html = fs.readFileSync(path.join(htmlDir, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  if (pathname === '/api/ping') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify({ ok: true }));
  }

  // Local speed test download fallback (used if Cloudflare CORS fails)
  if (pathname === '/api/speed/download') {
    const mb = Math.min(parseInt(parsed.query.mb) || 25, 100);
    const size = mb * 1024 * 1024;
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': size,
      'Cache-Control': 'no-store, no-cache',
    });
    let sent = 0;
    const write = () => {
      while (sent < size) {
        const rem = size - sent;
        const chunk = rem < RAND_BUF.length ? RAND_BUF.slice(0, rem) : RAND_BUF;
        const ok = res.write(chunk);
        sent += chunk.length;
        if (!ok) { res.once('drain', write); return; }
      }
      res.end();
    };
    write();
    return;
  }

  // Local speed test upload
  if (pathname === '/api/speed/upload' && req.method === 'POST') {
    const start = Date.now();
    let bytes = 0;
    req.on('data', c => { bytes += c.length; });
    req.on('end', () => {
      const elapsed = (Date.now() - start) / 1000;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ bytes, elapsed: elapsed.toFixed(3), mbps: (bytes * 8 / elapsed / 1e6).toFixed(2) }));
    });
    return;
  }

  if (pathname === '/api/saved') {
    try {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(await getSavedNetworks()));
    } catch (e) { res.writeHead(500); return res.end(JSON.stringify({ error: e.message })); }
  }

  if (pathname === '/api/networks') {
    try {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(await getAvailableNetworks()));
    } catch (e) { res.writeHead(500); return res.end(JSON.stringify({ error: e.message })); }
  }

  if (pathname === '/api/status') {
    try {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(await getStatus()));
    } catch (e) { res.writeHead(500); return res.end(JSON.stringify({ error: e.message })); }
  }

  if (pathname === '/api/diagnostics') {
    try {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(await getDiagnostics()));
    } catch (e) { res.writeHead(500); return res.end(JSON.stringify({ error: e.message })); }
  }

  if (pathname === '/api/connect' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      try {
        const { name } = JSON.parse(body);
        const ok = await connectNetwork(name);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: ok }));
      } catch (e) { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/connect-new' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      try {
        const { ssid, password, auth } = JSON.parse(body);
        const ok = await connectNewNetwork(ssid, password, auth);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: ok }));
      } catch (e) { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/disconnect' && req.method === 'POST') {
    try {
      const ok = await disconnectNetwork();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: ok }));
    } catch (e) { res.writeHead(500); return res.end(JSON.stringify({ error: e.message })); }
  }

  if (pathname === '/api/internet') {
    try {
      const result = await checkInternet();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(result));
    } catch (e) { res.writeHead(500); return res.end(JSON.stringify({ error: e.message })); }
  }

  if (pathname === '/api/install-zscaler' && req.method === 'POST') {
    try {
      const result = await fetchAndInstallZscalerCert();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: false, error: e.message }));
    }
  }

  if (pathname === '/api/open-browser' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const { url: target } = JSON.parse(body);
        // Only allow http/https
        const u = new URL(target);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
          exec(`start "" "${target}"`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        } else {
          res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid protocol' }));
        }
      } catch { res.writeHead(400); res.end(JSON.stringify({ error: 'Bad request' })); }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`WiFi Manager Pro running at http://127.0.0.1:${PORT}`);
  exec(`start http://127.0.0.1:${PORT}`);
});

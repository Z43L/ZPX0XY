const { app, BrowserWindow, shell } = require('electron');
const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');

app.setName('ZPX0XY');
const projectRoot = app.isPackaged ? process.resourcesPath : path.resolve(__dirname, '..');
const appData = path.join(app.getPath('userData'), 'zpx0xy');
let backend;

function reserveWebPort(port) {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.once('error', reject);
    probe.listen(port, '127.0.0.1', () => {
      const assignedPort = probe.address().port;
      probe.close(error => error ? reject(error) : resolve(assignedPort));
    });
  });
}

async function allocateWebPort() {
  try {
    return await reserveWebPort(4173);
  } catch (error) {
    if (error.code !== 'EADDRINUSE') throw error;
    return reserveWebPort(0);
  }
}

function startBackend(port) {
  const python = process.env.CAIDO_CLONE_PYTHON || (process.platform === 'darwin' ? '/usr/bin/python3' : 'python3');
  backend = spawn(python, [path.join(projectRoot, 'server.py')], {
    cwd: projectRoot,
    env: { ...process.env, CAIDO_CLONE_WEB_PORT: String(port), CAIDO_CLONE_DATA: path.join(appData, 'data'), CAIDO_CLONE_DB: path.join(appData, 'history.sqlite3') },
    stdio: 'inherit',
  });
  backend.on('error', error => console.error('Could not start local engine:', error));
  backend.on('exit', code => {
    if (!app.isQuitting && code !== 0) console.error(`Local engine exited (${code})`);
  });
}

function waitForBackend(port) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 20000;
    const poll = () => {
      const request = http.get(`http://127.0.0.1:${port}/api/status`, response => {
        response.resume();
        if (response.statusCode === 200) resolve();
        else retry();
      });
      request.on('error', retry);
      request.setTimeout(500, () => request.destroy());
      function retry() {
        if (backend?.exitCode !== null && backend?.exitCode !== undefined) {
          reject(new Error(`Local engine exited before becoming ready (${backend.exitCode})`));
        } else if (Date.now() > deadline) reject(new Error('Local engine did not become ready'));
        else setTimeout(poll, 250);
      }
    };
    poll();
  });
}

async function createWindow() {
  const webPort = await allocateWebPort();
  startBackend(webPort);
  await waitForBackend(webPort);
  const window = new BrowserWindow({
    width: 1440, height: 900, minWidth: 800, minHeight: 560,
    backgroundColor: '#f7f8fa', show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  window.once('ready-to-show', () => window.show());
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://') || url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  await window.loadURL(`http://127.0.0.1:${webPort}`);
}

app.whenReady().then(createWindow).catch(error => {
  console.error(error);
  app.quit();
});
app.on('before-quit', () => {
  app.isQuitting = true;
  if (backend && !backend.killed) backend.kill('SIGTERM');
});
app.on('window-all-closed', () => app.quit());

const { app, BrowserWindow } = require('electron')

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    titleBarStyle: 'default',
    title: 'CryptoX',
  })

  // Dev: load from Vite dev server using local network IP to bypass VPN issues
  const os = require('os');
  function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        // Ищем IPv4 адрес, который не является внутренним (не localhost) и начинается с 192.
        if (iface.family === 'IPv4' && !iface.internal && iface.address.startsWith('192.')) {
          return iface.address;
        }
      }
    }
    return 'localhost'; // фоллбэк
  }
  
  const localIP = getLocalIP();
  win.loadURL(`http://${localIP}:5173`);

  // Uncomment to open DevTools:
  // win.webContents.openDevTools()
}

app.whenReady().then(createWindow)

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})

// Debug logger that bypasses console.log blocking by Chrome extensions
class DebugLogger {
  private container: HTMLDivElement | null = null;
  private logs: string[] = [];
  private maxLogs = 50;

  init() {
    if (this.container) return;

    this.container = document.createElement("div");
    this.container.id = "debug-logger";
    this.container.style.cssText = `
      position: fixed;
      bottom: 0;
      right: 0;
      width: 400px;
      height: 300px;
      background: rgba(0, 0, 0, 0.9);
      color: #0f0;
      font-family: monospace;
      font-size: 11px;
      padding: 10px;
      overflow-y: auto;
      z-index: 999999;
      border-top: 2px solid #0f0;
      display: none;
    `;

    document.body.appendChild(this.container);

    // Toggle with Ctrl+Shift+D
    document.addEventListener("keydown", (e) => {
      if (e.ctrlKey && e.shiftKey && e.key === "D") {
        this.toggle();
      }
    });
  }

  toggle() {
    if (!this.container) return;
    this.container.style.display =
      this.container.style.display === "none" ? "block" : "none";
  }

  log(message: string) {
    const now = new Date();
    const timestamp =
      now.toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }) +
      "." +
      now.getMilliseconds().toString().padStart(3, "0");

    const logMessage = `[${timestamp}] ${message}`;
    this.logs.push(logMessage);

    // Keep only last N logs
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }

    if (this.container) {
      this.container.innerHTML = this.logs.join("<br>");
      this.container.scrollTop = this.container.scrollHeight;
    }

    // Also try regular console.log (might work in some browsers)
    try {
      console.log(logMessage);
    } catch {
      // Ignore if blocked
    }
  }

  clear() {
    this.logs = [];
    if (this.container) {
      this.container.innerHTML = "";
    }
  }
}

export const debugLogger = new DebugLogger();

import { PROTECTION_CAPABILITY, protectionActive, stateProtection } from './protection-model';
import { Tray, Menu, Notification, nativeImage, BrowserWindow, dialog } from 'electron';
import { execFile } from 'node:child_process';
import path from 'node:path';
import type { ClientState } from './protocol';
import { RequestNotifications, pending, type RequestRef } from './notifications';
export class Background {
  private tray?: Tray;
  private host = false;
  private checking = false;
  private closed = false;
  private timer: NodeJS.Timeout;
  private menuSignature = '';
  private notifications: RequestNotifications;
  private quittingDialog = false;
  // Blue shield while protection is active, red otherwise (nothing is being blocked).
  private icons = {
    tray: { on: nativeImage.createFromPath(path.join(__dirname, 'flowgate-tray.png')), off: nativeImage.createFromPath(path.join(__dirname, 'flowgate-tray-off.png')) },
    window: { on: nativeImage.createFromPath(path.join(__dirname, 'flowgate.png')), off: nativeImage.createFromPath(path.join(__dirname, 'flowgate-off.png')) },
  };
  private shieldOn?: boolean;
  constructor(
    private main: BrowserWindow,
    private windows: Set<BrowserWindow>,
    private state: () => ClientState,
    private show: (list?: boolean, message?: string) => void,
    private review: (ref: RequestRef) => void,
    private quit: () => void,
    private openFromTray: () => void,
  ) {
    const icon = nativeImage.createFromPath(path.join(__dirname, 'flowgate-tray.png'));
    try {
      // Red until protection is confirmed active.
      this.tray = new Tray(this.icons.tray.off);
      this.tray.setToolTip('FlowGate');
      this.tray.on('click', () => this.openFromTray());
    } catch {}
    this.notifications = new RequestNotifications(
      () => Notification.isSupported(),
      (content) =>
        new Notification({
          ...content,
          icon,
          silent: true,
          urgency: 'normal',
          timeoutType: 'default',
        }),
      (ref) => (ref ? this.review(ref) : this.show(true)),
      Date.now,
      false, // Permission popups already alert the user; avoid duplicate desktop banners.
    );
    void this.checkHost();
    this.timer = setInterval(() => void this.checkHost(), 10000);
  }
  private async checkHost() {
    if (this.checking) return;
    this.checking = true;
    this.host = await new Promise<boolean>((resolve) =>
      execFile(
        'dbus-send',
        [
          '--session',
          '--print-reply',
          '--dest=org.kde.StatusNotifierWatcher',
          '/StatusNotifierWatcher',
          'org.freedesktop.DBus.Properties.Get',
          'string:org.kde.StatusNotifierWatcher',
          'string:IsStatusNotifierHostRegistered',
        ],
        { timeout: 1500, maxBuffer: 8192 },
        (err, out) => resolve(!err && /boolean true/.test(out)),
      ),
    );
    this.checking = false;
    if (this.closed) return;
    if (!this.available() && !this.main.isDestroyed() && !this.main.isVisible())
      this.main.showInactive();
    this.update(this.state());
  }
  available() {
    return this.host && !!this.tray && !this.tray.isDestroyed();
  }
  status() {
    const trayAvailable = this.available();
    return { trayAvailable, notifications: this.notifications.status(trayAvailable) };
  }
  update(state: ClientState) {
    const active = [...this.windows].some(
      (w) =>
        !w.isDestroyed() &&
        w.isVisible() &&
        !w.isMinimized() &&
        w.isFocused() &&
        w.webContents.getURL().startsWith('flowgate://app/index.html'),
    );
    this.notifications.update(state, active);
    const on = protectionActive(state);
    if (on !== this.shieldOn) {
      this.shieldOn = on;
      if (this.tray && !this.tray.isDestroyed()) this.tray.setImage(on ? this.icons.tray.on : this.icons.tray.off);
      if (!this.main.isDestroyed()) this.main.setIcon(on ? this.icons.window.on : this.icons.window.off);
    }
    if (!this.tray || this.tray.isDestroyed()) return;
    const count = pending(state).length,
      c = state.control;
    const enforcement = c.capabilities?.includes(PROTECTION_CAPABILITY)
      ? stateProtection(state)
      : c.connected
        ? `Enforcement: ${c.enforcement?.state || c.mode || 'unknown'}`
        : 'Enforcement: unknown / disconnected';
    const udp = state.observation.connected
      ? state.observation.trafficMonitor?.state ||
        state.observation.activity?.udp?.state ||
        'unavailable'
      : 'unknown / observer disconnected';
    const signature = JSON.stringify([count, enforcement, udp]);
    if (signature === this.menuSignature) return;
    this.menuSignature = signature;
    this.tray.setToolTip(`FlowGate · ${count} pending · ${enforcement}`);
    this.tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: 'Open FlowGate', click: () => this.openFromTray() },
        { label: `Pending requests (${count})`, click: () => this.show(true) },
        { type: 'separator' },
        { label: enforcement, enabled: false },
        { label: `Extended monitoring: ${udp}`, enabled: false },
        { type: 'separator' },
        { label: 'Daemon protection keeps running if active.', enabled: false },
        { label: 'Quit FlowGate UI', click: () => void this.requestQuit() },
      ]),
    );
  }
  async requestQuit() {
    if (this.quittingDialog) return;
    const state = this.state();
    // A verified continuous daemon is independent; a normal UI Quit needs no extra confirmation.
    if (
      state.control.connected &&
      state.control.capabilities?.includes(PROTECTION_CAPABILITY) &&
      state.control.protection &&
      !pending(state).length
    ) {
      this.quit();
      return;
    }
    this.quittingDialog = true;
    this.show();
    try {
      const result = await dialog.showMessageBox(this.main, {
        type: 'question',
        title: 'Quit FlowGate UI',
        message: 'Quit the UI and stop request notifications?',
        detail:
          'Only this interface and its owned read-only observer exit. Independent daemon protection and UDP collection are not stopped. Their state may be active or unknown; bounded evaluation keeps its original deadline. Without the interface, unanswered requests can time out and be denied. You will no longer receive request notifications.',
        buttons: ['Keep running', 'Quit FlowGate UI'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
      });
      if (result.response === 1) this.quit();
    } finally {
      this.quittingDialog = false;
    }
  }
  close() {
    this.closed = true;
    clearInterval(this.timer);
    this.notifications.close();
    this.tray?.destroy();
  }
}

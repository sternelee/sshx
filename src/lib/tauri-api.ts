import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import {
  sendNotification,
  isPermissionGranted,
  requestPermission,
} from "@tauri-apps/plugin-notification";
import { openUrl } from "@tauri-apps/plugin-opener";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { SshxEvent, SessionInfo } from "./sshx-api";

const appWindow = getCurrentWindow();

export interface TauriSessionInfo extends SessionInfo {
  nodeId?: string;
}

// Enhanced Tauri-specific API implementation
export class TauriAPI {
  private eventListeners: Map<string, ((event: SshxEvent) => void)[]> =
    new Map();
  private unlistenFunctions: Map<string, UnlistenFn[]> = new Map();

  async createSession(): Promise<string> {
    try {
      const sessionId = await invoke<string>("create_session");
      console.log("Tauri: Created session", sessionId);

      // Show notification if permission is granted
      await this.showNotification(
        "Session Created",
        `Session ${sessionId.slice(0, 8)}... is ready to share`,
      );

      return sessionId;
    } catch (error) {
      console.error("Tauri: Failed to create session", error);
      throw error;
    }
  }

  async joinSession(ticket: string): Promise<string> {
    try {
      const sessionId = await invoke<string>("join_session", { ticket });
      console.log("Tauri: Joined session", sessionId);

      await this.showNotification(
        "Session Joined",
        `Connected to session ${sessionId.slice(0, 8)}...`,
      );

      return sessionId;
    } catch (error) {
      console.error("Tauri: Failed to join session", error);
      throw error;
    }
  }

  async sendData(sessionId: string, data: Uint8Array): Promise<void> {
    try {
      await invoke("send_data", { sessionId, data: Array.from(data) });
    } catch (error) {
      console.error("Tauri: Failed to send data", error);
      throw error;
    }
  }

  async getSessions(): Promise<string[]> {
    try {
      return await invoke<string[]>("get_sessions");
    } catch (error) {
      console.error("Tauri: Failed to get sessions", error);
      throw error;
    }
  }

  async closeSession(sessionId: string): Promise<boolean> {
    try {
      const result = await invoke<boolean>("close_session", { sessionId });
      console.log("Tauri: Closed session", sessionId, result);

      if (result) {
        await this.showNotification(
          "Session Closed",
          `Session ${sessionId.slice(0, 8)}... has been terminated`,
        );
      }

      return result;
    } catch (error) {
      console.error("Tauri: Failed to close session", error);
      throw error;
    }
  }

  async getSessionTicket(
    sessionId: string,
    includeSelf: boolean = true,
  ): Promise<string> {
    try {
      return await invoke<string>("get_session_ticket", {
        sessionId,
        includeSelf,
      });
    } catch (error) {
      console.error("Tauri: Failed to get session ticket", error);
      throw error;
    }
  }

  async getNodeId(): Promise<string> {
    try {
      return await invoke<string>("get_node_id");
    } catch (error) {
      console.error("Tauri: Failed to get node ID", error);
      throw error;
    }
  }

  async getAppVersion(): Promise<string> {
    try {
      return await invoke<string>("get_app_version");
    } catch (error) {
      console.error("Tauri: Failed to get app version", error);
      return "unknown";
    }
  }

  async showNotification(title: string, body: string): Promise<void> {
    try {
      // Check if notification permission is granted
      let permissionGranted = await isPermissionGranted();

      if (!permissionGranted) {
        const permission = await requestPermission();
        permissionGranted = permission === "granted";
      }

      if (permissionGranted) {
        await sendNotification({ title, body });
      } else {
        console.warn("Notification permission not granted");
      }
    } catch (error) {
      console.warn("Tauri: Native notification failed, trying invoke", error);
      try {
        await invoke("send_notification", { title, body });
      } catch (invokeError) {
        console.error("Tauri: Both notification methods failed", invokeError);
      }
    }
  }

  async openExternalUrl(url: string): Promise<void> {
    try {
      await openUrl(url);
    } catch (error) {
      console.error("Tauri: Failed to open external URL", error);
      // Fallback to invoke command
      try {
        await invoke("open_external_url", { url });
      } catch (invokeError) {
        console.error("Tauri: Both URL opening methods failed", invokeError);
        throw invokeError;
      }
    }
  }

  subscribeToEvents(
    sessionId: string,
    callback: (event: SshxEvent) => void,
  ): () => void {
    const listeners = this.eventListeners.get(sessionId) || [];
    listeners.push(callback);
    this.eventListeners.set(sessionId, listeners);

    // Set up Tauri event listener for this session
    const unlistenPromise = listen(`session-event-${sessionId}`, (event) => {
      const sshxEvent = event.payload as SshxEvent;
      callback(sshxEvent);
    });

    // Store the unlisten function
    unlistenPromise.then((unlisten) => {
      const unlistenFns = this.unlistenFunctions.get(sessionId) || [];
      unlistenFns.push(unlisten);
      this.unlistenFunctions.set(sessionId, unlistenFns);
    });

    // Return unsubscribe function
    return () => {
      const currentListeners = this.eventListeners.get(sessionId) || [];
      const index = currentListeners.indexOf(callback);
      if (index > -1) {
        currentListeners.splice(index, 1);
        this.eventListeners.set(sessionId, currentListeners);
      }

      // Clean up Tauri event listeners
      const unlistenFns = this.unlistenFunctions.get(sessionId) || [];
      unlistenFns.forEach((unlisten) => unlisten());
      this.unlistenFunctions.delete(sessionId);
    };
  }

  getSessionInfo(sessionId: string): { id: string; connected: boolean } | null {
    // For Tauri, we'll assume sessions are connected if they exist
    // This could be enhanced with proper state tracking
    return {
      id: sessionId,
      connected: true,
    };
  }

  // Tauri-specific window management methods
  async minimizeWindow(): Promise<void> {
    try {
      await appWindow.minimize();
    } catch (error) {
      console.error("Failed to minimize window:", error);
    }
  }

  async maximizeWindow(): Promise<void> {
    try {
      await appWindow.toggleMaximize();
    } catch (error) {
      console.error("Failed to maximize window:", error);
    }
  }

  async closeWindow(): Promise<void> {
    try {
      await appWindow.close();
    } catch (error) {
      console.error("Failed to close window:", error);
    }
  }

  async setWindowTitle(title: string): Promise<void> {
    try {
      await appWindow.setTitle(title);
    } catch (error) {
      console.error("Failed to set window title:", error);
    }
  }

  async onWindowCloseRequested(
    handler: () => boolean | Promise<boolean>,
  ): Promise<UnlistenFn> {
    return await appWindow.onCloseRequested(async (event) => {
      const shouldClose = await handler();
      if (!shouldClose) {
        event.preventDefault();
      }
    });
  }

  // App-specific methods
  async copyToClipboard(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
    } catch (error) {
      console.error("Failed to copy to clipboard:", error);
      throw error;
    }
  }

  async readFromClipboard(): Promise<string> {
    try {
      return await navigator.clipboard.readText();
    } catch (error) {
      console.error("Failed to read from clipboard:", error);
      throw error;
    }
  }
}

// Check if we're running in a Tauri environment
export const isTauri = (): boolean => {
  return (
    typeof window !== "undefined" && (window as any).__TAURI__ !== undefined
  );
};

// Export a singleton instance
let tauriApiInstance: TauriAPI | null = null;

export const getTauriApi = (): TauriAPI => {
  if (!tauriApiInstance) {
    tauriApiInstance = new TauriAPI();
  }
  return tauriApiInstance;
};

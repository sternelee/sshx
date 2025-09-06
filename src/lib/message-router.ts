/**
 * Message routing and distribution system for multi-ticket P2P sessions
 * Handles routing messages between different sessions and provides unified event handling
 */

import type { SshxEvent, User, Winsize } from "./sshx-api";
import type { MultiSessionSshxClient } from "./sshx-api";

export interface RoutedMessage {
  sessionId: string;
  timestamp: number;
  event: SshxEvent;
}

export interface SessionMessage {
  sessionId: string;
  data: Uint8Array;
  timestamp: number;
}

export interface RoutingConfig {
  enableBroadcast: boolean;
  enableCrossSessionRelay: boolean;
  maxMessageHistory: number;
  enableMessageFiltering: boolean;
}

export class MessageRouter {
  #multiSessionClient: MultiSessionSshxClient;
  #config: RoutingConfig;
  #messageHistory: RoutedMessage[] = [];
  #eventHandlers: Map<string, Set<(message: RoutedMessage) => void>> =
    new Map();
  #sessionSubscriptions: Map<string, Set<string>> = new Map(); // sessionId -> set of subscriberIds
  #activeSession: string | null = null;

  constructor(
    multiSessionClient: MultiSessionSshxClient,
    config: Partial<RoutingConfig> = {},
  ) {
    this.#multiSessionClient = multiSessionClient;
    this.#config = {
      enableBroadcast: true,
      enableCrossSessionRelay: false,
      maxMessageHistory: 1000,
      enableMessageFiltering: true,
      ...config,
    };
  }

  /**
   * Initialize the router with session event handling
   */
  initialize(): void {
    // Set up event handler for all sessions
    this.#multiSessionClient.createSession = this.#wrapCreateSession();
    this.#multiSessionClient.joinSession = this.#wrapJoinSession();
  }

  /**
   * Set the active session for focused operations
   */
  setActiveSession(sessionId: string): void {
    if (this.#multiSessionClient.isSessionActive(sessionId)) {
      this.#activeSession = sessionId;
    } else {
      throw new Error(`Session ${sessionId} is not active`);
    }
  }

  /**
   * Get the currently active session
   */
  getActiveSession(): string | null {
    return this.#activeSession;
  }

  /**
   * Route a message to a specific session
   */
  async sendToSession(sessionId: string, data: Uint8Array): Promise<void> {
    if (!this.#multiSessionClient.isSessionActive(sessionId)) {
      throw new Error(`Session ${sessionId} is not active`);
    }

    await this.#multiSessionClient.sendToSession(sessionId, data);
  }

  /**
   * Send a command to a specific session
   */
  async sendCommandToSession(sessionId: string, command: any): Promise<void> {
    if (!this.#multiSessionClient.isSessionActive(sessionId)) {
      throw new Error(`Session ${sessionId} is not active`);
    }

    await this.#multiSessionClient.sendCommand(sessionId, command);
  }

  /**
   * Broadcast a message to all active sessions
   */
  async broadcastToAll(data: Uint8Array): Promise<void> {
    if (!this.#config.enableBroadcast) {
      return;
    }

    await this.#multiSessionClient.broadcastToAll(data);
  }

  /**
   * Route a shell input to the active session
   */
  async sendToActiveSession(shellId: number, data: Uint8Array): Promise<void> {
    if (!this.#activeSession) {
      throw new Error("No active session set");
    }

    await this.#multiSessionClient.sendData(this.#activeSession, shellId, data);
  }

  /**
   * Send a command to the active session
   */
  async sendCommandToActiveSession(command: any): Promise<void> {
    if (!this.#activeSession) {
      throw new Error("No active session set");
    }

    await this.#multiSessionClient.sendCommand(this.#activeSession, command);
  }

  /**
   * Add an event handler for a specific session
   */
  addEventHandler(
    sessionId: string,
    handler: (message: RoutedMessage) => void,
  ): void {
    if (!this.#eventHandlers.has(sessionId)) {
      this.#eventHandlers.set(sessionId, new Set());
    }
    this.#eventHandlers.get(sessionId)!.add(handler);
  }

  /**
   * Remove an event handler for a specific session
   */
  removeEventHandler(
    sessionId: string,
    handler: (message: RoutedMessage) => void,
  ): void {
    const handlers = this.#eventHandlers.get(sessionId);
    if (handlers) {
      handlers.delete(handler);
      if (handlers.size === 0) {
        this.#eventHandlers.delete(sessionId);
      }
    }
  }

  /**
   * Subscribe to messages from a specific session
   */
  subscribeToSession(subscriberId: string, sessionId: string): void {
    if (!this.#sessionSubscriptions.has(sessionId)) {
      this.#sessionSubscriptions.set(sessionId, new Set());
    }
    this.#sessionSubscriptions.get(sessionId)!.add(subscriberId);
  }

  /**
   * Unsubscribe from messages from a specific session
   */
  unsubscribeFromSession(subscriberId: string, sessionId: string): void {
    const subscribers = this.#sessionSubscriptions.get(sessionId);
    if (subscribers) {
      subscribers.delete(subscriberId);
      if (subscribers.size === 0) {
        this.#sessionSubscriptions.delete(sessionId);
      }
    }
  }

  /**
   * Get message history for a session
   */
  getSessionHistory(sessionId: string, limit?: number): RoutedMessage[] {
    const history = this.#messageHistory.filter(
      (msg) => msg.sessionId === sessionId,
    );
    if (limit) {
      return history.slice(-limit);
    }
    return history;
  }

  /**
   * Get all message history
   */
  getAllHistory(limit?: number): RoutedMessage[] {
    if (limit) {
      return this.#messageHistory.slice(-limit);
    }
    return [...this.#messageHistory];
  }

  /**
   * Clear message history
   */
  clearHistory(): void {
    this.#messageHistory = [];
  }

  /**
   * Filter events based on configuration
   */
  #filterEvent(event: SshxEvent): boolean {
    if (!this.#config.enableMessageFiltering) {
      return true;
    }

    // Filter out redundant events like frequent pongs/latency updates
    if (event.pong !== undefined || event.shellLatency !== undefined) {
      return false;
    }

    return true;
  }

  /**
   * Handle incoming events from sessions
   */
  #handleSessionEvent(sessionId: string, event: SshxEvent): void {
    if (!this.#filterEvent(event)) {
      return;
    }

    const routedMessage: RoutedMessage = {
      sessionId,
      timestamp: Date.now(),
      event,
    };

    // Add to message history
    this.#messageHistory.push(routedMessage);
    if (this.#messageHistory.length > this.#config.maxMessageHistory) {
      this.#messageHistory.shift();
    }

    // Notify event handlers
    const handlers = this.#eventHandlers.get(sessionId);
    if (handlers) {
      handlers.forEach((handler) => {
        try {
          handler(routedMessage);
        } catch (error) {
          console.error(
            `Error in event handler for session ${sessionId}:`,
            error,
          );
        }
      });
    }

    // Handle cross-session relay if enabled
    if (this.#config.enableCrossSessionRelay) {
      this.#relayMessageToOtherSessions(sessionId, event);
    }
  }

  /**
   * Relay messages to other sessions (for cross-session collaboration)
   */
  async #relayMessageToOtherSessions(
    sourceSessionId: string,
    event: SshxEvent,
  ): Promise<void> {
    // Only relay specific events that make sense for cross-session sharing
    const relayableEvents = ["hear"]; // Chat messages, etc.

    if (
      !relayableEvents.some(
        (type) => event[type as keyof SshxEvent] !== undefined,
      )
    ) {
      return;
    }

    const activeSessions = this.#multiSessionClient.getActiveSessions();
    for (const sessionId of activeSessions) {
      if (sessionId !== sourceSessionId) {
        try {
          await this.#multiSessionClient.sendCommand(sessionId, event);
        } catch (error) {
          console.error(
            `Failed to relay message to session ${sessionId}:`,
            error,
          );
        }
      }
    }
  }

  /**
   * Wrap createSession to add event handling
   */
  #wrapCreateSession() {
    const originalCreate = this.#multiSessionClient.createSession.bind(
      this.#multiSessionClient,
    );
    return async () => {
      const sessionId = await originalCreate();
      this.#setupSessionEventHandlers(sessionId);
      return sessionId;
    };
  }

  /**
   * Wrap joinSession to add event handling
   */
  #wrapJoinSession() {
    const originalJoin = this.#multiSessionClient.joinSession.bind(
      this.#multiSessionClient,
    );
    return async (ticket: string) => {
      const sessionId = await originalJoin(ticket);
      this.#setupSessionEventHandlers(sessionId);
      return sessionId;
    };
  }

  /**
   * Set up event handlers for a new session
   */
  #setupSessionEventHandlers(sessionId: string): void {
    // This would need to be integrated with the actual session event system
    // For now, this is a placeholder for the event handling setup
    console.log(`Set up event handlers for session: ${sessionId}`);
  }

  /**
   * Get routing statistics
   */
  getStats() {
    return {
      totalSessions: this.#multiSessionClient.getSessionCount(),
      activeSessions: this.#multiSessionClient.getActiveSessionCount(),
      messageHistorySize: this.#messageHistory.length,
      eventHandlersCount: this.#eventHandlers.size,
      subscriptionsCount: this.#sessionSubscriptions.size,
      activeSession: this.#activeSession,
    };
  }

  /**
   * Clean up resources
   */
  dispose(): void {
    this.#eventHandlers.clear();
    this.#sessionSubscriptions.clear();
    this.#messageHistory = [];
    this.#activeSession = null;
  }
}

/**
 * Factory function to create a message router with default configuration
 */
export function createMessageRouter(
  multiSessionClient: MultiSessionSshxClient,
  config?: Partial<RoutingConfig>,
): MessageRouter {
  return new MessageRouter(multiSessionClient, config);
}


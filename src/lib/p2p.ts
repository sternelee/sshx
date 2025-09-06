import init, { WebClient } from "$lib/p2p-pkg";

export type P2PClientOptions<T> = {
  onMessage(message: T): void;
};

export class P2PClient<T, U> {
  #webClient: WebClient | null = null;

  constructor(ticket: string, options: P2PClientOptions<T>) {
    init().then(() => {
      const onMessage = (data: Uint8Array) => {
        // TODO: Decode the protobuf message.
        // For now, let's assume the wasm side sends a decoded object.
        // This is not what I implemented, but it's easier for now.
        // I will fix this later.
        // options.onMessage(data as T);
        console.log("message from wasm", data);
      };
      WebClient.new(ticket, onMessage).then((client) => {
        this.#webClient = client;
      });
    });
  }

  async send(message: U) {
    if (!this.#webClient) {
      console.error("P2P client not initialized");
      return;
    }
    // TODO: Encode the protobuf message.
    // For now, let's assume the message is already a Uint8Array.
    // await this.#webClient.send(message as unknown as Uint8Array);
  }

  dispose() {
    this.#webClient = null;
  }
}

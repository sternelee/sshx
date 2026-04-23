/**
 * @file Encryption of byte streams based on a random key.
 *
 * This is used for end-to-end encryption between the terminal source and its
 * client. Keep this file consistent with the Rust implementation.
 */

const SALT: string =
  "This is a non-random salt for sshx.io, since we want to stretch the security of 83-bit keys!";

export class Encrypt {
  private constructor(
    private ver: 1 | 2,
    private aesKey: CryptoKey,
  ) {}

  /** Create a new encryptor using the latest version (v2). */
  static async new(key: string): Promise<Encrypt> {
    return Encrypt.new_v2(key);
  }

  /** Create a v1 encryptor for backward compatibility. */
  static async new_v1(key: string): Promise<Encrypt> {
    const argon2 = await import(
      "argon2-browser/dist/argon2-bundled.min.js" as any
    );
    const result = await argon2.hash({
      pass: key,
      salt: SALT,
      type: argon2.ArgonType.Argon2id,
      mem: 19 * 1024,
      time: 2,
      parallelism: 1,
      hashLen: 16,
    });
    const aesKey = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(
        result.hashHex
          .match(/.{1,2}/g)
          .map((byte: string) => parseInt(byte, 16)),
      ),
      { name: "AES-CTR" },
      false,
      ["encrypt"],
    );
    return new Encrypt(1, aesKey);
  }

  /** Create a v2 encryptor with AES-256-GCM. */
  static async new_v2(key: string): Promise<Encrypt> {
    const argon2 = await import(
      "argon2-browser/dist/argon2-bundled.min.js" as any
    );
    const result = await argon2.hash({
      pass: key,
      salt: SALT,
      type: argon2.ArgonType.Argon2id,
      mem: 19 * 1024,
      time: 2,
      parallelism: 1,
      hashLen: 32,
    });
    const aesKey = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(
        result.hashHex
          .match(/.{1,2}/g)
          .map((byte: string) => parseInt(byte, 16)),
      ),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
    return new Encrypt(2, aesKey);
  }

  /** Get the encryption version. */
  version(): 1 | 2 {
    return this.ver;
  }

  /** Get the encrypted zero block. */
  async zeros(): Promise<Uint8Array> {
    if (this.ver === 1) {
      const zeros = new Uint8Array(16);
      const cipher = await crypto.subtle.encrypt(
        { name: "AES-CTR", counter: zeros, length: 64 },
        this.aesKey,
        zeros,
      );
      return new Uint8Array(cipher);
    } else {
      const zeros = new Uint8Array(16);
      const nonce = new Uint8Array(12); // all zeros for deterministic zeros
      const cipher = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        this.aesKey,
        zeros,
      );
      // Prepend nonce: 12 + 16 + 16 = 44 bytes
      const result = new Uint8Array(12 + cipher.byteLength);
      result.set(nonce, 0);
      result.set(new Uint8Array(cipher), 12);
      return result;
    }
  }

  /** Encrypt a segment of data from a stream. */
  async encrypt(
    streamNum: bigint,
    offset: bigint,
    data: Uint8Array,
  ): Promise<Uint8Array> {
    if (streamNum === 0n) throw new Error("stream number must be nonzero");

    if (this.ver === 1) {
      const blockNum = offset >> 4n;
      const iv = new Uint8Array(16);
      new DataView(iv.buffer).setBigUint64(0, streamNum);
      new DataView(iv.buffer).setBigUint64(8, blockNum);

      const padBytes = Number(offset % 16n);
      const paddedData = new Uint8Array(padBytes + data.length);
      paddedData.set(data, padBytes);

      const encryptedData = await crypto.subtle.encrypt(
        {
          name: "AES-CTR",
          counter: iv,
          length: 64,
        },
        this.aesKey,
        paddedData,
      );
      return new Uint8Array(encryptedData, padBytes, data.length);
    } else {
      const nonce = new Uint8Array(12);
      crypto.getRandomValues(nonce);
      const aad = makeAad(streamNum, offset);
      const cipher = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad as any },
        this.aesKey,
        data as any,
      );
      // Prepend nonce: nonce || ciphertext || tag
      const result = new Uint8Array(12 + cipher.byteLength);
      result.set(nonce, 0);
      result.set(new Uint8Array(cipher), 12);
      return result;
    }
  }

  /** Decrypt a segment of data from a stream. */
  async decrypt(
    streamNum: bigint,
    offset: bigint,
    data: Uint8Array,
  ): Promise<Uint8Array> {
    if (streamNum === 0n) throw new Error("stream number must be nonzero");

    if (this.ver === 1) {
      // CTR mode is self-inverse.
      return this.encrypt(streamNum, offset, data);
    } else {
      if (data.length < 12 + 16) {
        throw new Error("ciphertext too short");
      }
      const nonce = data.slice(0, 12);
      const ciphertext = data.slice(12);
      const aad = makeAad(streamNum, offset);
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad as any },
        this.aesKey,
        ciphertext as any,
      );
      return new Uint8Array(plain);
    }
  }
}

/** Build AAD from stream number and offset. */
function makeAad(streamNum: bigint, offset: bigint): Uint8Array {
  const aad = new Uint8Array(16);
  const view = new DataView(aad.buffer);
  view.setBigUint64(0, streamNum);
  view.setBigUint64(8, offset);
  return aad;
}

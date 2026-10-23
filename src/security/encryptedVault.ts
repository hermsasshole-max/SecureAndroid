import { EncryptedVaultEntry } from './types';

export interface KeyValueStorageAdapter {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  keys(): string[];
}

export class MemoryStorageAdapter implements KeyValueStorageAdapter {
  private map = new Map<string, string>();
  getItem(key: string): string | null {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  keys(): string[] {
    return Array.from(this.map.keys());
  }
}

export class BrowserLocalStorageAdapter implements KeyValueStorageAdapter {
  private prefix: string;
  constructor(prefix = 'aegis_enc_prefs_') {
    this.prefix = prefix;
  }
  getItem(key: string): string | null {
    return window.localStorage.getItem(this.prefix + key);
  }
  setItem(key: string, value: string): void {
    window.localStorage.setItem(this.prefix + key, value);
  }
  removeItem(key: string): void {
    window.localStorage.removeItem(this.prefix + key);
  }
  keys(): string[] {
    const out: string[] = [];
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      if (k && k.startsWith(this.prefix)) {
        out.push(k.slice(this.prefix.length));
      }
    }
    return out;
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * WebCrypto AES-256-GCM encrypted persistence vault mirroring Android's
 * `EncryptedSharedPreferences` (`MasterKey.KeyScheme.AES256_GCM`).
 * Never persists plaintext JSON to underlying storage.
 */
export class EncryptedPreferencesVault {
  private storage: KeyValueStorageAdapter;
  private keyPromise: Promise<CryptoKey> | null = null;
  private static readonly MASTER_KEY_SLOT = '__master_key_raw_v1__';

  constructor(storage: KeyValueStorageAdapter) {
    this.storage = storage;
  }

  private async getOrCreateMasterKey(): Promise<CryptoKey> {
    if (this.keyPromise) return this.keyPromise;

    this.keyPromise = (async () => {
      const existingB64 = this.storage.getItem(EncryptedPreferencesVault.MASTER_KEY_SLOT);
      if (existingB64) {
        const raw = base64ToBytes(existingB64);
        return globalThis.crypto.subtle.importKey(
          'raw',
          raw as BufferSource,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      }

      const generated = await globalThis.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      const exported = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', generated));
      this.storage.setItem(EncryptedPreferencesVault.MASTER_KEY_SLOT, bytesToBase64(exported));

      return globalThis.crypto.subtle.importKey(
        'raw',
        exported as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    })();

    return this.keyPromise;
  }

  async putEncrypted<T>(key: string, value: T): Promise<EncryptedVaultEntry> {
    const cryptoKey = await this.getOrCreateMasterKey();
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const encodedPlaintext = new TextEncoder().encode(JSON.stringify(value));
    const aad = new TextEncoder().encode(key);

    const cipherBuffer = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource },
      cryptoKey,
      encodedPlaintext as BufferSource
    );

    const entry: EncryptedVaultEntry = {
      key,
      ivBase64: bytesToBase64(iv),
      ciphertextBase64: bytesToBase64(new Uint8Array(cipherBuffer)),
      updatedAtIso: new Date().toISOString(),
    };

    this.storage.setItem(key, JSON.stringify(entry));
    return entry;
  }

  async getDecrypted<T>(key: string): Promise<T | null> {
    const raw = this.storage.getItem(key);
    if (!raw) return null;

    const entry = JSON.parse(raw) as EncryptedVaultEntry;
    const cryptoKey = await this.getOrCreateMasterKey();
    const iv = base64ToBytes(entry.ivBase64);
    const ciphertext = base64ToBytes(entry.ciphertextBase64);
    const aad = new TextEncoder().encode(key);

    const plainBuffer = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource },
      cryptoKey,
      ciphertext as BufferSource
    );

    const jsonStr = new TextDecoder().decode(plainBuffer);
    return JSON.parse(jsonStr) as T;
  }

  inspectEncryptedEntries(): EncryptedVaultEntry[] {
    return this.storage
      .keys()
      .filter((k) => k !== EncryptedPreferencesVault.MASTER_KEY_SLOT)
      .map((k) => {
        const raw = this.storage.getItem(k);
        if (!raw) return null;
        try {
          return JSON.parse(raw) as EncryptedVaultEntry;
        } catch {
          return null;
        }
      })
      .filter((item): item is EncryptedVaultEntry => item !== null);
  }
}

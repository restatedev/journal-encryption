import { webcrypto } from "node:crypto";

export class StoredCipherText {
  private static STORED_PREFIX = new TextEncoder().encode("RTv1\0");
  public static IV_LENGTH = 12;
  private static ENCRYPTED_KEY_LENGTH = 184;

  constructor(
    public encryptedDek: Uint8Array,
    public iv: Uint8Array,
    public cipherText: Uint8Array
  ) {}

  static fromArrayBuffer(data: ArrayBuffer): StoredCipherText {
    if (
      data.byteLength <=
      this.STORED_PREFIX.length + this.ENCRYPTED_KEY_LENGTH + this.IV_LENGTH
    ) {
      throw new Error("Invalid data length");
    }

    const prefix = new Uint8Array(data.slice(0, 0 + this.STORED_PREFIX.length));

    if (!this.STORED_PREFIX.every((value, i) => value === prefix[i])) {
      throw new Error("Invalid data prefix");
    }

    const unprefixedData = data.slice(this.STORED_PREFIX.length);

    const encryptedDek = unprefixedData.slice(0, this.ENCRYPTED_KEY_LENGTH);
    const iv = unprefixedData.slice(
      this.ENCRYPTED_KEY_LENGTH,
      this.ENCRYPTED_KEY_LENGTH + this.IV_LENGTH
    );
    const cipherText = unprefixedData.slice(
      this.ENCRYPTED_KEY_LENGTH + this.IV_LENGTH
    );

    return new StoredCipherText(
      new Uint8Array(encryptedDek),
      new Uint8Array(iv),
      new Uint8Array(cipherText)
    );
  }

  async decrypt(decryptingDek: webcrypto.CryptoKey): Promise<ArrayBuffer> {
    return await webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv: this.iv },
      decryptingDek,
      this.cipherText
    );
  }

  static async encrypt(
    encryptedDek: Uint8Array,
    key: webcrypto.CryptoKey,
    data: ArrayBuffer
  ): Promise<StoredCipherText> {
    const iv = webcrypto.getRandomValues(new Uint8Array(this.IV_LENGTH));

    const result = await webcrypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );

    return new StoredCipherText(encryptedDek, iv, new Uint8Array(result));
  }

  toArrayBuffer(): ArrayBuffer {
    if (
      this.encryptedDek.byteLength !== StoredCipherText.ENCRYPTED_KEY_LENGTH
    ) {
      throw new Error("Unexpected encrypted dek length");
    }

    const data = new Uint8Array(
      StoredCipherText.STORED_PREFIX.length +
        StoredCipherText.ENCRYPTED_KEY_LENGTH +
        StoredCipherText.IV_LENGTH +
        this.cipherText.byteLength
    );

    data.set(StoredCipherText.STORED_PREFIX, 0);
    data.set(this.encryptedDek, StoredCipherText.STORED_PREFIX.length);
    data.set(
      this.iv,
      StoredCipherText.STORED_PREFIX.length +
        StoredCipherText.ENCRYPTED_KEY_LENGTH
    );
    data.set(
      this.cipherText,
      StoredCipherText.STORED_PREFIX.length +
        StoredCipherText.ENCRYPTED_KEY_LENGTH +
        StoredCipherText.IV_LENGTH
    );

    return data.buffer;
  }
}

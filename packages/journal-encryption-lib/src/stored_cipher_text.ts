import { webcrypto } from "node:crypto";

export class StoredCipherText {
  private static STORED_PREFIX = Buffer.from("RTv1\0");
  public static IV_LENGTH = 12;
  private static ENCRYPTED_KEY_LENGTH = 184;

  constructor(
    public encryptedDek: Uint8Array,
    public iv: Uint8Array,
    public cipherText: Uint8Array
  ) {}

  static fromBuffer(data: Buffer): StoredCipherText {
    if (
      data.length <=
      this.STORED_PREFIX.length + this.ENCRYPTED_KEY_LENGTH + this.IV_LENGTH
    ) {
      throw new Error("Invalid data length");
    }

    const prefix = data.subarray(0, 0 + this.STORED_PREFIX.length);
    if (!this.STORED_PREFIX.equals(prefix)) {
      throw new Error("Invalid data prefix");
    }

    const unprefixedData = data.subarray(this.STORED_PREFIX.length);

    const encryptedDek = unprefixedData.subarray(0, this.ENCRYPTED_KEY_LENGTH);
    const iv = unprefixedData.subarray(
      this.ENCRYPTED_KEY_LENGTH,
      this.ENCRYPTED_KEY_LENGTH + this.IV_LENGTH
    );
    const cipherText = unprefixedData.subarray(
      this.ENCRYPTED_KEY_LENGTH + this.IV_LENGTH
    );

    return new StoredCipherText(encryptedDek, iv, cipherText);
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

  toBuffer(): Buffer {
    if (this.encryptedDek.length !== StoredCipherText.ENCRYPTED_KEY_LENGTH) {
      throw new Error("Unexpected encrypted dek length");
    }

    const data = Buffer.alloc(
      StoredCipherText.STORED_PREFIX.length +
        StoredCipherText.ENCRYPTED_KEY_LENGTH +
        StoredCipherText.IV_LENGTH +
        this.cipherText.length
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

    return data;
  }
}

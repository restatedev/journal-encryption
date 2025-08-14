import * as crypto from "node:crypto";

export class StoredCipherText {
  private static STORED_PREFIX = new TextEncoder().encode("RTv1\0");
  public static IV_LENGTH = 12;

  constructor(
    public encryptedDek: Uint8Array,
    public iv: Uint8Array,
    public cipherText: Uint8Array
  ) {}

  static fromBytes(data: Uint8Array): StoredCipherText {
    const prefix = new Uint8Array(data.slice(0, 0 + this.STORED_PREFIX.length));

    if (
      prefix.length !== this.STORED_PREFIX.length ||
      !this.STORED_PREFIX.every((value, i) => value === prefix[i])
    ) {
      throw new Error("Invalid stored ciphertext prefix");
    }

    const unprefixedData = data.slice(this.STORED_PREFIX.length);

    const encryptedDekLengthBytes = unprefixedData.slice(0, 2);
    if (encryptedDekLengthBytes.length !== 2) {
      throw new Error("Invalid stored ciphertext length");
    }
    // big endian u16
    const encryptedDekLength =
      encryptedDekLengthBytes[0] * 2 ** 8 + encryptedDekLengthBytes[1];

    const encryptedDek = unprefixedData.slice(2, encryptedDekLength + 2);
    if (encryptedDek.length !== encryptedDekLength) {
      throw new Error("Invalid stored ciphertext length");
    }
    const iv = unprefixedData.slice(
      encryptedDekLength + 2,
      encryptedDekLength + 2 + this.IV_LENGTH
    );
    if (iv.length !== this.IV_LENGTH) {
      throw new Error("Invalid stored ciphertext length");
    }
    const cipherText = unprefixedData.slice(
      encryptedDekLength + 2 + this.IV_LENGTH
    );

    return new StoredCipherText(
      new Uint8Array(encryptedDek),
      new Uint8Array(iv),
      new Uint8Array(cipherText)
    );
  }

  async decrypt(
    decryptingDek: crypto.webcrypto.CryptoKey
  ): Promise<Uint8Array> {
    return new Uint8Array(
      await crypto.webcrypto.subtle.decrypt(
        { name: "AES-GCM", iv: this.iv, tagLength: 128 },
        decryptingDek,
        this.cipherText
      )
    );
  }

  static async encryptAsync(
    encryptedDek: Uint8Array,
    key: crypto.webcrypto.CryptoKey,
    data: Uint8Array
  ): Promise<StoredCipherText> {
    const iv = crypto.webcrypto.getRandomValues(new Uint8Array(this.IV_LENGTH));

    const result = await crypto.webcrypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      data
    );

    return new StoredCipherText(encryptedDek, iv, new Uint8Array(result));
  }

  static encryptSync(
    encryptedDek: Uint8Array,
    key: crypto.KeyObject,
    data: Uint8Array
  ): StoredCipherText {
    const iv = crypto.webcrypto.getRandomValues(new Uint8Array(this.IV_LENGTH));

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, {
      authTagLength: 16,
    });
    const ciphertext = cipher.update(data);
    const padding = cipher.final(); // should be empty for aes-gcm anyway
    const authTag = cipher.getAuthTag();

    return new StoredCipherText(
      encryptedDek,
      iv,
      Buffer.concat([ciphertext, padding, authTag])
    );
  }

  toBytes(): Uint8Array {
    if (this.encryptedDek.length > 255) {
      throw new Error(
        `StoredCipherText cannot store encrypted dek with a length of more than 255; dek was ${this.encryptedDek.length}`
      );
    }

    const data = new Uint8Array(
      StoredCipherText.STORED_PREFIX.length +
        2 +
        this.encryptedDek.length +
        StoredCipherText.IV_LENGTH +
        this.cipherText.byteLength
    );

    data.set(StoredCipherText.STORED_PREFIX, 0);
    data.set(
      // big endian u16
      [this.encryptedDek.length >>> 8, this.encryptedDek.length],
      StoredCipherText.STORED_PREFIX.length
    );
    data.set(this.encryptedDek, StoredCipherText.STORED_PREFIX.length + 2);
    data.set(
      this.iv,
      StoredCipherText.STORED_PREFIX.length + 2 + this.encryptedDek.length
    );
    data.set(
      this.cipherText,
      StoredCipherText.STORED_PREFIX.length +
        2 +
        this.encryptedDek.length +
        StoredCipherText.IV_LENGTH
    );

    return data;
  }
}

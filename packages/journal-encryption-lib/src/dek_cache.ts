import {
  DecryptCommand,
  GenerateDataKeyCommand,
  KMS,
  KMSClient,
} from "@aws-sdk/client-kms";
import { webcrypto } from "node:crypto";

interface EncryptingDek {
  key: webcrypto.CryptoKey;
  encryptedDek: Uint8Array;
}

export class DekCache {
  private kms: KMSClient;
  private encryptingKmsKeyID: string;
  private encryptingDek?: Promise<EncryptingDek>;
  private decryptingDeks: Map<string, Promise<webcrypto.CryptoKey>>;

  constructor({
    kms,
    encryptingKmsKeyID,
  }: {
    kms: KMSClient;
    encryptingKmsKeyID: string;
  }) {
    this.kms = kms;
    this.encryptingKmsKeyID = encryptingKmsKeyID;
    this.encryptingDek = undefined;
    this.decryptingDeks = new Map();
  }

  static cacheKey(encryptedDek: Uint8Array): string {
    return Buffer.from(encryptedDek).toString("base64");
  }

  cacheDecryptingDek(
    encryptedDek: Uint8Array,
    dek: Promise<webcrypto.CryptoKey>
  ) {
    const cacheKey = DekCache.cacheKey(encryptedDek);
    this.decryptingDeks.set(
      cacheKey,
      dek.catch((e) => {
        this.decryptingDeks.delete(cacheKey);
        return Promise.reject(e);
      })
    );
  }

  async getEncryptingDek(): Promise<EncryptingDek> {
    if (this.encryptingDek !== undefined) return this.encryptingDek;

    this.encryptingDek = this.createEncryptingDek()
      .then((dek) => {
        this.cacheDecryptingDek(
          dek.encryptedDek,
          Promise.resolve(dek.decryptingDek)
        );
        return { key: dek.encryptingDek, encryptedDek: dek.encryptedDek };
      })
      .catch((e) => {
        this.encryptingDek = undefined;
        return Promise.reject(e);
      });

    return this.encryptingDek;
  }

  async createEncryptingDek() {
    try {
      const start = new Date();
      const dekResult = await this.kms.send(
        new GenerateDataKeyCommand({
          KeyId: this.encryptingKmsKeyID,
          KeySpec: "AES_256", // 32 byte keys, 184 byte encrypted keys
        })
      );

      if (!dekResult.Plaintext) {
        throw new Error("Missing dek plaintext");
      }
      if (!dekResult.CiphertextBlob) {
        throw new Error("Missing dek ciphertext");
      }

      const [encryptingDek, decryptingDek] = await Promise.all([
        webcrypto.subtle.importKey(
          "raw",
          dekResult.Plaintext,
          "AES-GCM",
          false,
          ["encrypt"]
        ),
        webcrypto.subtle.importKey(
          "raw",
          dekResult.Plaintext,
          "AES-GCM",
          false,
          ["decrypt"]
        ),
      ]);

      console.log(
        `Created encrypting dek against KMS key '${
          this.encryptingKmsKeyID
        }' in ${new Date().valueOf() - start.valueOf()}ms`
      );

      return {
        encryptedDek: dekResult.CiphertextBlob,
        encryptingDek,
        decryptingDek,
      };
    } catch (e) {
      console.log(
        `Failed to create encrypting dek against KMS key '${this.encryptingKmsKeyID}':`,
        e
      );
      throw e;
    }
  }

  async getDecryptingDek(
    encryptedDek: Uint8Array
  ): Promise<webcrypto.CryptoKey> {
    const cacheKey = DekCache.cacheKey(encryptedDek);
    const cachedDek = this.decryptingDeks.get(cacheKey);
    if (cachedDek !== undefined) return cachedDek;

    const dekPromise = this.decryptDek(encryptedDek).catch((e) => {
      this.decryptingDeks.delete(cacheKey);
      return Promise.reject(e);
    });

    this.decryptingDeks.set(cacheKey, dekPromise);

    return dekPromise;
  }

  async decryptDek(encryptedDek: Uint8Array): Promise<webcrypto.CryptoKey> {
    try {
      const start = new Date();
      const dekResult = await this.kms.send(
        new DecryptCommand({
          CiphertextBlob: encryptedDek,
        })
      );

      if (!dekResult.Plaintext) {
        throw new Error("Missing dek plaintext");
      }

      const dek = await webcrypto.subtle.importKey(
        "raw",
        dekResult.Plaintext,
        "AES-GCM",
        false,
        ["decrypt"]
      );

      console.log(
        `Loaded decryping dek in ${new Date().valueOf() - start.valueOf()}ms`
      );

      return dek;
    } catch (e) {
      console.log("Failed to load decrypting dek:", e);
      throw e;
    }
  }
}

import { KMSClient } from "@aws-sdk/client-kms";
import { DekCache } from "./dek_cache.js";
import { StoredCipherText } from "./stored_cipher_text.js";
import { KeyObject } from "node:crypto";

export async function createJournalEntryCodec({
  kms,
  encryptingKmsKeyID,
}: {
  kms: KMSClient;
  encryptingKmsKeyID: string;
}) {
  const dekCache = new DekCache({
    kms,
    encryptingKmsKeyID,
  });
  const encryptingDek = await dekCache.getEncryptingDek();
  const encryptingDekKeyObject = KeyObject.from(encryptingDek.key);

  return {
    encode(buf: Uint8Array): Uint8Array {
      const storedCipherText = StoredCipherText.encryptSync(
        encryptingDek.encryptedDek,
        encryptingDekKeyObject,
        buf
      );

      return storedCipherText.toBytes();
    },
    async decode(buf: Uint8Array): Promise<Uint8Array> {
      const storedCipherText = StoredCipherText.fromBytes(buf);

      const decryptingDek = await dekCache.getDecryptingDek(
        storedCipherText.encryptedDek
      );

      return await storedCipherText.decrypt(decryptingDek);
    },
  };
}

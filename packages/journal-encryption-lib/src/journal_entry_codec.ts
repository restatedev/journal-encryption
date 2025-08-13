import { KMSClient } from "@aws-sdk/client-kms";
import { DekCache } from "./dek_cache.js";
import { StoredCipherText } from "./stored_cipher_text.js";

export function createJournalEntryCodec({
  kms,
  kmsKeyID,
}: {
  kms: KMSClient;
  kmsKeyID: string;
}) {
  const dekCache = new DekCache({
    kms,
    kmsKeyID,
  });
  // start loading this in the background
  dekCache.getEncryptingDek();

  return {
    async encode(buf: Uint8Array): Promise<Uint8Array> {
      const encryptingDek = await dekCache.getEncryptingDek();

      const storedCipherText = await StoredCipherText.encrypt(
        encryptingDek.encryptedDek,
        encryptingDek.key,
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

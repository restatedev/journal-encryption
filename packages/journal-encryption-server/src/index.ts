import { KMSClient } from "@aws-sdk/client-kms";
import { Hono } from "hono";
import { handle } from "hono/aws-lambda";
import { DekCache, StoredCipherText } from "@restatedev/journal-encryption-lib";

const KMS_KEY_ID = process.env.KMS_KEY_ID;
if (!KMS_KEY_ID) {
  throw new Error("Missing environment variable KMS_KEY_ID");
}

const dekCache = new DekCache({
  kms: new KMSClient({}),
  kmsKeyID: KMS_KEY_ID,
});
// kick off getting the first encrypting dek in the background
dekCache.getEncryptingDek();

const app = new Hono();

app.post("/encrypt", async (c) => {
  try {
    const encryptingDek = await dekCache.getEncryptingDek();
    const data = await c.req.arrayBuffer();

    const storedCipherText = await StoredCipherText.encrypt(
      encryptingDek.encryptedDek,
      encryptingDek.key,
      data
    );

    return c.body(storedCipherText.toBuffer(), 200, {
      "Content-Type": "application/octet-stream",
    });
  } catch (e) {
    console.log("Failed to encrypt:", e);
    return c.body("Failed to encrypt", 500);
  }
});

app.post("/decrypt", async (c) => {
  try {
    const data = await c.req.arrayBuffer();

    const storedCipherText = StoredCipherText.fromBuffer(Buffer.from(data));

    const decryptingDek = await dekCache.getDecryptingDek(
      storedCipherText.encryptedDek
    );

    const result = await storedCipherText.decrypt(decryptingDek);

    return c.body(result, 200, {
      "Content-Type": "application/octet-stream",
    });
  } catch (e) {
    console.log("Failed to decrypt:", e);
    return c.body("Failed to decrypt", 500);
  }
});

// so that bun can also serve
export default app;

export const handler = handle(app);

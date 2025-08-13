import { KMSClient } from "@aws-sdk/client-kms";
import { Hono } from "hono";
import { handle } from "hono/aws-lambda";
import { createJournalEntryCodec } from "@restatedev/journal-encryption-lib";
import { cors } from "hono/cors";

const KMS_KEY_ID = process.env.KMS_KEY_ID;
if (!KMS_KEY_ID) {
  throw new Error("Missing environment variable KMS_KEY_ID");
}

const { encode, decode } = createJournalEntryCodec({
  kms: new KMSClient({}),
  encryptingKmsKeyID: KMS_KEY_ID,
});

const app = new Hono();

app.use(
  "/*",
  cors({
    origin: "*",
    allowMethods: ["POST"],
    maxAge: 600,
    credentials: true,
  })
);

app.post("/encrypt", async (c) => {
  try {
    const data = await c.req.arrayBuffer();

    const encryptedData = await encode(new Uint8Array(data));

    return c.body(encryptedData, 200, {
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
    const decryptedData = await decode(new Uint8Array(data));

    return c.body(decryptedData, 200, {
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

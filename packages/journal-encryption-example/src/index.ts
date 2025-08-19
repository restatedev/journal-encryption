import { serve } from "@restatedev/restate-sdk";
import { KMSClient } from "@aws-sdk/client-kms";
import { createJournalEntryCodec } from "@restatedev/journal-encryption-lib";

import { greeter } from "./greeter.js";

const KMS_KEY_ID = process.env.KMS_KEY_ID;
if (!KMS_KEY_ID) {
  throw new Error("Missing environment variable KMS_KEY_ID");
}

serve({
  port: 9080,
  services: [greeter],
  defaultServiceOptions: {
    journalRetention: { days: 1 },
    idempotencyRetention: { days: 1 },
    inactivityTimeout: { minutes: 10 },
  },
  journalValueCodecProvider: () =>
    createJournalEntryCodec({
      kms: new KMSClient({}),
      encryptingKmsKeyID: KMS_KEY_ID,
    }),
});
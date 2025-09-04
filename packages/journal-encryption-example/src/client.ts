import { KMSClient } from "@aws-sdk/client-kms";
import { createJournalEntryCodec } from "@restatedev/journal-encryption-lib";
import { JournalValueCodec } from "@restatedev/restate-sdk";
import * as clients from "@restatedev/restate-sdk-clients";

import { GreeterType } from "./greeter.js";

async function main() {
  const KMS_KEY_ID = process.env.KMS_KEY_ID;
  if (!KMS_KEY_ID) {
    throw new Error("Missing environment variable KMS_KEY_ID");
  }

  const journalValueCodec: JournalValueCodec = await createJournalEntryCodec({
    kms: new KMSClient({}),
    encryptingKmsKeyID: KMS_KEY_ID,
  });

  const restateClient = clients.connect({
    url: "http://localhost:8080",
    journalValueCodec,
  });

  const greet = await restateClient
    .serviceClient({ name: "greeter" } as unknown as GreeterType)
    .greet({ name: "Confidential" });

  console.log("Got response:", greet);
}

main();

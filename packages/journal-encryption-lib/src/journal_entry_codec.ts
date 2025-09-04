import { KMSClient } from "@aws-sdk/client-kms";
import { DekCache, EncryptingDek } from "./dek_cache.js";
import { StoredCipherText } from "./stored_cipher_text.js";
import { KeyObject } from "node:crypto";

type EncryptionState =
  | {
      type: "initialized";
      dekCache: DekCache;
      encryptionDek: EncryptingDek;
      encryptingDekKeyObject: KeyObject;
      counter: number;
    }
  | {
      type: "rotating";
      dekCache: DekCache;
      encryptionDek: EncryptingDek;
      encryptingDekKeyObject: KeyObject;
    };

async function createEncryptionState(
  kms: KMSClient,
  encryptingKmsKeyID: string
): Promise<EncryptionState> {
  const dekCache = new DekCache({
    kms,
    encryptingKmsKeyID,
  });
  const encryptionDek = await dekCache.getEncryptingDek();
  const encryptingDekKeyObject = KeyObject.from(encryptionDek.key);

  return {
    type: "initialized",
    dekCache,
    encryptionDek,
    encryptingDekKeyObject,
    counter: 0,
  };
}

function needsRotation(state: EncryptionState, rotateAfterNumberOfEntries: number) {
  if (state.type === "rotating") {
    return false;
  }
  return state.counter  > rotateAfterNumberOfEntries;
}

function incrementMessageCounter(state: EncryptionState) {
  if (state.type === "initialized") {
    state.counter++;
  }
}


export async function createJournalEntryCodec({
  kms,
  encryptingKmsKeyID,
  rotateAfterNumberOfEntries,
}: {
  kms: KMSClient;
  encryptingKmsKeyID: string;
  rotateAfterNumberOfEntries?: number;
}) {

  // This is the main encryption state. It will be rotated after a certain number of entries.
  // While rotating, it will continue to use the old DEK until the rotation is complete.
  // New entries will use the new DEK.
  let state = await createEncryptionState(kms, encryptingKmsKeyID);

  const rotationThreshold = rotateAfterNumberOfEntries ?? 50_000_000;

  return {
    encode(buf: Uint8Array): Uint8Array {
      incrementMessageCounter(state);

      if (needsRotation(state, rotationThreshold)) {
        // set the current state to rotating, so we don't start multiple rotations
        state = {
          ...state,
          type: "rotating",
        };
        // schedule an asynchronous rotation of the DEK
        createEncryptionState(kms, encryptingKmsKeyID)
          .then((newState) => {
            state = newState;
          })
          .catch((e) => {
            console.error("Failed to rotate DEK:", e);
            process.exit(1);
          });
      }

      const storedCipherText = StoredCipherText.encryptSync(
        state.encryptionDek.encryptedDek,
        state.encryptingDekKeyObject,
        buf
      );

      return storedCipherText.toBytes();
    },

    async decode(buf: Uint8Array): Promise<Uint8Array> {
      const storedCipherText = StoredCipherText.fromBytes(buf);

      const decryptingDek = await state.dekCache.getDecryptingDek(
        storedCipherText.encryptedDek
      );

      return await storedCipherText.decrypt(decryptingDek);
    },
  };
}

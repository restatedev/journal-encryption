# A Journal Encryption Example

This project is a reference implementation of [JournalValueCodec](https://github.com/restatedev/sdk-typescript/blob/main/packages/libs/restate-sdk-core/src/entry_codec.ts) to support journal encryption/decryption in the TypeScript SDK.

```ts
export type JournalValueCodec = {
  encode(buf: Uint8Array): Uint8Array;
  decode(buf: Uint8Array): Promise<Uint8Array>;
};
```

This project provides a reference implementation that uses Amazon's KMS to manage encryption keys.
This reference implementation obtains a DEK provided by the KMS on startup, to obtain a fresh AES-GCM-256 key.
Each value is encrypted with that key before leaving the SDK.
The encrypted values are structured to include a prefix containing the encrypted version of the Data Encryption Key (DEK) returned by Amazon KMS. This design ensures that the necessary key information is always bundled with the encrypted data, enabling decryption.

Here’s an ASCII representation of the value frame:

```
+--------+---------------------+--------------------+
| RTv1\0 | Encrypted DEK (KMS) | Encrypted Payload  |
+--------+---------------------+--------------------+
```

- **Encrypted DEK (KMS)**: The Data Encryption Key encrypted using Amazon KMS.
- **Encrypted Payload**: The actual data encrypted with the DEK using AES-GCM-256. 

NOTE: If you prefer, you can create a simpler implementation that uses a static key stored in a secret store and reference that in the encrypted payload. It is up to the individual organization's requirements and available tools.

## What is actually being encrypted?

* The input and output parameters to the handler
* `ctx.run()` blocks 
* RPC calls parameters and return values (service to service invocations)
* State values
* Awakeables
* Durable promises

## Project Structure

This repository is organized into the following components:

* **`journal-encryption-lib`**: A library implementing the `JournalValueCodec` interface, utilizing Amazon KMS for encryption and decryption key management.
* **`journal-encryption-server`**: A server designed to run in a secure environment, providing decryption service for the restate client UI.
* **`journal-encryption-example`**: A sample implementation showcasing how to use the library in a Restate greeter service.

## Getting Started

To get started with this project:

1. Clone the repository:
  ```bash
  git clone git@github.com:restatedev/journal-encryption.git 
  cd journal-encryption
  ```

2. Install dependencies:
  ```bash
  npm install
  npm run build
  ```

3. Set up your environment:
  - Ensure you have access to an Amazon KMS key.
  - Provision a key, and obtain a key ID to use.
  - Set the `KMS_KEY_ID` environment variable to your KMS key ID.

4. Run the decryption server locally:
  ```bash
  export KMS_KEY_ID=your-kms-key-id 
  cd packages/journal-encryption-server
  npm install
  npm build
  npm start
  ```

5. Explore the example:
  - Navigate to the `journal-encryption-example` directory to see how to integrate this lib into a restate service.
  - To start locally

  ```bash
  export KMS_KEY_ID=your-kms-key-id 
  cd packages/journal-encryption-example
  npm run dev
  ```

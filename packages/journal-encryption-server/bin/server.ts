#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { JournalEncryptionServerStack } from "../lib/server-stack";

const app = new cdk.App();
new JournalEncryptionServerStack(app, "JournalEncryptionServerStack", {
  env: {
    region: "eu-central-1",
  },
});

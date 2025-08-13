import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as kms from "aws-cdk-lib/aws-kms";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";

export class JournalEncryptionServerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const kmsKey = new kms.Key(this, "key", {});

    const fn = new NodejsFunction(this, "lambda", {
      entry: "src/index.ts",
      handler: "handler",
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        KMS_KEY_ID: kmsKey.keyId,
      },
    });
    kmsKey.grantEncryptDecrypt(fn);
    const fnUrl = fn.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.NONE,
    });

    new cdk.CfnOutput(this, "lambdaUrl", {
      value: fnUrl.url!,
    });
    new cdk.CfnOutput(this, "kmsKey", {
      value: kmsKey.keyArn,
    });
  }
}

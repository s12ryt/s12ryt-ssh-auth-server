import { Readable } from "node:stream";

import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
  type S3ClientConfig,
} from "@aws-sdk/client-s3";

import type { S3ConnectionSecret } from "../domain/models.js";
import type { S3Download, S3Gateway, S3Object } from "../proxy/gateways.js";

interface S3ClientLike {
  send(
    command: object,
    options?: { abortSignal?: AbortSignal },
  ): Promise<unknown>;
}

type S3ClientFactory = (secret: S3ConnectionSecret) => S3ClientLike;

export class AwsS3Gateway implements S3Gateway {
  constructor(private readonly clientFactory: S3ClientFactory = createClient) {}

  async test(secret: S3ConnectionSecret, signal: AbortSignal): Promise<void> {
    const client = this.clientFactory(secret);
    await client.send(
      new ListObjectsV2Command({
        Bucket: secret.bucket,
        Prefix: secret.prefix,
        MaxKeys: 1,
      }),
      { abortSignal: signal },
    );
  }

  async list(
    secret: S3ConnectionSecret,
    prefix: string,
    signal: AbortSignal,
  ): Promise<S3Object[]> {
    const client = this.clientFactory(secret);
    const objects: S3Object[] = [];
    let continuationToken: string | undefined;
    do {
      const response = (await client.send(
        new ListObjectsV2Command({
          Bucket: secret.bucket,
          Prefix: prefix,
          ContinuationToken: continuationToken,
        }),
        { abortSignal: signal },
      )) as {
        Contents?: Array<{ Key?: string; Size?: number; LastModified?: Date }>;
        IsTruncated?: boolean;
        NextContinuationToken?: string;
      };
      for (const object of response.Contents ?? []) {
        if (!object.Key) continue;
        const item: S3Object = { key: object.Key, size: object.Size ?? 0 };
        if (object.LastModified)
          item.lastModified = object.LastModified.toISOString();
        objects.push(item);
      }
      continuationToken = response.IsTruncated
        ? response.NextContinuationToken
        : undefined;
    } while (continuationToken);
    return objects;
  }

  async upload(
    secret: S3ConnectionSecret,
    key: string,
    body: AsyncIterable<Uint8Array>,
    signal: AbortSignal,
  ): Promise<number> {
    const client = this.clientFactory(secret);
    let bytes = 0;
    const counted = Readable.from(
      (async function* () {
        for await (const chunk of body) {
          bytes += chunk.byteLength;
          yield chunk;
        }
      })(),
    );
    await client.send(
      new PutObjectCommand({ Bucket: secret.bucket, Key: key, Body: counted }),
      {
        abortSignal: signal,
      },
    );
    return bytes;
  }

  async download(
    secret: S3ConnectionSecret,
    key: string,
    signal: AbortSignal,
  ): Promise<S3Download> {
    const client = this.clientFactory(secret);
    const response = (await client.send(
      new GetObjectCommand({ Bucket: secret.bucket, Key: key }),
      { abortSignal: signal },
    )) as { Body?: unknown; ContentLength?: number; ContentType?: string };
    const body = toReadable(response.Body);
    const download: S3Download = { body };
    if (response.ContentLength !== undefined)
      download.contentLength = response.ContentLength;
    if (response.ContentType !== undefined)
      download.contentType = response.ContentType;
    return download;
  }

  async delete(
    secret: S3ConnectionSecret,
    key: string,
    signal: AbortSignal,
  ): Promise<void> {
    const client = this.clientFactory(secret);
    await client.send(
      new DeleteObjectCommand({ Bucket: secret.bucket, Key: key }),
      {
        abortSignal: signal,
      },
    );
  }
}

function createClient(secret: S3ConnectionSecret): S3Client {
  const config: S3ClientConfig = {
    region: secret.region,
    endpoint: secret.endpoint,
    forcePathStyle: secret.usePathStyle,
    credentials: {
      accessKeyId: secret.accessKeyId,
      secretAccessKey: secret.secretAccessKey,
    },
  };
  return new S3Client(config);
}

function toReadable(body: unknown): Readable {
  if (body instanceof Readable) return body;
  if (
    body &&
    typeof (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator] ===
      "function"
  ) {
    return Readable.from(body as AsyncIterable<Uint8Array>);
  }
  throw new Error("S3 response body is not readable");
}

import type { Request, Response } from "express";
import Busboy from "busboy";
import type { Readable } from "node:stream";
import { createResponseDiagnostic, FichierClient, FichierError, parseUploadLinks, uploadStatusUrl, type FichierResponseDiagnostic } from "./1fichier.js";

const MAX_MULTIPART_OVERHEAD = 1024 * 1024;

interface UploadResult {
  filename: string;
  size: number;
  links: string[];
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function parseSafeSize(value: string | undefined): number | null {
  if (!value || !/^\d+$/.test(value)) return null;
  const size = Number(value);
  return Number.isSafeInteger(size) && size >= 0 ? size : null;
}

function errorMessage(error: unknown): string {
  if (error instanceof FichierError) {
    return error.upstreamMessage ? `${error.message}: ${error.upstreamMessage}` : error.message;
  }
  return error instanceof Error ? error.message : "Upload failed";
}

function errorResponse(error: unknown): FichierResponseDiagnostic {
  if (error instanceof FichierError && error.response) return error.response;
  return createResponseDiagnostic(undefined, { error: error instanceof Error ? error.message : "Upload failed" });
}

async function processFile(
  file: Readable,
  filename: string,
  size: number,
  client: FichierClient,
): Promise<UploadResult> {
  const server = await client.getUploadServer();
  const uploadResponse = await client.uploadMultipart(server, filename, size, file);
  if (uploadResponse.statusCode === 500) {
    let body: unknown = uploadResponse.body;
    try { body = uploadResponse.body ? JSON.parse(uploadResponse.body) as unknown : {}; } catch { /* preserve bounded text */ }
    throw new FichierError("1fichier rejected the upload", 500, typeof body === "string" ? body : undefined, createResponseDiagnostic(500, body));
  }
  if (uploadResponse.statusCode !== 200 && uploadResponse.statusCode !== 302) {
    let body: unknown = uploadResponse.body;
    try { body = uploadResponse.body ? JSON.parse(uploadResponse.body) as unknown : {}; } catch { /* preserve bounded text */ }
    throw new FichierError("1fichier returned an unexpected upload response", uploadResponse.statusCode, typeof body === "string" ? body : undefined, createResponseDiagnostic(uploadResponse.statusCode, body));
  }

  let immediateBody: unknown = null;
  if (uploadResponse.body) {
    try {
      immediateBody = JSON.parse(uploadResponse.body) as unknown;
    } catch {
      immediateBody = null;
    }
  }
  const status = await client.getUploadStatus(uploadStatusUrl(uploadResponse, server), server.id);
  const links = [...new Set([...parseUploadLinks(immediateBody), ...parseUploadLinks(status)])];
  if (links.length === 0) throw new FichierError("Upload finished without a download link");
  return { filename, size, links };
}

export async function handleUpload(
  request: Request,
  response: Response,
  client: FichierClient,
  maxUploadBytes: number,
): Promise<void> {
  const contentLength = parseSafeSize(headerValue(request.headers["content-length"]));
  if (contentLength === null) {
    response.status(411).json({ error: "A Content-Length header is required for streamed uploads" });
    return;
  }
  if (contentLength > maxUploadBytes + MAX_MULTIPART_OVERHEAD) {
    response.status(413).json({ error: "Upload is larger than the configured maximum" });
    return;
  }
  const declaredSize = parseSafeSize(headerValue(request.headers["x-file-size"]));
  if (declaredSize === null) {
    response.status(400).json({ error: "X-File-Size must contain the file size in bytes" });
    return;
  }
  if (declaredSize > maxUploadBytes) {
    response.status(413).json({ error: "File is larger than the configured maximum" });
    return;
  }
  if (contentLength < declaredSize) {
    response.status(400).json({ error: "Content-Length is smaller than the declared file size" });
    return;
  }

  const contentType = headerValue(request.headers["content-type"]);
  if (!contentType?.toLowerCase().startsWith("multipart/form-data")) {
    response.status(415).json({ error: "Upload must use multipart/form-data" });
    return;
  }

  let seenFile = false;
  let processing: Promise<UploadResult> | undefined;
  const result = await new Promise<UploadResult>((resolve, reject) => {
    let parser: ReturnType<typeof Busboy>;
    try {
      parser = Busboy({ headers: request.headers, limits: { files: 2, fields: 4, fileSize: maxUploadBytes } });
    } catch {
      reject(new Error("Invalid multipart upload"));
      return;
    }

    parser.on("file", (_fieldName, file, info) => {
      if (seenFile) {
        file.resume();
        reject(new Error("Upload one file per request"));
        return;
      }
      seenFile = true;
      processing = processFile(file, info.filename || "upload.bin", declaredSize, client);
      processing.catch((error: unknown) => {
        // Keep consuming an incoming body after a control-plane failure so a
        // client cannot leave the connection half-open while we respond.
        file.resume();
        reject(error);
      });
      file.on("limit", () => reject(new Error("File is larger than the configured maximum")));
    });
    parser.on("filesLimit", () => reject(new Error("Upload one file per request")));
    parser.on("error", reject);
    parser.on("finish", () => {
      if (!seenFile) {
        reject(new Error("No file was supplied"));
        return;
      }
      if (!processing) {
        reject(new Error("No file was supplied"));
        return;
      }
      processing.then(resolve, reject);
    });
    request.pipe(parser);
  }).catch((error: unknown) => {
    throw error;
  });

  response.status(200).json({ ok: true, file: result });
}

export function sendUploadError(response: Response, error: unknown): void {
  const status = error instanceof FichierError && error.statusCode === 500 ? 502 : 502;
  response.status(status).json({ error: errorMessage(error), response: errorResponse(error) });
}

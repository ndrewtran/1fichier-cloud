import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, Response } from "express";

const SESSION_COOKIE = "1fichier_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

interface SessionPayload {
  issuedAt: number;
  expiresAt: number;
  nonce: string;
}

export interface LoginThrottle {
  allowed: boolean;
  retryAfterSeconds: number;
}

interface FailureRecord {
  count: number;
  firstFailureAt: number;
  blockedUntil: number;
}

export class LoginThrottleStore {
  private readonly records = new Map<string, FailureRecord>();
  private readonly windowMs = 15 * 60 * 1000;
  private readonly maxFailures = 5;
  private readonly blockMs = 15 * 60 * 1000;

  public check(key: string, now = Date.now()): LoginThrottle {
    const record = this.records.get(key);
    if (!record) return { allowed: true, retryAfterSeconds: 0 };
    if (record.blockedUntil > now) {
      return { allowed: false, retryAfterSeconds: Math.ceil((record.blockedUntil - now) / 1000) };
    }
    if (now - record.firstFailureAt > this.windowMs) {
      this.records.delete(key);
    }
    return { allowed: true, retryAfterSeconds: 0 };
  }

  public recordFailure(key: string, now = Date.now()): LoginThrottle {
    const current = this.records.get(key);
    if (!current || now - current.firstFailureAt > this.windowMs) {
      const next: FailureRecord = { count: 1, firstFailureAt: now, blockedUntil: 0 };
      this.records.set(key, next);
      return { allowed: true, retryAfterSeconds: 0 };
    }
    current.count += 1;
    if (current.count >= this.maxFailures) current.blockedUntil = now + this.blockMs;
    return this.check(key, now);
  }

  public clear(key: string): void {
    this.records.delete(key);
  }
}

function encode(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function decode(value: string): string | null {
  try {
    return Buffer.from(value, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

function signature(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createSession(secret: string, now = Date.now()): string {
  const payload: SessionPayload = {
    issuedAt: now,
    expiresAt: now + SESSION_TTL_MS,
    nonce: randomBytes(18).toString("base64url"),
  };
  const encodedPayload = encode(JSON.stringify(payload));
  return `${encodedPayload}.${signature(encodedPayload, secret)}`;
}

export function verifySession(value: string | undefined, secret: string, now = Date.now()): boolean {
  if (!value) return false;
  const parts = value.split(".");
  if (parts.length !== 2) return false;
  const [encodedPayload, suppliedSignature] = parts;
  if (!encodedPayload || !suppliedSignature) return false;
  const expectedSignature = signature(encodedPayload, secret);
  const expectedBuffer = Buffer.from(expectedSignature, "utf8");
  const suppliedBuffer = Buffer.from(suppliedSignature, "utf8");
  if (expectedBuffer.length !== suppliedBuffer.length || !timingSafeEqual(expectedBuffer, suppliedBuffer)) return false;
  const decoded = decode(encodedPayload);
  if (!decoded) return false;
  try {
    const payload = JSON.parse(decoded) as SessionPayload;
    return Number.isSafeInteger(payload.issuedAt)
      && Number.isSafeInteger(payload.expiresAt)
      && typeof payload.nonce === "string"
      && payload.expiresAt > now
      && payload.issuedAt <= now;
  } catch {
    return false;
  }
}

export function setSessionCookie(response: Response, secret: string, secure: boolean): void {
  response.cookie(SESSION_COOKIE, createSession(secret), {
    httpOnly: true,
    sameSite: "lax",
    secure,
    maxAge: SESSION_TTL_MS,
    path: "/",
  });
}

export function clearSessionCookie(response: Response, secure: boolean): void {
  response.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: "lax", secure, path: "/" });
}

export function hasValidSession(request: Request, secret: string): boolean {
  const cookieHeader = request.headers.cookie;
  if (!cookieHeader) return false;
  const cookie = cookieHeader.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  return verifySession(cookie?.slice(SESSION_COOKIE.length + 1), secret);
}

export function sessionCookieName(): string {
  return SESSION_COOKIE;
}

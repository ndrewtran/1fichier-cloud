export interface AppConfig {
  appPassword: string;
  sessionSecret: string;
  apiKey: string;
  host: string;
  port: number;
  nodeEnv: string;
  cookieSecure: boolean;
  maxUploadBytes: number;
}

const DEFAULT_MAX_UPLOAD_BYTES = 300 * 1024 * 1024 * 1024;

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function positiveInteger(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

export function loadConfig(): AppConfig {
  const nodeEnv = process.env.NODE_ENV ?? "development";
  const cookieSecureValue = process.env.COOKIE_SECURE;
  const cookieSecure = cookieSecureValue
    ? cookieSecureValue.toLowerCase() === "true"
    : nodeEnv === "production";

  return {
    appPassword: required("APP_PASSWORD"),
    sessionSecret: required("SESSION_SECRET"),
    apiKey: required("1FICHIER_API_KEY"),
    host: process.env.HOST ?? "0.0.0.0",
    port: positiveInteger("PORT", 3000),
    nodeEnv,
    cookieSecure,
    maxUploadBytes: positiveInteger("MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES),
  };
}

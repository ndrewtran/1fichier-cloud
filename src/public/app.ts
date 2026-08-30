interface UploadItem {
  id: string;
  file: File;
  status: "queued" | "uploading" | "complete" | "error";
  progress: number;
  error?: string;
  links: string[];
}

interface DownloadItem {
  id: string;
  link: string;
  status: "ready" | "started" | "error";
  token?: string;
  error?: string;
}

type ApiStatus = "checking" | "connected" | "not_configured" | "invalid_key" | "unavailable";

type ActivityLevel = "info" | "warn" | "error";
type ActivityOperation = "session" | "upload" | "download" | "queue" | "api" | "client";

// Four lifecycle entries per file covers a realistic 500-file batch while retaining session/API diagnostics.
const MAX_ACTIVITY_ENTRIES = 2_000;

interface ActivityResponse {
  status?: number;
  body?: unknown;
}

interface ActivityLogEntry {
  id: string;
  timestamp: string;
  level: ActivityLevel;
  operation: ActivityOperation;
  context: string;
  title: string;
  detail: string;
  response?: ActivityResponse;
}

const loginView = element("login-view");
const deskView = element("desk-view");
const loginForm = element<HTMLFormElement>("login-form");
const loginError = element("login-error");
const passwordInput = element<HTMLInputElement>("password");
const fileInput = element<HTMLInputElement>("file-input");
const fileStatus = element("file-status");
const uploadQueue = element("upload-queue");
const uploadStatus = element("upload-status");
const uploadLimit = element("upload-limit");
const linkForm = element<HTMLFormElement>("link-form");
const linkInput = element<HTMLTextAreaElement>("link-input");
const linkPassword = element<HTMLInputElement>("link-password");
const downloadQueue = element("download-queue");
const downloadStatus = element("download-status");
const activityList = element("activity-list");
const activityLog = element("activity-log");
const activityDrawer = element("activity-drawer");
const drawerPeek = element("drawer-peek");
const drawerPeekLabel = element("drawer-peek-label");
const drawerRestore = element<HTMLButtonElement>("drawer-restore");
const drawerMinimize = element<HTMLButtonElement>("drawer-minimize");
const drawerOpen = element<HTMLButtonElement>("drawer-open");
const activityCount = element("activity-count");
const transferCount = element("transfer-count");
const logoutButton = element<HTMLButtonElement>("logout-button");
const apiStatus = element("api-status");

const uploads: UploadItem[] = [];
const downloads: DownloadItem[] = [];
const activities: ActivityLogEntry[] = [];
let processingUploads = false;
let apiStatusRequest = 0;
let selectedActivityId: string | undefined;
let drawerState: "closed" | "minimized" | "open" = "closed";
let lastLoggedApiStatus: Exclude<ApiStatus, "checking"> | undefined;
let sessionGeneration = 0;
let logoutPending = false;

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing element: ${id}`);
  return found as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function errorText(value: unknown, fallback: string): string {
  return isRecord(value) && typeof value.error === "string" ? value.error : fallback;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character);
}

const sensitiveResponseKey = /authorization|(?:api[_-]?)?key|password|passwd|cookie|secret|session|credential|bearer|token|auth(?:entication|orization)?|pass(?:word|phrase)?/i;

function sanitizeResponseText(value: string): string {
  return value
    .slice(0, 4_096)
    .replace(/https?:\/\/[^/\s@]+:[^@\s]+@/gi, "https://[redacted]@")
    .replace(/(["']?)(authorization|(?:api[_-]?)?key|password|passwd|cookie|secret|session|credential|bearer|token|auth(?:entication|orization)?|pass(?:word|phrase)?)\1\s*[:=]\s*(?:(?:bearer|basic)\s+)?(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi, (_match, quote: string, key: string) => `${quote}${key}${quote}: [redacted]`);
}

function sanitizeResponseValue(value: unknown, depth = 0): unknown {
  if (depth > 4) return "[truncated]";
  if (typeof value === "string") return sanitizeResponseText(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : "[invalid number]";
  if (typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 24).map((item) => sanitizeResponseValue(item, depth + 1));
  if (!isRecord(value)) return "[unsupported value]";
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value).slice(0, 32)) {
    if (sensitiveResponseKey.test(key)) continue;
    result[key.slice(0, 80)] = sanitizeResponseValue(item, depth + 1);
  }
  return result;
}

function responseDiagnostic(status: number | undefined, body: unknown, fallback: string): ActivityResponse {
  const nested = isRecord(body) && isRecord(body.response) ? body.response : undefined;
  if (nested) {
    const nestedStatus = typeof nested.status === "number" ? nested.status : status;
    const nestedBody = nested.body;
    return { ...(nestedStatus !== undefined ? { status: nestedStatus } : {}), ...(nestedBody !== undefined ? { body: sanitizeResponseValue(nestedBody) } : {}) };
  }
  return {
    ...(status !== undefined ? { status } : {}),
    body: sanitizeResponseValue(body ?? { error: fallback }),
  };
}

function syntheticResponse(kind: string, message: string, name?: string): ActivityResponse {
  return { body: { kind, message: sanitizeResponseText(message), ...(name ? { name: sanitizeResponseText(name) } : {}) } };
}

function errorDetails(error: unknown, fallback: string): { message: string; name?: string } {
  if (!(error instanceof Error)) return { message: fallback };
  const message = error.message ? sanitizeResponseText(error.message) : fallback;
  const name = error.name ? sanitizeResponseText(error.name) : undefined;
  return name ? { message, name } : { message };
}

function responseText(response: ActivityResponse | undefined): string {
  if (!response) return "No response details available";
  const body = response.body;
  const serialized = typeof body === "string" ? body : JSON.stringify(body);
  const status = response.status === undefined ? "status unavailable" : `HTTP ${response.status}`;
  return `${status}${serialized ? `\n${serialized}` : ""}`.slice(0, 4_096);
}

function displayBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = "B";
  for (const candidate of units) {
    value /= 1024;
    unit = candidate;
    if (value < 1024) break;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${unit}`;
}

function newId(): string {
  return crypto.randomUUID();
}

function setVisible(authenticated: boolean): void {
  loginView.hidden = authenticated;
  deskView.hidden = !authenticated;
  if (authenticated) fileInput.focus();
  else passwordInput.focus();
}

function setApiStatus(status: ApiStatus): void {
  const statusClass = status === "connected" ? "status--ok" : status === "invalid_key" || status === "unavailable" ? "status--error" : status === "not_configured" ? "status--waiting" : "status--working";
  const statusCopy = status === "connected" ? "API connected" : status === "not_configured" ? "API not configured" : status === "invalid_key" ? "API key invalid" : status === "unavailable" ? "API unavailable" : "API checking";
  apiStatus.className = `status ${statusClass}`;
  apiStatus.textContent = statusCopy;
}

function resetApiStatus(): void {
  apiStatusRequest += 1;
  setApiStatus("checking");
}

function clearSessionState(): void {
  sessionGeneration += 1;
  activities.length = 0;
  selectedActivityId = undefined;
  drawerState = "closed";
  lastLoggedApiStatus = undefined;
  resetApiStatus();
  processingUploads = false;
  uploads.length = 0;
  downloads.length = 0;
  linkInput.value = "";
  linkPassword.value = "";
  fileStatus.textContent = "No files selected";
  const button = linkForm.querySelector<HTMLButtonElement>("button[type=submit]");
  if (button) button.disabled = false;
  renderUploads();
  renderDownloads();
  renderActivity();
}

function addActivity(
  title: string,
  detail: string,
  level: ActivityLevel = "info",
  operation: ActivityOperation = "client",
  context = title,
  response?: ActivityResponse,
): void {
  const entry: ActivityLogEntry = {
    id: newId(),
    timestamp: new Date().toISOString(),
    level,
    operation,
    context,
    title,
    detail,
    ...(level === "error" ? { response: response ?? syntheticResponse("client", detail) } : response ? { response } : {}),
  };
  activities.unshift(entry);
  activities.splice(MAX_ACTIVITY_ENTRIES);
  if (selectedActivityId && !activities.some((activity) => activity.id === selectedActivityId)) selectedActivityId = undefined;
  renderActivity();
}

function activityTime(timestamp: string): string {
  return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function activityLevelClass(level: ActivityLevel): string {
  return `log-level--${level}`;
}

function renderActivity(): void {
  const recent = activities.slice(0, 6);
  activityList.innerHTML = recent.length > 0
    ? recent.map((activity) => `<li><button class="activity-item" type="button" aria-pressed="${activity.id === selectedActivityId}" aria-controls="activity-drawer" data-activity-id="${escapeHtml(activity.id)}"><strong>${escapeHtml(activity.title)}</strong><span class="activity-detail${activity.level === "error" ? " error" : ""}">${escapeHtml(activity.detail)}</span><span class="activity-meta"><span>${activity.level.toUpperCase()}</span><time datetime="${escapeHtml(activity.timestamp)}">${escapeHtml(activityTime(activity.timestamp))}</time></span></button></li>`).join("")
    : "<li class=\"activity-empty\">No activity yet</li>";
  activityCount.textContent = String(activities.length);
  activityLog.innerHTML = activities.map((activity) => {
    const response = activity.level === "error" ? `<details class="log-response"><summary>Response</summary><pre>${escapeHtml(responseText(activity.response))}</pre></details>` : "";
    return `<li id="log-${escapeHtml(activity.id)}" class="log-line${activity.id === selectedActivityId ? " is-selected" : ""}" tabindex="-1" data-log-id="${escapeHtml(activity.id)}" data-level="${activity.level}"><time class="log-time" datetime="${escapeHtml(activity.timestamp)}">${escapeHtml(activityTime(activity.timestamp))}</time><span class="log-level ${activityLevelClass(activity.level)}">${activity.level.toUpperCase()}</span><span class="log-source">${escapeHtml(activity.operation)}</span><span class="log-message"><strong>${escapeHtml(activity.title)}</strong> ${escapeHtml(activity.detail)}<span class="log-context">${escapeHtml(activity.context)}</span>${response}</span></li>`;
  }).join("");
  renderDrawer();
}

function renderDrawer(): void {
  activityDrawer.hidden = drawerState !== "open";
  drawerPeek.hidden = drawerState !== "minimized";
  drawerOpen.hidden = drawerState !== "closed" || activities.length === 0;
  const selected = activities.find((activity) => activity.id === selectedActivityId);
  drawerPeekLabel.textContent = selected ? `Activity log minimized · ${selected.title} selected` : "Activity log minimized";
}

function selectActivity(id: string): void {
  if (!activities.some((activity) => activity.id === id)) return;
  selectedActivityId = id;
  drawerState = "open";
  renderActivity();
  focusDrawerContent();
}

function focusDrawerContent(): void {
  window.requestAnimationFrame(() => {
    const selected = selectedActivityId ? document.getElementById(`log-${selectedActivityId}`) : null;
    if (selected instanceof HTMLElement) {
      selected.scrollIntoView({ block: "nearest" });
      selected.focus({ preventScroll: true });
      return;
    }
    drawerMinimize.focus();
  });
}

function renderUploads(): void {
  uploadQueue.innerHTML = uploads.map((item) => {
    const statusCopy = item.status === "uploading"
      ? `Uploading · ${item.progress}%`
      : item.status === "complete" ? "Upload complete" : item.status === "error" ? item.error ?? "Upload failed" : "Waiting for slot";
    const statusClass = item.status === "complete" ? "status--ok" : item.status === "error" ? "status--error" : item.status === "uploading" ? "status--working" : "status--waiting";
    const links = item.links.length > 0
      ? `<span class="result-links">${item.links.map((link) => `<a href="${escapeHtml(link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(link)}</a>`).join("")}</span>`
      : "";
    return `<li class="queue-row"><div class="queue-main"><span class="queue-name" title="${escapeHtml(item.file.name)}">${escapeHtml(item.file.name)}</span><span class="queue-meta">${displayBytes(item.file.size)}</span></div>${item.status === "uploading" ? `<div class="progress" aria-label="Upload progress: ${item.progress} percent"><span style="width: ${item.progress}%"></span></div>` : ""}<div class="queue-detail"><span class="${statusClass === "status--error" ? "error-copy" : statusClass}">${escapeHtml(statusCopy)}</span>${item.status === "error" ? `<button type="button" data-retry-upload="${item.id}">Retry</button>` : `<span>${item.status === "complete" ? `${item.links.length} link${item.links.length === 1 ? "" : "s"} ready` : ""}</span>`}</div>${links}</li>`;
  }).join("");
  const active = uploads.filter((item) => item.status === "uploading").length;
  const pending = uploads.filter((item) => item.status === "queued").length;
  uploadStatus.className = `status ${active > 0 ? "status--working" : pending > 0 ? "status--waiting" : "status--ok"}`;
  uploadStatus.textContent = active > 0 ? `${active} active` : pending > 0 ? `${pending} waiting` : uploads.length > 0 ? "complete" : "ready";
  transferCount.textContent = String(uploads.filter((item) => item.status === "uploading" || item.status === "queued").length + downloads.filter((item) => item.status === "ready").length);
}

function renderDownloads(): void {
  downloadQueue.innerHTML = downloads.map((item) => {
    const statusCopy = item.status === "ready" ? "Token ready · expires in about five minutes" : item.status === "started" ? "Download started" : item.error ?? "Could not create token";
    const button = item.status === "ready" ? `<button type="button" data-start-download="${item.id}">Start download</button>` : "";
    return `<li class="queue-row"><div class="queue-main"><span class="queue-name" title="${escapeHtml(item.link)}">${escapeHtml(item.link)}</span><span class="queue-meta">1fichier</span></div><div class="queue-detail"><span class="${item.status === "error" ? "error-copy" : item.status === "started" ? "status status--ok" : "status status--waiting"}">${escapeHtml(statusCopy)}</span>${button}</div></li>`;
  }).join("");
  const ready = downloads.filter((item) => item.status === "ready").length;
  downloadStatus.className = `status ${ready > 0 ? "status--waiting" : downloads.some((item) => item.status === "error") ? "status--error" : "status--ok"}`;
  downloadStatus.textContent = ready > 0 ? `${ready} ready` : downloads.length > 0 ? "complete" : "ready";
  transferCount.textContent = String(uploads.filter((item) => item.status === "uploading" || item.status === "queued").length + ready);
}

function parseResponse(value: string): unknown {
  const text = value.trim();
  if (!text) return null;
  try { return JSON.parse(text) as unknown; } catch { return sanitizeResponseText(text); }
}

function isApiStatus(value: unknown): value is Exclude<ApiStatus, "checking"> {
  return value === "connected" || value === "not_configured" || value === "invalid_key" || value === "unavailable";
}

function recordApiStatus(status: Exclude<ApiStatus, "checking">, diagnostic?: ActivityResponse): void {
  if (status === lastLoggedApiStatus) return;
  lastLoggedApiStatus = status;
  if (status === "connected") {
    addActivity("1fichier API", "API connected", "info", "api", "1fichier API");
  } else if (status === "not_configured") {
    addActivity("1fichier API", "API key is not configured", "warn", "api", "1fichier API");
  } else {
    addActivity("1fichier API", status === "invalid_key" ? "API key is invalid" : "API unavailable", "error", "api", "1fichier API", diagnostic ?? syntheticResponse("api", status === "invalid_key" ? "API key is invalid" : "API unavailable"));
  }
}

async function refreshApiStatus(): Promise<void> {
  const requestId = ++apiStatusRequest;
  setApiStatus("checking");
  try {
    const response = await fetch("/api/1fichier/status", { credentials: "same-origin" });
    const body = parseResponse(await response.text());
    if (response.status === 401) {
      if (requestId !== apiStatusRequest) return;
      clearSessionState();
      setVisible(false);
      loginError.textContent = "Session expired, please sign in again";
      loginError.hidden = false;
      addActivity("Session", "Session expired", "error", "session", "authenticated session", responseDiagnostic(response.status, body, "Session expired"));
      return;
    }
    const status = isRecord(body) && isApiStatus(body.status) ? body.status : "unavailable";
    if (requestId === apiStatusRequest) {
      setApiStatus(status);
      const diagnostic = isRecord(body) && body.response !== undefined ? responseDiagnostic(response.status, body, "API unavailable") : undefined;
      recordApiStatus(status, diagnostic);
    }
  } catch (error: unknown) {
    if (requestId === apiStatusRequest) {
      setApiStatus("unavailable");
      const details = errorDetails(error, "API request failed");
      recordApiStatus("unavailable", syntheticResponse("network", details.message, details.name));
    }
  }
}

function uploadOne(item: UploadItem): Promise<void> {
  return new Promise((resolve) => {
    const generation = sessionGeneration;
    const request = new XMLHttpRequest();
    const form = new FormData();
    form.append("file[]", item.file, item.file.name);
    item.status = "uploading";
    item.progress = 0;
    addActivity(item.file.name, "Upload started", "info", "upload", `uploads/${item.file.name}`);
    renderUploads();
    request.open("POST", "/api/upload");
    request.withCredentials = true;
    request.setRequestHeader("X-File-Size", String(item.file.size));
    request.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) {
        item.progress = Math.min(99, Math.round((event.loaded / event.total) * 100));
        renderUploads();
      }
    });
    request.addEventListener("load", () => {
      if (generation !== sessionGeneration) {
        resolve();
        return;
      }
      const body = parseResponse(request.responseText);
      if (request.status >= 200 && request.status < 300 && isRecord(body) && isRecord(body.file) && Array.isArray(body.file.links)) {
        item.status = "complete";
        item.progress = 100;
        item.links = body.file.links.filter((value): value is string => typeof value === "string");
        addActivity(item.file.name, "Upload complete", "info", "upload", `uploads/${item.file.name}`);
      } else {
        item.status = "error";
        item.error = errorText(body, request.status === 401 ? "Session expired" : "Upload failed");
        addActivity(item.file.name, "Upload needs attention", "error", "upload", `uploads/${item.file.name}`, responseDiagnostic(request.status, body, item.error));
      }
      renderUploads();
      resolve();
    });
    request.addEventListener("error", () => {
      if (generation !== sessionGeneration) {
        resolve();
        return;
      }
      item.status = "error";
      item.error = "Network error";
      addActivity(item.file.name, "Upload needs attention", "error", "upload", `uploads/${item.file.name}`, syntheticResponse("network", item.error));
      renderUploads();
      resolve();
    });
    request.addEventListener("abort", () => {
      if (generation !== sessionGeneration) {
        resolve();
        return;
      }
      item.status = "error";
      item.error = "Upload cancelled";
      addActivity(item.file.name, "Upload cancelled", "error", "upload", `uploads/${item.file.name}`, syntheticResponse("client", item.error));
      renderUploads();
      resolve();
    });
    request.send(form);
  });
}

async function processUploads(): Promise<void> {
  if (processingUploads || logoutPending) return;
  processingUploads = true;
  const generation = sessionGeneration;
  try {
    for (const item of uploads) {
      if (generation !== sessionGeneration) return;
      if (item.status === "queued") await uploadOne(item);
    }
  } finally {
    if (generation === sessionGeneration) {
      processingUploads = false;
      renderUploads();
    }
  }
}

async function submitLinks(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (logoutPending) return;
  const links = linkInput.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  if (links.length === 0) {
    downloadStatus.className = "status status--error";
    downloadStatus.textContent = "Add a link";
    addActivity("Download request", "Add a link", "error", "download", "download form", syntheticResponse("validation", "Add a link"));
    return;
  }
  downloadStatus.className = "status status--working";
  downloadStatus.textContent = "requesting";
  const button = linkForm.querySelector<HTMLButtonElement>("button[type=submit]");
  if (button) button.disabled = true;
  const generation = sessionGeneration;
  let requestDiagnostic: ActivityResponse | undefined;
  addActivity(`${links.length} link${links.length === 1 ? "" : "s"}`, "Added to download queue", "info", "queue", "download queue");
  try {
    const response = await fetch("/api/download/token", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ links, pass: linkPassword.value || undefined }),
    });
    const body = parseResponse(await response.text());
    if (generation !== sessionGeneration) return;
    requestDiagnostic = responseDiagnostic(response.status, body, "Could not create download tokens");
    if (!isRecord(body) || !Array.isArray(body.results)) throw new Error(errorText(body, "Could not create download tokens"));
    for (const result of body.results) {
      if (!isRecord(result) || typeof result.link !== "string") continue;
      const item: DownloadItem = { id: newId(), link: result.link, status: typeof result.token === "string" ? "ready" : "error" };
      if (typeof result.token === "string") item.token = result.token;
      if (typeof result.error === "string") item.error = result.error;
      downloads.unshift(item);
      if (item.status === "ready") addActivity(result.link, "Download token ready", "info", "download", `downloads/${result.link}`);
      else addActivity(result.link, item.error ?? "Could not create download token", "error", "download", `downloads/${result.link}`, responseDiagnostic(response.status, result, item.error ?? "Could not create download token"));
    }
    linkInput.value = "";
    linkPassword.value = "";
    renderDownloads();
  } catch (error: unknown) {
    if (generation !== sessionGeneration) return;
    downloadStatus.className = "status status--error";
    const details = errorDetails(error, "Request failed");
    const message = details.message;
    downloadStatus.textContent = message;
    addActivity("Download request", message, "error", "download", "download queue", requestDiagnostic ?? syntheticResponse("network", message, details.name));
  } finally {
    if (generation === sessionGeneration) {
      if (button) button.disabled = false;
      renderDownloads();
    }
  }
}

function startDownload(id: string): void {
  if (logoutPending) return;
  const item = downloads.find((candidate) => candidate.id === id);
  if (!item?.token) return;
  const anchor = document.createElement("a");
  anchor.href = item.token;
  anchor.target = "_blank";
  anchor.rel = "noopener noreferrer";
  anchor.click();
  item.status = "started";
  delete item.token;
  addActivity(item.link, "Download started", "info", "download", `downloads/${item.link}`);
  renderDownloads();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (logoutPending) return;
  loginError.hidden = true;
  const button = loginForm.querySelector<HTMLButtonElement>("button[type=submit]");
  if (button) button.disabled = true;
  let loggedFailure = false;
  try {
    const response = await fetch("/api/login", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: passwordInput.value }) });
    const body = parseResponse(await response.text());
    if (!response.ok) {
      const message = errorText(body, "Sign in failed");
      addActivity("Session", message, "error", "session", "login", responseDiagnostic(response.status, body, message));
      loggedFailure = true;
      throw new Error(message);
    }
    passwordInput.value = "";
    clearSessionState();
    setVisible(true);
    addActivity("Session", "Signed in", "info", "session", "authenticated session");
    void refreshApiStatus();
  } catch (error: unknown) {
    if (!loggedFailure) {
      const details = errorDetails(error, "Sign in failed");
      addActivity("Session", details.message, "error", "session", "login", syntheticResponse("network", details.message, details.name));
    }
    loginError.textContent = error instanceof Error ? error.message : "Sign in failed";
    loginError.hidden = false;
  } finally {
    if (button) button.disabled = false;
  }
});

logoutButton.addEventListener("click", async () => {
  if (logoutPending) return;
  logoutPending = true;
  deskView.inert = true;
  deskView.setAttribute("aria-busy", "true");
  clearSessionState();
  try {
    await fetch("/api/logout", { method: "POST", credentials: "same-origin", signal: AbortSignal.timeout(10_000) });
  } catch {
    // The local session is cleared even when the server cannot be reached.
  } finally {
    logoutPending = false;
    deskView.inert = false;
    deskView.removeAttribute("aria-busy");
    setVisible(false);
  }
});

fileInput.addEventListener("change", () => {
  if (logoutPending) {
    fileInput.value = "";
    return;
  }
  const selected = Array.from(fileInput.files ?? []);
  const room = Math.max(0, 500 - uploads.length);
  const added = selected.slice(0, room);
  for (const file of added) {
    uploads.push({ id: newId(), file, status: "queued", progress: 0, links: [] });
    addActivity(file.name, "Added to upload queue", "info", "queue", `uploads/${file.name}`);
  }
  fileStatus.textContent = added.length > 0 ? `${added.length} file${added.length === 1 ? "" : "s"} queued` : "No files selected";
  fileInput.value = "";
  renderUploads();
  void processUploads();
});

uploadQueue.addEventListener("click", (event) => {
  if (logoutPending) return;
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const retry = target.closest<HTMLElement>("[data-retry-upload]")?.dataset.retryUpload;
  if (!retry) return;
  const item = uploads.find((candidate) => candidate.id === retry);
  if (item) {
    item.status = "queued";
    delete item.error;
    addActivity(item.file.name, "Upload retry queued", "info", "queue", `uploads/${item.file.name}`);
    renderUploads();
    void processUploads();
  }
});

downloadQueue.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const id = target.closest<HTMLElement>("[data-start-download]")?.dataset.startDownload;
  if (id) startDownload(id);
});

activityList.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const id = target.closest<HTMLElement>("[data-activity-id]")?.dataset.activityId;
  if (id) selectActivity(id);
});

activityDrawer.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const action = target.closest<HTMLElement>("[data-drawer-action]")?.dataset.drawerAction;
  if (action === "minimize") {
    drawerState = "minimized";
    renderDrawer();
    drawerRestore.focus();
  } else if (action === "close") {
    drawerState = "closed";
    renderDrawer();
    drawerOpen.focus();
  }
});

drawerPeek.addEventListener("click", () => {
  drawerState = "open";
  renderDrawer();
  focusDrawerContent();
});

drawerOpen.addEventListener("click", () => {
  drawerState = "open";
  renderDrawer();
  focusDrawerContent();
});

linkForm.addEventListener("submit", (event) => { void submitLinks(event); });

async function boot(): Promise<void> {
  try {
    const response = await fetch("/api/session", { credentials: "same-origin" });
    const body = parseResponse(await response.text());
    if (isRecord(body) && body.authenticated === true) {
      clearSessionState();
      setVisible(true);
      if (typeof body.maxUploadBytes === "number") uploadLimit.textContent = `Max file size · ${displayBytes(body.maxUploadBytes)}`;
      void refreshApiStatus();
    } else {
      clearSessionState();
      setVisible(false);
    }
  } catch {
    clearSessionState();
    setVisible(false);
    loginError.textContent = "The client is unavailable";
    loginError.hidden = false;
  }
  renderUploads();
  renderDownloads();
}

void boot();

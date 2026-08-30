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

interface SessionResponse {
  authenticated?: boolean;
  maxUploadBytes?: number;
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
const activityCount = element("activity-count");
const transferCount = element("transfer-count");
const logoutButton = element<HTMLButtonElement>("logout-button");

const uploads: UploadItem[] = [];
const downloads: DownloadItem[] = [];
const activities: Array<{ title: string; detail: string; time: string }> = [];
let processingUploads = false;

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

function addActivity(title: string, detail: string): void {
  activities.unshift({ title, detail, time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) });
  activities.splice(6);
  activityList.innerHTML = activities.map((activity) => `<li><strong>${escapeHtml(activity.title)}</strong>${escapeHtml(activity.detail)}<span class="activity-time">Today · ${escapeHtml(activity.time)}</span></li>`).join("");
  activityCount.textContent = String(activities.length);
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
  try { return JSON.parse(value) as unknown; } catch { return null; }
}

function uploadOne(item: UploadItem): Promise<void> {
  return new Promise((resolve) => {
    const request = new XMLHttpRequest();
    const form = new FormData();
    form.append("file[]", item.file, item.file.name);
    item.status = "uploading";
    item.progress = 0;
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
      const body = parseResponse(request.responseText);
      if (request.status >= 200 && request.status < 300 && isRecord(body) && isRecord(body.file) && Array.isArray(body.file.links)) {
        item.status = "complete";
        item.progress = 100;
        item.links = body.file.links.filter((value): value is string => typeof value === "string");
        addActivity(item.file.name, "Upload complete");
      } else {
        item.status = "error";
        item.error = errorText(body, request.status === 401 ? "Session expired" : "Upload failed");
        addActivity(item.file.name, "Upload needs attention");
      }
      renderUploads();
      resolve();
    });
    request.addEventListener("error", () => {
      item.status = "error";
      item.error = "Network error";
      addActivity(item.file.name, "Upload needs attention");
      renderUploads();
      resolve();
    });
    request.addEventListener("abort", () => {
      item.status = "error";
      item.error = "Upload cancelled";
      renderUploads();
      resolve();
    });
    request.send(form);
  });
}

async function processUploads(): Promise<void> {
  if (processingUploads) return;
  processingUploads = true;
  try {
    for (const item of uploads) {
      if (item.status === "queued") await uploadOne(item);
    }
  } finally {
    processingUploads = false;
    renderUploads();
  }
}

async function submitLinks(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  const links = linkInput.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  if (links.length === 0) {
    downloadStatus.className = "status status--error";
    downloadStatus.textContent = "Add a link";
    return;
  }
  downloadStatus.className = "status status--working";
  downloadStatus.textContent = "requesting";
  const button = linkForm.querySelector<HTMLButtonElement>("button[type=submit]");
  if (button) button.disabled = true;
  try {
    const response = await fetch("/api/download/token", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ links, pass: linkPassword.value || undefined }),
    });
    const body = parseResponse(await response.text());
    if (!isRecord(body) || !Array.isArray(body.results)) throw new Error(errorText(body, "Could not create download tokens"));
    for (const result of body.results) {
      if (!isRecord(result) || typeof result.link !== "string") continue;
      const item: DownloadItem = { id: newId(), link: result.link, status: typeof result.token === "string" ? "ready" : "error" };
      if (typeof result.token === "string") item.token = result.token;
      if (typeof result.error === "string") item.error = result.error;
      downloads.unshift(item);
    }
    linkInput.value = "";
    linkPassword.value = "";
    addActivity(`${links.length} link${links.length === 1 ? "" : "s"}`, "Added to download queue");
    renderDownloads();
  } catch (error: unknown) {
    downloadStatus.className = "status status--error";
    downloadStatus.textContent = error instanceof Error ? error.message : "Request failed";
  } finally {
    if (button) button.disabled = false;
    renderDownloads();
  }
}

function startDownload(id: string): void {
  const item = downloads.find((candidate) => candidate.id === id);
  if (!item?.token) return;
  const anchor = document.createElement("a");
  anchor.href = item.token;
  anchor.target = "_blank";
  anchor.rel = "noopener noreferrer";
  anchor.click();
  item.status = "started";
  delete item.token;
  addActivity(item.link, "Download started");
  renderDownloads();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.hidden = true;
  const button = loginForm.querySelector<HTMLButtonElement>("button[type=submit]");
  if (button) button.disabled = true;
  try {
    const response = await fetch("/api/login", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: passwordInput.value }) });
    const body = parseResponse(await response.text());
    if (!response.ok) throw new Error(errorText(body, "Sign in failed"));
    passwordInput.value = "";
    setVisible(true);
    addActivity("Session", "Signed in");
  } catch (error: unknown) {
    loginError.textContent = error instanceof Error ? error.message : "Sign in failed";
    loginError.hidden = false;
  } finally {
    if (button) button.disabled = false;
  }
});

logoutButton.addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
  uploads.length = 0;
  downloads.length = 0;
  setVisible(false);
  renderUploads();
  renderDownloads();
});

fileInput.addEventListener("change", () => {
  const selected = Array.from(fileInput.files ?? []);
  const room = Math.max(0, 500 - uploads.length);
  const added = selected.slice(0, room);
  for (const file of added) uploads.push({ id: newId(), file, status: "queued", progress: 0, links: [] });
  fileStatus.textContent = added.length > 0 ? `${added.length} file${added.length === 1 ? "" : "s"} queued` : "No files selected";
  fileInput.value = "";
  renderUploads();
  void processUploads();
});

uploadQueue.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const retry = target.closest<HTMLElement>("[data-retry-upload]")?.dataset.retryUpload;
  if (!retry) return;
  const item = uploads.find((candidate) => candidate.id === retry);
  if (item) {
    item.status = "queued";
    delete item.error;
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

linkForm.addEventListener("submit", (event) => { void submitLinks(event); });

async function boot(): Promise<void> {
  try {
    const response = await fetch("/api/session", { credentials: "same-origin" });
    const body = parseResponse(await response.text()) as SessionResponse;
    if (body.authenticated === true) {
      setVisible(true);
      if (typeof body.maxUploadBytes === "number") uploadLimit.textContent = `Max file size · ${displayBytes(body.maxUploadBytes)}`;
    } else {
      setVisible(false);
    }
  } catch {
    setVisible(false);
    loginError.textContent = "The client is unavailable";
    loginError.hidden = false;
  }
  renderUploads();
  renderDownloads();
}

void boot();

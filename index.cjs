const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");
const express = require("express");
const cors = require("cors");
require("dotenv").config();

const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, "data");
const DATA_FILE = path.join(DATA_DIR, "store.json");
const SCHEMA_FILE = path.join(ROOT_DIR, "db", "schema.sql");
const PORT = Number(process.env.PORT || 8080);
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.NEON_DATABASE_URL || "";
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:5173";
const PUBLIC_APP_URL = process.env.PUBLIC_APP_URL || "https://yourdomain.com/app";
const TOKEN_SECRET = process.env.TOKEN_SECRET || `${process.env.ADMIN_PASSWORD || "ADMIN-2026"}-local-secret`;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ADMIN-2026";
const DAY_MS = 24 * 60 * 60 * 1000;
const PROFILE_DESCRIPTION = "Message from Hyperteam install the Hyper regedit access";
const PROFILE_ORGANIZATION = "Hyperteam";

const defaultOptions = [
  {
    id: "opt_headshot",
    name: "Headshot",
    slug: "headshot",
    symbol: "HS",
    description: "Accuracy profile controlled from the admin panel.",
    enabled: true,
    sortOrder: 10
  },
  {
    id: "opt_location",
    name: "Location",
    slug: "location",
    symbol: "LC",
    description: "Location layer status and user access switch.",
    enabled: true,
    sortOrder: 20
  },
  {
    id: "opt_aim_drag",
    name: "Aim Drag",
    slug: "aim-drag",
    symbol: "AD",
    description: "Drag profile toggle stored per user.",
    enabled: true,
    sortOrder: 30
  },
  {
    id: "opt_sniper_aim",
    name: "Sniper Aim",
    slug: "sniper-aim",
    symbol: "SA",
    description: "Scoped profile toggle for active packages.",
    enabled: true,
    sortOrder: 40
  }
];

const defaultPackages = [
  { id: "pkg_7", name: "7 Days", price: 100, durationDays: 7, status: "Active" },
  { id: "pkg_15", name: "15 Days", price: 150, durationDays: 15, status: "Active" },
  { id: "pkg_30", name: "30 Days", price: 250, durationDays: 30, status: "Active" }
];

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function slugify(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64) || id("slug");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const iterations = 120000;
  const hash = crypto.pbkdf2Sync(String(password), salt, iterations, 32, "sha256").toString("hex");
  return `pbkdf2$${iterations}$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  const [kind, iterationsText, salt, expected] = String(stored).split("$");
  if (kind !== "pbkdf2" || !iterationsText || !salt || !expected) return false;
  const actual = crypto
    .pbkdf2Sync(String(password), salt, Number(iterationsText), Buffer.from(expected, "hex").length, "sha256")
    .toString("hex");
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signToken(payload, ttlMs) {
  const body = {
    ...payload,
    exp: Date.now() + ttlMs
  };
  const encoded = base64url(JSON.stringify(body));
  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(encoded).digest("base64url");
  return `${encoded}.${sig}`;
}

function verifyToken(token) {
  const [encoded, sig] = String(token || "").split(".");
  if (!encoded || !sig) return null;
  const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(encoded).digest("base64url");
  if (Buffer.byteLength(sig) !== Buffer.byteLength(expected)) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    return payload.exp > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

function cleanRow(row = {}) {
  const copy = { ...row };
  delete copy.password_hash;
  delete copy.passwordHash;
  return copy;
}

function toIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function parseDeviceIds(value, fallback = "") {
  let list = [];
  if (Array.isArray(value)) {
    list = value;
  } else if (typeof value === "string" && value.trim()) {
    try {
      const parsed = JSON.parse(value);
      list = Array.isArray(parsed) ? parsed : [value];
    } catch {
      list = [value];
    }
  }
  if (fallback) list.push(fallback);
  return [...new Set(list.map((item) => String(item || "").trim()).filter(Boolean))];
}

function isGenericDeviceName(value = "") {
  return ["iPhone", "iPad", "Android Device", "Unknown Device"].includes(String(value || "").trim());
}

function nextDeviceName(incoming = "", current = "") {
  const next = String(incoming || "").trim().slice(0, 80);
  const existing = String(current || "").trim();
  if (!next) return existing;
  if (existing && isGenericDeviceName(next) && !isGenericDeviceName(existing)) return existing;
  return next;
}

function publicUser(row = {}, optionStates = {}) {
  const expiresAt = toIso(row.expires_at || row.expiresAt);
  const onlineUntil = row.online_until || row.onlineUntil;
  const deviceIds = parseDeviceIds(row.device_ids || row.deviceIds, row.device_id || row.deviceId || "");
  const maxDevices = Math.max(1, Number(row.max_devices ?? row.maxDevices ?? 1) || 1);
  return {
    id: row.id,
    userId: row.id,
    username: row.username,
    packageId: row.package_id || row.packageId || "",
    packageName: row.package_name || row.packageName || "Custom Access",
    status: row.status,
    expiresAt,
    deviceId: deviceIds[0] || "",
    deviceIds,
    deviceName: row.device_name || row.deviceName || "",
    maxDevices,
    activeDevices: deviceIds.length,
    deviceLockedAt: toIso(row.device_locked_at || row.deviceLockedAt),
    lastSeenAt: toIso(row.last_seen_at || row.lastSeenAt),
    online: onlineUntil ? new Date(onlineUntil).getTime() > Date.now() : false,
    optionStates
  };
}

function adminUser(row = {}, optionStates = {}) {
  return {
    ...publicUser(row, optionStates),
    accessKey: row.access_key || row.accessKey || ""
  };
}

function publicOption(row = {}) {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    symbol: row.symbol || "HX",
    iconUrl: row.icon_url || row.iconUrl || "",
    description: row.description || "",
    enabled: Boolean(row.enabled),
    sortOrder: Number(row.sort_order ?? row.sortOrder ?? 100)
  };
}

function publicPackage(row = {}) {
  return {
    id: row.id,
    name: row.name,
    price: Number(row.price || 0),
    durationDays: Number(row.duration_days ?? row.durationDays ?? 7),
    status: row.status || "Active"
  };
}

function publicSettings(row = {}) {
  return {
    brandName: row.brand_name || row.brandName || "Hyper Regedit Access",
    appIconUrl: row.app_icon_url || row.appIconUrl || "/icon.png",
    webClipLabel: row.web_clip_label || row.webClipLabel || "Hyper Access",
    splashImageUrl: row.splash_image_url || row.splashImageUrl || row.app_icon_url || row.appIconUrl || "/icon.png",
    splashText: row.splash_text || row.splashText || "Loading Hyper Regedit Access",
    loginBackgroundUrl: row.login_background_url || row.loginBackgroundUrl || "/assets/hyper-logo.jpeg",
    dashboardLogoUrl: row.dashboard_logo_url || row.dashboardLogoUrl || row.app_icon_url || row.appIconUrl || "/icon.png",
    liveBackgroundUrl:
      row.live_background_url || row.liveBackgroundUrl || row.login_background_url || row.loginBackgroundUrl || "/assets/hyper-logo.jpeg",
    developerName: row.developer_name || row.developerName || "ESE Developer",
    developerBannerUrl: row.developer_banner_url || row.developerBannerUrl || "",
    telegramUrl: row.telegram_url || row.telegramUrl || "https://t.me/your_support",
    maintenanceEnabled: Boolean(row.maintenance_enabled ?? row.maintenanceEnabled),
    maintenanceMessage:
      row.maintenance_message || row.maintenanceMessage || "System maintenance is running. Please try again later.",
    webClipUrl: row.web_clip_url || row.webClipUrl || PUBLIC_APP_URL
  };
}

function escapeXml(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function cleanProfileLabel(value = "") {
  return String(value || "Hyper Access").trim().slice(0, 40) || "Hyper Access";
}

function imageDataUrlBase64(value = "") {
  const match = String(value).match(/^data:image\/(?:png|jpe?g|webp);base64,([\s\S]+)$/i);
  return match ? match[1].replace(/\s/g, "") : "";
}

function assetUrl(value = "") {
  const source = String(value || "").trim();
  if (!source || source.startsWith("data:")) return "";
  if (/^https?:\/\//i.test(source)) return source;
  if (source.startsWith("/")) {
    try {
      return new URL(source, PUBLIC_APP_URL).toString();
    } catch {
      return "";
    }
  }
  return "";
}

async function webClipIconBase64(settings = {}) {
  const embedded = imageDataUrlBase64(settings.appIconUrl);
  if (embedded) return embedded;
  const url = assetUrl(settings.appIconUrl);
  if (!url || typeof fetch !== "function") return "";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) return "";
    const type = response.headers.get("content-type") || "";
    if (!type.startsWith("image/")) return "";
    return Buffer.from(await response.arrayBuffer()).toString("base64");
  } catch {
    return "";
  } finally {
    clearTimeout(timer);
  }
}

async function buildMobileConfig(settings = {}) {
  const label = cleanProfileLabel(settings.webClipLabel || settings.brandName);
  const appUrl = settings.webClipUrl || PUBLIC_APP_URL;
  const iconBase64 = await webClipIconBase64(settings);
  const profileUuid = crypto.randomUUID().toUpperCase();
  const webClipUuid = crypto.randomUUID().toUpperCase();
  const iconBlock = iconBase64
    ? `
      <key>Icon</key>
      <data>${iconBase64}</data>`
    : "";

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>ConsentText</key>
  <dict>
    <key>default</key>
    <string>OWNER : @hyperregedit
TELEGRAM
HYPER REGEDIT OFFICIAL
https://t.me/hyperregedit</string>
  </dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>FullScreen</key>
      <true/>${iconBlock}
      <key>IsRemovable</key>
      <true/>
      <key>Label</key>
      <string>${escapeXml(label)}</string>
      <key>PayloadDescription</key>
      <string>Add ${escapeXml(label)} to the iPhone Home Screen.</string>
      <key>PayloadDisplayName</key>
      <string>${escapeXml(label)} Web Clip</string>
      <key>PayloadIdentifier</key>
      <string>com.hyperregedit.access.webclip</string>
      <key>PayloadOrganization</key>
      <string>${PROFILE_ORGANIZATION}</string>
      <key>PayloadType</key>
      <string>com.apple.webClip.managed</string>
      <key>PayloadUUID</key>
      <string>${webClipUuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Precomposed</key>
      <true/>
      <key>URL</key>
      <string>${escapeXml(appUrl)}</string>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>${PROFILE_DESCRIPTION}</string>
  <key>PayloadDisplayName</key>
  <string>Hyper Regedit Official</string>
  <key>PayloadIdentifier</key>
  <string>com.hyperregedit.access.profile</string>
  <key>PayloadOrganization</key>
  <string>${PROFILE_ORGANIZATION}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${profileUuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>`;
}

function stateSeed() {
  const adminHash = hashPassword(ADMIN_PASSWORD);
  const userHash = hashPassword("123456");
  const now = new Date();
  return {
    settings: {
      brandName: "Hyper Regedit Access",
      appIconUrl: "/icon.png",
      webClipLabel: "Hyper Access",
      splashImageUrl: "/icon.png",
      splashText: "Loading Hyper Regedit Access",
      loginBackgroundUrl: "/assets/hyper-logo.jpeg",
      dashboardLogoUrl: "/icon.png",
      liveBackgroundUrl: "/assets/hyper-logo.jpeg",
      developerName: "ESE Developer",
      developerBannerUrl: "",
      telegramUrl: "https://t.me/your_support",
      maintenanceEnabled: false,
      maintenanceMessage: "System maintenance is running. Please try again later.",
      webClipUrl: PUBLIC_APP_URL
    },
    admins: [{ id: "admin_main", username: ADMIN_USERNAME, passwordHash: adminHash }],
    packages: defaultPackages,
    options: defaultOptions.map(publicOption),
    users: [
      {
        id: "user_demo",
        username: "user001",
        accessKey: "123456",
        passwordHash: userHash,
        packageId: "pkg_7",
        packageName: "7 Days",
        status: "Active",
        expiresAt: new Date(now.getTime() + 7 * DAY_MS).toISOString(),
        deviceId: "",
        deviceIds: [],
        deviceName: "",
        maxDevices: 1,
        deviceLockedAt: null,
        lastSeenAt: null,
        onlineUntil: null
      }
    ],
    optionStates: {},
    logs: []
  };
}

class JsonStore {
  async init() {
    await fs.mkdir(DATA_DIR, { recursive: true });
    try {
      await fs.access(DATA_FILE);
    } catch {
      await this.write(stateSeed());
    }
  }

  async read() {
    await this.init();
    return JSON.parse(await fs.readFile(DATA_FILE, "utf8"));
  }

  async write(state) {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(DATA_FILE, JSON.stringify(state, null, 2));
  }

  async getSettings() {
    return publicSettings((await this.read()).settings);
  }

  async updateSettings(input) {
    const state = await this.read();
    state.settings = { ...state.settings, ...input };
    await this.write(state);
    return publicSettings(state.settings);
  }

  async getAdmin(username) {
    const state = await this.read();
    return state.admins.find((admin) => admin.username === username) || null;
  }

  async updateAdminPassword(username, password) {
    const state = await this.read();
    const admin = state.admins.find((item) => item.username === username);
    if (!admin) throw new Error("Admin not found");
    admin.passwordHash = hashPassword(password);
    await this.write(state);
    return { username: admin.username };
  }

  async listPackages() {
    return (await this.read()).packages.map(publicPackage);
  }

  async upsertPackage(input) {
    const state = await this.read();
    const item = publicPackage({ ...input, id: input.id || id("pkg") });
    const index = state.packages.findIndex((pkg) => pkg.id === item.id);
    if (index >= 0) state.packages[index] = item;
    else state.packages.push(item);
    await this.write(state);
    return item;
  }

  async deletePackage(packageId) {
    const state = await this.read();
    state.packages = state.packages.filter((pkg) => pkg.id !== packageId);
    await this.write(state);
  }

  async listOptions() {
    return (await this.read()).options.map(publicOption).sort((a, b) => a.sortOrder - b.sortOrder);
  }

  async upsertOption(input) {
    const state = await this.read();
    const option = publicOption({
      ...input,
      id: input.id || id("opt"),
      slug: input.slug || slugify(input.name)
    });
    const index = state.options.findIndex((item) => item.id === option.id);
    if (index >= 0) state.options[index] = option;
    else state.options.push(option);
    await this.write(state);
    return option;
  }

  async deleteOption(optionId) {
    const state = await this.read();
    state.options = state.options.filter((item) => item.id !== optionId);
    state.optionStates = Object.fromEntries(
      Object.entries(state.optionStates).filter(([key, value]) => (value.optionId || key.split(":").pop()) !== optionId)
    );
    await this.write(state);
  }

  async getUserByUsername(username) {
    const state = await this.read();
    const user = state.users.find((item) => item.username.toLowerCase() === String(username).toLowerCase());
    return user ? { ...user, passwordHash: user.passwordHash } : null;
  }

  async getUserByPassword(password) {
    const state = await this.read();
    return state.users.find((item) => verifyPassword(password, item.passwordHash)) || null;
  }

  async getUserById(userId) {
    const state = await this.read();
    return state.users.find((item) => item.id === userId) || null;
  }

  async listUsers() {
    const state = await this.read();
    return state.users.map((user) => adminUser(user, this.userStatesFromState(state, user.id)));
  }

  userStatesFromState(state, userId) {
    return Object.fromEntries(
      Object.entries(state.optionStates || {})
        .filter(([, value]) => value.userId === userId)
        .map(([key, value]) => [value.optionId || key.split(":").pop(), Boolean(value.enabled)])
    );
  }

  async createUser(input) {
    const state = await this.read();
    const accessKey = String(input.password || "").trim();
    if (!accessKey) throw new Error("Access key is required");
    if (state.users.some((user) => verifyPassword(accessKey, user.passwordHash))) {
      throw new Error("Access key already exists");
    }
    const userId = id("user");
    const username = String(input.username || userId).trim() || userId;
    if (state.users.some((user) => user.username.toLowerCase() === username.toLowerCase())) {
      throw new Error("Username already exists");
    }
    const pkg = state.packages.find((item) => item.id === input.packageId) || state.packages[0];
    const expiresAt =
      input.expiresAt || new Date(Date.now() + Number(pkg?.durationDays || input.durationDays || 7) * DAY_MS).toISOString();
    const user = {
      id: userId,
      username,
      accessKey,
      passwordHash: hashPassword(accessKey),
      packageId: input.packageId || "",
      packageName: input.packageName || pkg?.name || "Custom Access",
      status: input.status || "Active",
      expiresAt,
      deviceId: "",
      deviceIds: [],
      deviceName: "",
      maxDevices: Math.max(1, Number(input.maxDevices || 1) || 1),
      deviceLockedAt: null,
      lastSeenAt: null,
      onlineUntil: null
    };
    state.users.push(user);
    await this.write(state);
    return adminUser(user, {});
  }

  async updateUser(userId, input) {
    const state = await this.read();
    const index = state.users.findIndex((item) => item.id === userId);
    if (index < 0) throw new Error("User not found");
    const user = state.users[index];
    const nextAccessKey = String(input.password || "").trim();
    if (nextAccessKey && state.users.some((item) => item.id !== userId && verifyPassword(nextAccessKey, item.passwordHash))) {
      throw new Error("Access key already exists");
    }
    const pkg = state.packages.find((item) => item.id === input.packageId);
    state.users[index] = {
      ...user,
      username: input.username ?? user.username,
      accessKey: nextAccessKey || user.accessKey || "",
      passwordHash: nextAccessKey ? hashPassword(nextAccessKey) : user.passwordHash,
      packageId: input.packageId ?? user.packageId,
      packageName: input.packageName || pkg?.name || user.packageName,
      status: input.status ?? user.status,
      expiresAt: input.expiresAt ?? user.expiresAt,
      deviceId: input.resetDevice ? "" : user.deviceId,
      deviceIds: input.resetDevice ? [] : parseDeviceIds(user.deviceIds, user.deviceId),
      deviceName: input.resetDevice ? "" : input.deviceName ?? user.deviceName,
      maxDevices: Math.max(1, Number(input.maxDevices ?? user.maxDevices ?? 1) || 1),
      deviceLockedAt: input.resetDevice ? null : user.deviceLockedAt
    };
    await this.write(state);
    return adminUser(state.users[index], this.userStatesFromState(state, userId));
  }

  async deleteUser(userId) {
    const state = await this.read();
    state.users = state.users.filter((item) => item.id !== userId);
    state.logs = state.logs.filter((item) => item.userId !== userId);
    state.optionStates = Object.fromEntries(
      Object.entries(state.optionStates).filter(([, value]) => value.userId !== userId)
    );
    await this.write(state);
  }

  async getUserOptionStates(userId) {
    const state = await this.read();
    return this.userStatesFromState(state, userId);
  }

  async setUserOptionState(userId, optionId, enabled) {
    const state = await this.read();
    state.optionStates[`${userId}:${optionId}`] = { userId, optionId, enabled: Boolean(enabled) };
    await this.write(state);
    return this.userStatesFromState(state, userId);
  }

  async setUserLoginState(userId, patch) {
    const state = await this.read();
    const user = state.users.find((item) => item.id === userId);
    if (!user) return null;
    Object.assign(user, patch);
    await this.write(state);
    return user;
  }

  async addLog(input) {
    const state = await this.read();
    state.logs.unshift({
      id: id("log"),
      createdAt: new Date().toISOString(),
      ...input
    });
    state.logs = state.logs.slice(0, 200);
    await this.write(state);
  }

  async listLogs() {
    return (await this.read()).logs.slice(0, 80);
  }

  async deleteLogs(logIds = []) {
    const ids = new Set(logIds.map((item) => String(item)));
    const state = await this.read();
    state.logs = state.logs.filter((log) => !ids.has(String(log.id)));
    await this.write(state);
  }

  async clearLogs() {
    const state = await this.read();
    state.logs = [];
    await this.write(state);
  }
}

class PgStore {
  constructor(pool) {
    this.pool = pool;
  }

  async init() {
    await this.pool.query(await fs.readFile(SCHEMA_FILE, "utf8"));
    await this.pool.query(`alter table if exists app_users add column if not exists access_key text not null default ''`);
    await this.pool.query(`alter table if exists access_logs add column if not exists device_id text not null default ''`);
    await this.pool.query(
      `insert into app_settings (id, web_clip_url) values ('main', $1) on conflict (id) do nothing`,
      [PUBLIC_APP_URL]
    );
    await this.pool.query(
      `insert into admins (id, username, password_hash) values ($1, $2, $3) on conflict (username) do nothing`,
      ["admin_main", ADMIN_USERNAME, hashPassword(ADMIN_PASSWORD)]
    );
    for (const pkg of defaultPackages) {
      await this.pool.query(
        `insert into packages (id, name, price, duration_days, status)
         values ($1, $2, $3, $4, $5) on conflict (id) do nothing`,
        [pkg.id, pkg.name, pkg.price, pkg.durationDays, pkg.status]
      );
    }
    for (const option of defaultOptions) {
      await this.pool.query(
        `insert into feature_options (id, name, slug, symbol, description, enabled, sort_order)
         values ($1, $2, $3, $4, $5, $6, $7) on conflict (id) do nothing`,
        [option.id, option.name, option.slug, option.symbol, option.description, option.enabled, option.sortOrder]
      );
    }
    await this.pool.query(
      `insert into app_users (id, username, password_hash, access_key, package_id, package_name, status, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, now() + interval '7 days')
       on conflict (username) do nothing`,
      ["user_demo", "user001", hashPassword("123456"), "123456", "pkg_7", "7 Days", "Active"]
    );
    await this.pool.query(`update app_users set access_key = '123456' where username = 'user001' and coalesce(access_key, '') = ''`);
    await this.pool.query(`update app_users set device_ids = coalesce(device_ids, '[]'::jsonb), max_devices = coalesce(max_devices, 1)`);
  }

  async getSettings() {
    const { rows } = await this.pool.query(`select * from app_settings where id = 'main'`);
    return publicSettings(rows[0]);
  }

  async updateSettings(input) {
    const current = await this.getSettings();
    const next = { ...current, ...input };
    const { rows } = await this.pool.query(
      `update app_settings
       set brand_name = $1, app_icon_url = $2, web_clip_label = $3,
           login_background_url = $4, dashboard_logo_url = $5,
           live_background_url = $6, splash_image_url = $7, splash_text = $8,
           developer_name = $9, developer_banner_url = $10,
           telegram_url = $11, maintenance_enabled = $12, maintenance_message = $13, web_clip_url = $14,
           updated_at = now()
       where id = 'main'
       returning *`,
      [
        next.brandName,
        next.appIconUrl,
        next.webClipLabel,
        next.loginBackgroundUrl,
        next.dashboardLogoUrl,
        next.liveBackgroundUrl,
        next.splashImageUrl,
        next.splashText,
        next.developerName,
        next.developerBannerUrl,
        next.telegramUrl,
        next.maintenanceEnabled,
        next.maintenanceMessage,
        next.webClipUrl
      ]
    );
    return publicSettings(rows[0]);
  }

  async getAdmin(username) {
    const { rows } = await this.pool.query(`select * from admins where username = $1`, [username]);
    return rows[0] ? { username: rows[0].username, passwordHash: rows[0].password_hash } : null;
  }

  async updateAdminPassword(username, password) {
    const { rows } = await this.pool.query(
      `update admins set password_hash = $1, updated_at = now() where username = $2 returning username`,
      [hashPassword(password), username]
    );
    if (!rows[0]) throw new Error("Admin not found");
    return { username: rows[0].username };
  }

  async listPackages() {
    const { rows } = await this.pool.query(`select * from packages order by duration_days asc, name asc`);
    return rows.map(publicPackage);
  }

  async upsertPackage(input) {
    const packageId = input.id || id("pkg");
    const { rows } = await this.pool.query(
      `insert into packages (id, name, price, duration_days, status)
       values ($1, $2, $3, $4, $5)
       on conflict (id) do update
       set name = excluded.name, price = excluded.price, duration_days = excluded.duration_days,
           status = excluded.status, updated_at = now()
       returning *`,
      [packageId, input.name, Number(input.price || 0), Number(input.durationDays || 7), input.status || "Active"]
    );
    return publicPackage(rows[0]);
  }

  async deletePackage(packageId) {
    await this.pool.query(`delete from packages where id = $1`, [packageId]);
  }

  async listOptions() {
    const { rows } = await this.pool.query(`select * from feature_options order by sort_order asc, name asc`);
    return rows.map(publicOption);
  }

  async upsertOption(input) {
    const optionId = input.id || id("opt");
    const { rows } = await this.pool.query(
      `insert into feature_options (id, name, slug, symbol, icon_url, description, enabled, sort_order)
       values ($1, $2, $3, $4, $5, $6, $7, $8)
       on conflict (id) do update
       set name = excluded.name, slug = excluded.slug, symbol = excluded.symbol, icon_url = excluded.icon_url,
           description = excluded.description, enabled = excluded.enabled, sort_order = excluded.sort_order,
           updated_at = now()
       returning *`,
      [
        optionId,
        input.name,
        input.slug || slugify(input.name),
        input.symbol || String(input.name || "HX").slice(0, 2).toUpperCase(),
        input.iconUrl || "",
        input.description || "",
        input.enabled !== false,
        Number(input.sortOrder || 100)
      ]
    );
    return publicOption(rows[0]);
  }

  async deleteOption(optionId) {
    await this.pool.query(`delete from feature_options where id = $1`, [optionId]);
  }

  async getUserByUsername(username) {
    const { rows } = await this.pool.query(`select * from app_users where lower(username) = lower($1)`, [username]);
    return rows[0] || null;
  }

  async getUserByPassword(password) {
    const { rows } = await this.pool.query(`select * from app_users order by created_at desc`);
    return rows.find((row) => verifyPassword(password, row.password_hash)) || null;
  }

  async getUserById(userId) {
    const { rows } = await this.pool.query(`select * from app_users where id = $1`, [userId]);
    return rows[0] || null;
  }

  async listUsers() {
    const { rows } = await this.pool.query(`select * from app_users order by created_at desc`);
    const users = [];
    for (const row of rows) {
      users.push(adminUser(row, await this.getUserOptionStates(row.id)));
    }
    return users;
  }

  async createUser(input) {
    const accessKey = String(input.password || "").trim();
    if (!accessKey) throw new Error("Access key is required");
    if (await this.getUserByPassword(accessKey)) throw new Error("Access key already exists");
    const packages = await this.listPackages();
    const pkg = packages.find((item) => item.id === input.packageId) || packages[0];
    const expiresAt =
      input.expiresAt || new Date(Date.now() + Number(pkg?.durationDays || input.durationDays || 7) * DAY_MS).toISOString();
    const userId = id("user");
    const username = String(input.username || userId).trim() || userId;
    const { rows } = await this.pool.query(
      `insert into app_users (id, username, password_hash, access_key, package_id, package_name, status, expires_at, max_devices, device_ids, device_name)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, '[]'::jsonb, '')
       returning *`,
      [
        userId,
        username,
        hashPassword(accessKey),
        accessKey,
        input.packageId || null,
        input.packageName || pkg?.name || "Custom Access",
        input.status || "Active",
        expiresAt,
        Math.max(1, Number(input.maxDevices || 1) || 1)
      ]
    );
    return adminUser(rows[0], {});
  }

  async updateUser(userId, input) {
    const current = await this.getUserById(userId);
    if (!current) throw new Error("User not found");
    const nextAccessKey = String(input.password || "").trim();
    if (nextAccessKey) {
      const duplicate = await this.getUserByPassword(nextAccessKey);
      if (duplicate && duplicate.id !== userId) throw new Error("Access key already exists");
    }
    const packages = await this.listPackages();
    const pkg = packages.find((item) => item.id === input.packageId);
    const nextHash = nextAccessKey ? hashPassword(nextAccessKey) : current.password_hash;
    const { rows } = await this.pool.query(
      `update app_users
       set username = $1, password_hash = $2, access_key = $3, package_id = $4, package_name = $5, status = $6,
           expires_at = $7, device_id = $8, device_ids = $9::jsonb, max_devices = $10,
           device_name = $11, device_locked_at = $12, updated_at = now()
       where id = $13
       returning *`,
      [
        input.username ?? current.username,
        nextHash,
        nextAccessKey || current.access_key || "",
        input.packageId ?? current.package_id,
        input.packageName || pkg?.name || current.package_name,
        input.status ?? current.status,
        input.expiresAt ?? current.expires_at,
        input.resetDevice ? null : current.device_id,
        input.resetDevice ? JSON.stringify([]) : JSON.stringify(parseDeviceIds(current.device_ids, current.device_id)),
        Math.max(1, Number(input.maxDevices ?? current.max_devices ?? 1) || 1),
        input.resetDevice ? "" : input.deviceName ?? current.device_name,
        input.resetDevice ? null : current.device_locked_at,
        userId
      ]
    );
    return adminUser(rows[0], await this.getUserOptionStates(userId));
  }

  async deleteUser(userId) {
    await this.pool.query(`delete from app_users where id = $1`, [userId]);
  }

  async getUserOptionStates(userId) {
    const { rows } = await this.pool.query(`select option_id, enabled from user_option_states where user_id = $1`, [userId]);
    return Object.fromEntries(rows.map((row) => [row.option_id, row.enabled]));
  }

  async setUserOptionState(userId, optionId, enabled) {
    await this.pool.query(
      `insert into user_option_states (user_id, option_id, enabled, updated_at)
       values ($1, $2, $3, now())
       on conflict (user_id, option_id) do update
       set enabled = excluded.enabled, updated_at = now()`,
      [userId, optionId, Boolean(enabled)]
    );
    return this.getUserOptionStates(userId);
  }

  async setUserLoginState(userId, patch) {
    const columns = [];
    const values = [];
    const map = {
      deviceId: "device_id",
      deviceIds: "device_ids",
      deviceName: "device_name",
      maxDevices: "max_devices",
      deviceLockedAt: "device_locked_at",
      lastSeenAt: "last_seen_at",
      onlineUntil: "online_until"
    };
    for (const [key, column] of Object.entries(map)) {
      if (Object.prototype.hasOwnProperty.call(patch, key)) {
        values.push(key === "deviceIds" ? JSON.stringify(patch[key] || []) : patch[key]);
        columns.push(`${column} = $${values.length}${key === "deviceIds" ? "::jsonb" : ""}`);
      }
    }
    if (!columns.length) return this.getUserById(userId);
    values.push(userId);
    const { rows } = await this.pool.query(
      `update app_users set ${columns.join(", ")}, updated_at = now() where id = $${values.length} returning *`,
      values
    );
    return rows[0];
  }

  async addLog(input) {
    await this.pool.query(
      `insert into access_logs (id, user_id, username, device_id, action, ip_address, user_agent)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [
        id("log"),
        input.userId || null,
        input.username || "",
        input.deviceId || "",
        input.action,
        input.ipAddress || "",
        input.userAgent || ""
      ]
    );
  }

  async listLogs() {
    const { rows } = await this.pool.query(
      `select id, user_id as "userId", username, device_id as "deviceId", action, ip_address as "ipAddress",
              user_agent as "userAgent", created_at as "createdAt"
       from access_logs
       order by created_at desc
       limit 80`
    );
    return rows.map((row) => ({ ...row, createdAt: toIso(row.createdAt) }));
  }

  async deleteLogs(logIds = []) {
    const ids = logIds.map((item) => String(item || "").trim()).filter(Boolean);
    if (!ids.length) return;
    await this.pool.query(`delete from access_logs where id = any($1::text[])`, [ids]);
  }

  async clearLogs() {
    await this.pool.query(`delete from access_logs`);
  }
}

async function makeStore() {
  if (!DATABASE_URL) {
    const store = new JsonStore();
    await store.init();
    console.log("Using local JSON storage. Set DATABASE_URL to use Neon PostgreSQL.");
    return store;
  }

  const { Pool } = require("pg");
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_URL.includes("sslmode=disable") ? false : { rejectUnauthorized: true },
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
  });
  const store = new PgStore(pool);
  await store.init();
  console.log("Connected to Neon PostgreSQL.");
  return store;
}

function clientIp(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

function getBearer(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function requireRole(role) {
  return (req, res, next) => {
    const payload = verifyToken(getBearer(req));
    if (!payload || payload.role !== role) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.auth = payload;
    return next();
  };
}

function isExpired(user) {
  const expiresAt = user.expires_at || user.expiresAt;
  return expiresAt ? new Date(expiresAt).getTime() < Date.now() : false;
}

function packageUserResponse(user, options, settings, optionStates) {
  return {
    user: publicUser(user, optionStates),
    options,
    settings
  };
}

async function main() {
  const store = await makeStore();
  const app = express();

  app.use(
    cors({
      origin(origin, callback) {
        if (!origin || origin === CLIENT_ORIGIN || /^https?:\/\/localhost(:\d+)?$/.test(origin)) {
          callback(null, true);
        } else {
          callback(null, true);
        }
      },
      credentials: true
    })
  );
  app.use(express.json({ limit: "25mb" }));

  app.get("/api/health", async (_req, res) => {
    res.json({ ok: true, storage: DATABASE_URL ? "neon" : "local-json" });
  });

  app.get("/api/bootstrap", async (_req, res) => {
    res.json({
      settings: await store.getSettings(),
      packages: await store.listPackages(),
      options: await store.listOptions()
    });
  });

  app.post("/api/auth/admin-login", async (req, res) => {
    const admin = await store.getAdmin(String(req.body.username || ""));
    if (!admin || !verifyPassword(req.body.password || "", admin.passwordHash || admin.password_hash)) {
      return res.status(401).json({ message: "Invalid admin login" });
    }
    const token = signToken({ role: "admin", username: admin.username }, 12 * 60 * 60 * 1000);
    res.json({ token, admin: { username: admin.username } });
  });

  app.post("/api/auth/login", async (req, res) => {
    const settings = await store.getSettings();
    if (settings.maintenanceEnabled) {
      return res.status(503).json({ message: settings.maintenanceMessage });
    }

    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "").trim();
    const deviceId = String(req.body.deviceId || "").trim();
    const deviceName = String(req.body.deviceName || "").trim();
    if (!password) {
      await store.addLog({
        username,
        deviceId,
        action: "failed_login",
        ipAddress: clientIp(req),
        userAgent: req.headers["user-agent"] || ""
      });
      return res.status(401).json({ message: "Access key is required" });
    }
    const user = username ? await store.getUserByUsername(username) : await store.getUserByPassword(password);

    if (!user || (username && !verifyPassword(password, user.passwordHash || user.password_hash))) {
      await store.addLog({
        username,
        deviceId,
        action: "failed_login",
        ipAddress: clientIp(req),
        userAgent: req.headers["user-agent"] || ""
      });
      return res.status(401).json({ message: "Access key is not active" });
    }

    if (String(user.status || "").toLowerCase() !== "active" || isExpired(user)) {
      await store.addLog({
        userId: user.id,
        username: user.username,
        deviceId,
        action: "blocked_login",
        ipAddress: clientIp(req),
        userAgent: req.headers["user-agent"] || ""
      });
      return res.status(403).json({ message: "Package inactive or expired" });
    }

    if (!deviceId) {
      return res.status(400).json({ message: "Device ID missing" });
    }

    const maxDevices = Math.max(1, Number(user.max_devices ?? user.maxDevices ?? 1) || 1);
    const knownDeviceIds = parseDeviceIds(user.device_ids || user.deviceIds, user.device_id || user.deviceId || "");
    const deviceAllowed = knownDeviceIds.includes(deviceId);
    if (!deviceAllowed && knownDeviceIds.length >= maxDevices) {
      await store.addLog({
        userId: user.id,
        username: user.username,
        deviceId,
        action: "device_blocked",
        ipAddress: clientIp(req),
        userAgent: req.headers["user-agent"] || ""
      });
      return res.status(403).json({ message: "Device limit reached. Ask admin to reset or increase limit." });
    }

    const now = new Date();
    const nextDeviceIds = deviceAllowed ? knownDeviceIds : [...knownDeviceIds, deviceId];
    const onlineUntil = new Date(now.getTime() + 2 * 60 * 1000).toISOString();
    const updatedUser = await store.setUserLoginState(user.id, {
      deviceId: nextDeviceIds[0] || deviceId,
      deviceIds: nextDeviceIds,
      deviceName: nextDeviceName(deviceName, user.device_name || user.deviceName || ""),
      deviceLockedAt: knownDeviceIds.length ? user.device_locked_at || user.deviceLockedAt : now.toISOString(),
      lastSeenAt: now.toISOString(),
      onlineUntil
    });
    await store.addLog({
      userId: user.id,
      username: user.username,
      deviceId,
      action: "login",
      ipAddress: clientIp(req),
      userAgent: req.headers["user-agent"] || ""
    });

    const token = signToken(
      { role: "user", sub: user.id, username: user.username, deviceId },
      req.body.remember ? 30 * DAY_MS : DAY_MS
    );
    const optionStates = await store.getUserOptionStates(user.id);
    res.json({
      token,
      ...packageUserResponse(updatedUser, await store.listOptions(), await store.getSettings(), optionStates)
    });
  });

  app.post("/api/auth/logout", requireRole("user"), async (req, res) => {
    const user = await store.getUserById(req.auth.sub);
    if (user) {
      await store.setUserLoginState(user.id, { onlineUntil: new Date().toISOString() });
      await store.addLog({
        userId: user.id,
        username: user.username,
        deviceId: req.auth.deviceId || "",
        action: "logout",
        ipAddress: clientIp(req),
        userAgent: req.headers["user-agent"] || ""
      });
    }
    res.json({ ok: true });
  });

  app.get("/api/me", requireRole("user"), async (req, res) => {
    const user = await store.getUserById(req.auth.sub);
    if (!user) return res.status(404).json({ message: "User not found" });
    const settings = await store.getSettings();
    if (settings.maintenanceEnabled) return res.status(503).json({ message: settings.maintenanceMessage });
    await store.setUserLoginState(user.id, {
      lastSeenAt: new Date().toISOString(),
      onlineUntil: new Date(Date.now() + 2 * 60 * 1000).toISOString()
    });
    const freshUser = await store.getUserById(user.id);
    res.json(
      packageUserResponse(freshUser, await store.listOptions(), settings, await store.getUserOptionStates(user.id))
    );
  });

  app.patch("/api/me/device-name", requireRole("user"), async (req, res) => {
    const user = await store.getUserById(req.auth.sub);
    if (!user) return res.status(404).json({ message: "User not found" });
    const deviceName = String(req.body.deviceName || "").trim().slice(0, 80);
    if (!deviceName) return res.status(400).json({ message: "Device name required" });
    const updatedUser = await store.setUserLoginState(user.id, {
      deviceName,
      lastSeenAt: new Date().toISOString(),
      onlineUntil: new Date(Date.now() + 2 * 60 * 1000).toISOString()
    });
    await store.addLog({
      userId: user.id,
      username: user.username,
      deviceId: req.auth.deviceId || "",
      action: "device_name_saved",
      ipAddress: clientIp(req),
      userAgent: req.headers["user-agent"] || ""
    });
    res.json({ user: publicUser(updatedUser, await store.getUserOptionStates(user.id)) });
  });

  app.patch("/api/me/options/:optionId", requireRole("user"), async (req, res) => {
    const user = await store.getUserById(req.auth.sub);
    if (!user) return res.status(404).json({ message: "User not found" });
    const states = await store.setUserOptionState(user.id, req.params.optionId, Boolean(req.body.enabled));
    await store.addLog({
      userId: user.id,
      username: user.username,
      deviceId: req.auth.deviceId || "",
      action: `option_${req.body.enabled ? "on" : "off"}`,
      ipAddress: clientIp(req),
      userAgent: req.headers["user-agent"] || ""
    });
    res.json({ optionStates: states });
  });

  app.get("/api/admin/summary", requireRole("admin"), async (_req, res) => {
    const users = await store.listUsers();
    const logs = await store.listLogs();
    res.json({
      totalUsers: users.length,
      activeUsers: users.filter((user) => user.status === "Active" && !isExpired(user)).length,
      expiredUsers: users.filter((user) => isExpired(user) || user.status !== "Active").length,
      onlineUsers: users.filter((user) => user.online).length,
      latestLogs: logs.slice(0, 10)
    });
  });

  app.get("/api/admin/users", requireRole("admin"), async (_req, res) => {
    res.json({ users: await store.listUsers() });
  });

  app.patch("/api/admin/password", requireRole("admin"), async (req, res) => {
    const newPassword = String(req.body.newPassword || "");
    if (newPassword.length < 6) return res.status(400).json({ message: "New password must be at least 6 characters" });
    const admin = await store.getAdmin(req.auth.username);
    if (req.body.currentPassword && !verifyPassword(req.body.currentPassword, admin?.passwordHash || admin?.password_hash)) {
      return res.status(403).json({ message: "Current admin password is wrong" });
    }
    res.json({ admin: await store.updateAdminPassword(req.auth.username, newPassword) });
  });

  app.post("/api/admin/users", requireRole("admin"), async (req, res) => {
    try {
      res.status(201).json({ user: await store.createUser(req.body) });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  });

  app.patch("/api/admin/users/:userId", requireRole("admin"), async (req, res) => {
    try {
      res.json({ user: await store.updateUser(req.params.userId, req.body) });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  });

  app.delete("/api/admin/users/:userId", requireRole("admin"), async (req, res) => {
    await store.deleteUser(req.params.userId);
    res.json({ ok: true });
  });

  app.get("/api/admin/options", requireRole("admin"), async (_req, res) => {
    res.json({ options: await store.listOptions() });
  });

  app.post("/api/admin/options", requireRole("admin"), async (req, res) => {
    res.status(201).json({ option: await store.upsertOption(req.body) });
  });

  app.patch("/api/admin/options/:optionId", requireRole("admin"), async (req, res) => {
    res.json({ option: await store.upsertOption({ ...req.body, id: req.params.optionId }) });
  });

  app.delete("/api/admin/options/:optionId", requireRole("admin"), async (req, res) => {
    await store.deleteOption(req.params.optionId);
    res.json({ ok: true });
  });

  app.get("/api/admin/packages", requireRole("admin"), async (_req, res) => {
    res.json({ packages: await store.listPackages() });
  });

  app.post("/api/admin/packages", requireRole("admin"), async (req, res) => {
    res.status(201).json({ package: await store.upsertPackage(req.body) });
  });

  app.patch("/api/admin/packages/:packageId", requireRole("admin"), async (req, res) => {
    res.json({ package: await store.upsertPackage({ ...req.body, id: req.params.packageId }) });
  });

  app.delete("/api/admin/packages/:packageId", requireRole("admin"), async (req, res) => {
    await store.deletePackage(req.params.packageId);
    res.json({ ok: true });
  });

  app.get("/api/admin/settings", requireRole("admin"), async (_req, res) => {
    res.json({ settings: await store.getSettings() });
  });

  app.patch("/api/admin/settings", requireRole("admin"), async (req, res) => {
    res.json({ settings: await store.updateSettings(req.body) });
  });

  app.get("/api/admin/logs", requireRole("admin"), async (_req, res) => {
    res.json({ logs: await store.listLogs() });
  });

  app.delete("/api/admin/logs", requireRole("admin"), async (req, res) => {
    const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
    if (req.body.all) {
      await store.clearLogs();
    } else {
      const cleanIds = ids.map((item) => String(item || "").trim()).filter(Boolean);
      if (!cleanIds.length) return res.status(400).json({ message: "No logs selected" });
      await store.deleteLogs(cleanIds);
    }
    res.json({ logs: await store.listLogs() });
  });

  app.delete("/api/admin/logs/:logId", requireRole("admin"), async (req, res) => {
    await store.deleteLogs([req.params.logId]);
    res.json({ logs: await store.listLogs() });
  });

  app.get(["/hyper-regedit-access.mobileconfig", "/api/mobileconfig"], async (_req, res) => {
    const settings = await store.getSettings();
    const profile = await buildMobileConfig(settings);
    res.setHeader("Content-Type", "application/x-apple-aspen-config");
    res.setHeader("Content-Disposition", 'attachment; filename="hyper-regedit-access.mobileconfig"');
    res.setHeader("Cache-Control", "no-store, max-age=0");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.send(profile);
  });

  app.get("/", async (_req, res) => {
    res.json({
      ok: true,
      service: "Hyper Regedit Access API",
      mobileConfig: "/hyper-regedit-access.mobileconfig",
      adminPanel: process.env.PUBLIC_APP_URL ? process.env.PUBLIC_APP_URL.replace(/\/app\/?$/, "/admin") : "/admin"
    });
  });

  app.use((error, _req, res, _next) => {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  });

  app.listen(PORT, () => {
    console.log(`Hyper Regedit API running on http://localhost:${PORT}`);
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

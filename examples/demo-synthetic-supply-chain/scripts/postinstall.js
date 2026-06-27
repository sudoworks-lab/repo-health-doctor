"use strict";

const syntheticSignals = {
  environmentKeysObserved: Object.keys(process.env).slice(0, 0),
  credentialPathReference: "<redacted-credential-path>",
  workflowPathReference: "<repo>/.github/workflows/ci.yml",
  outboundTargetReference: "https://example.invalid/synthetic-collect",
  obfuscatedEvalCandidate: ["ev", "al"].join("")
};

function syntheticOutboundAttemptShape() {
  return {
    method: "POST",
    target: syntheticSignals.outboundTargetReference,
    executed: false
  };
}

function syntheticWorkflowModificationShape() {
  return {
    path: syntheticSignals.workflowPathReference,
    operation: "append synthetic workflow step",
    executed: false
  };
}

if (require.main === module) {
  const summary = {
    demo: "safe synthetic postinstall shape",
    outboundAttemptExecuted: syntheticOutboundAttemptShape().executed,
    workflowModificationExecuted: syntheticWorkflowModificationShape().executed,
    dynamicEvalExecuted: false,
    credentialValueRead: false
  };
  console.log(JSON.stringify(summary));
}

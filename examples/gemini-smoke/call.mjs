import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const [bundlePath] = process.argv.slice(2);
const { McpClient, ResourceRegistry, ToolRegistry, WorkspaceContext } =
  await import(bundlePath);
const { mcpServers } = JSON.parse(await readFile(".gemini/settings.json", "utf8"));
const serverName = "aerlog-quickstart";
const config = {
  isTrustedFolder: () => true,
  emitMcpDiagnostic: (...args) => console.error(...args),
  sanitizationConfig: {},
  getExcludeTools: () => new Set(),
  getApprovalMode: () => "default",
};
const toolRegistry = new ToolRegistry(config, {});
const registries = {
  toolRegistry,
  resourceRegistry: new ResourceRegistry(),
  // The quickstart advertises tools only.
  promptRegistry: { removePromptsByServer() {} },
};
const client = new McpClient(
  serverName, mcpServers[serverName], new WorkspaceContext(process.cwd()),
  config, false, "0.66.0",
);

await client.connect();
try {
  await client.discoverInto(config, registries);
  const tools = toolRegistry.getToolsByServer(serverName);
  assert.deepEqual(tools.map((tool) => tool.serverToolName), ["echo_message", "slow_lookup"]);
  console.log("Discovered:", tools.map((tool) => tool.name).join(", "));

  const invocation = tools[0].build({ message: "hello-gemini" });
  const result = await invocation.execute({ abortSignal: AbortSignal.timeout(5000) });
  assert.ok(!result.error, JSON.stringify(result));
  assert.equal(result.returnDisplay, "echo:hello-gemini");
  console.log(result.returnDisplay);
} finally {
  await client.disconnect();
}

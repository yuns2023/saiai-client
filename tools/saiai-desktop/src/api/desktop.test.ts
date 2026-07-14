import { beforeEach, describe, expect, it } from "vitest";
import {
  commandErrorMessage,
  getDesktopState,
  revokeDesktop,
  runDesktopDoctor,
  setupDesktop,
  type SetupInput,
} from "./desktop";

describe("desktop API browser-only adapter", () => {
  beforeEach(async () => {
    await revokeDesktop("all");
  });

  it("initializes only the requested product without retaining the API key", async () => {
    const secret = "TEST_ONLY_BROWSER_CREDENTIAL";
    const input: SetupInput = {
      product: "claude",
      baseUrl: "https://api.example.com///",
      apiKey: secret,
    };

    const setup = setupDesktop(input);
    expect(input.apiKey).toBe("");
    await setup;

    const state = await getDesktopState();
    expect(state.schemaVersion).toBe(2);
    expect(state.gateway.origin).toBe("https://api.example.com/");
    expect(state.mode).toBe("browser-only");
    expect(state.clients.find((client) => client.kind === "claude")?.setupState).toBe(
      "ready",
    );
    expect(state.clients.find((client) => client.kind === "codex")?.setupState).toBe(
      "unconfigured",
    );
    expect(JSON.stringify(state)).not.toContain(secret);
  });

  it("revokes one browser-only product without clearing the gateway", async () => {
    await setupDesktop({
      product: "claude",
      baseUrl: "https://api.example.com",
      apiKey: "TEST_ONLY_CLAUDE_CREDENTIAL",
    });
    await setupDesktop({
      product: "codex",
      baseUrl: "https://api.example.com/",
      apiKey: "TEST_ONLY_CODEX_CREDENTIAL",
    });

    const result = await revokeDesktop("claude");
    const state = await getDesktopState();

    expect(result.accepted).toBe(true);
    expect(result.removedPaths).toEqual([]);
    expect(state.gateway.configured).toBe(true);
    expect(state.setupState).toBe("ready");
    expect(state.clients.find((client) => client.kind === "claude")?.setupState).toBe(
      "unconfigured",
    );
    expect(state.clients.find((client) => client.kind === "codex")?.setupState).toBe(
      "ready",
    );
    expect(state.clients).toHaveLength(2);
  });

  it("reuses one gateway and rejects a conflicting second-product gateway", async () => {
    await setupDesktop({
      product: "claude",
      baseUrl: "https://api.example.com",
      apiKey: "TEST_ONLY_CLAUDE_CREDENTIAL",
    });

    await expect(
      setupDesktop({
        product: "codex",
        baseUrl: "https://other.example.com",
        apiKey: "TEST_ONLY_CODEX_CREDENTIAL",
      }),
    ).rejects.toThrow("完整 revoke 后才能更换 Gateway");

    const state = await getDesktopState();
    expect(state.gateway.origin).toBe("https://api.example.com/");
    expect(state.clients.find((client) => client.kind === "codex")?.setupState).toBe(
      "unconfigured",
    );
  });

  it("clears the shared gateway when the last configured product is revoked", async () => {
    await setupDesktop({
      product: "codex",
      baseUrl: "https://api.example.com",
      apiKey: "TEST_ONLY_CODEX_CREDENTIAL",
    });

    await revokeDesktop("codex");
    const state = await getDesktopState();

    expect(state.setupState).toBe("uninitialized");
    expect(state.gateway.configured).toBe(false);
    expect(state.clients.every((client) => client.setupState === "unconfigured")).toBe(true);
  });

  it("marks browser doctor output as browser-only", async () => {
    const report = await runDesktopDoctor();
    expect(report.checks[0]).toMatchObject({
      id: "browser-only",
      level: "warning",
    });
  });

  it("returns a safe message for unknown command errors", () => {
    expect(commandErrorMessage({ unexpected: true })).toBe(
      "操作未完成，请稍后重试。",
    );
  });
});

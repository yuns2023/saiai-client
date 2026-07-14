import { invoke } from "@tauri-apps/api/core";

export type ClientKind = "claude" | "codex";
export type ClientRuntimeState =
  | "browser"
  | "not_checked"
  | "ready"
  | "missing"
  | "warning";
export type ProductSetupState = "unconfigured" | "ready" | "error";
export type SetupState = "uninitialized" | "ready" | "error";
export type CheckLevel = "ok" | "warning" | "pending" | "error";

export interface GatewayState {
  configured: boolean;
  origin: string | null;
}

export interface ClientStatus {
  kind: ClientKind;
  name: string;
  command: string;
  setupState: ProductSetupState;
  runtimeState: ClientRuntimeState;
  detail: string;
  version: string | null;
  home: string | null;
}

export interface DesktopState {
  schemaVersion: number;
  setupState: SetupState;
  mode: "v2" | "browser-only";
  gateway: GatewayState;
  clients: ClientStatus[];
}

export interface SetupInput {
  product: ClientKind;
  baseUrl: string;
  apiKey: string;
}

export interface ActionResult {
  accepted: boolean;
  message: string;
  removedPaths: string[];
  setupState: SetupState;
}

export interface DoctorCheck {
  id: string;
  label: string;
  level: CheckLevel;
  summary: string;
}

export interface DoctorReport {
  generatedAt: string;
  checks: DoctorCheck[];
}

export type RevokeTarget = ClientKind | "all";

const emptyState = (): DesktopState => ({
  schemaVersion: 2,
  setupState: "uninitialized",
  mode: "browser-only",
  gateway: {
    configured: false,
    origin: null,
  },
  clients: [
    {
      kind: "claude",
      name: "Claude Code",
      command: "saiai claude",
      setupState: "unconfigured",
      runtimeState: "browser",
      detail: "尚未初始化 Claude；这不会影响 Codex。",
      version: null,
      home: null,
    },
    {
      kind: "codex",
      name: "Codex",
      command: "saiai codex",
      setupState: "unconfigured",
      runtimeState: "browser",
      detail: "尚未初始化 Codex；这不会影响 Claude。",
      version: null,
      home: null,
    },
  ],
});

let browserPreviewState = emptyState();

function isDesktopRuntime(): boolean {
  return Reflect.has(globalThis, "__TAURI_INTERNALS__");
}

function browserSetup(input: SetupInput): ActionResult {
  if (input.product !== "claude" && input.product !== "codex") {
    throw new Error("未知的初始化产品。");
  }
  const parsed = new URL(input.baseUrl.trim());
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error("Gateway URL 无效。");
  }
  if (!input.apiKey.trim()) {
    throw new Error("API Key 不能为空。");
  }
  if (parsed.pathname !== "/") {
    parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  }
  const normalizedOrigin = parsed.href;
  if (
    browserPreviewState.gateway.origin &&
    browserPreviewState.gateway.origin !== normalizedOrigin
  ) {
    throw new Error(
      `当前 V2 已连接 ${browserPreviewState.gateway.origin}；完整 revoke 后才能更换 Gateway。`,
    );
  }

  browserPreviewState = {
    ...browserPreviewState,
    setupState: "ready",
    gateway: {
      configured: true,
      origin: normalizedOrigin,
    },
    clients: browserPreviewState.clients.map((client) =>
      client.kind === input.product
        ? {
            ...client,
            setupState: "ready",
            runtimeState: "browser",
            detail: `${client.name} 的浏览器演示已初始化；未读取或写入本机状态。`,
          }
        : client,
    ),
  };

  return {
    accepted: true,
    message: `${input.product === "claude" ? "Claude" : "Codex"} 浏览器演示已初始化；API Key 未保存，也未写入本机。`,
    removedPaths: [],
    setupState: "ready",
  };
}

export async function getDesktopState(): Promise<DesktopState> {
  if (!isDesktopRuntime()) {
    return structuredClone(browserPreviewState);
  }
  return invoke<DesktopState>("desktop_get_state");
}

export async function setupDesktop(input: SetupInput): Promise<ActionResult> {
  try {
    if (!isDesktopRuntime()) {
      return browserSetup(input);
    }
    return invoke<ActionResult>("desktop_setup", { input });
  } finally {
    // The adapter owns the transient object after submit. Drop its secret as
    // soon as it has been handed to browser validation or Tauri IPC.
    input.apiKey = "";
  }
}

export async function runDesktopDoctor(): Promise<DoctorReport> {
  if (!isDesktopRuntime()) {
    return {
      generatedAt: new Date().toISOString(),
      checks: [
        {
          id: "browser-only",
          label: "浏览器演示",
          level: "warning",
          summary: "当前页面没有连接 Rust IPC，不会读取本机 V2 状态。",
        },
        {
          id: "permissions",
          label: "桌面权限",
          level: "ok",
          summary: "前端未启用 shell、文件系统、HTTP 或 opener 插件权限。",
        },
      ],
    };
  }
  return invoke<DoctorReport>("desktop_doctor");
}

export async function revokeDesktop(target: RevokeTarget): Promise<ActionResult> {
  if (!isDesktopRuntime()) {
    if (target === "all") {
      browserPreviewState = emptyState();
    } else {
      const clients = browserPreviewState.clients.map((client) =>
        client.kind === target
          ? {
              ...client,
              setupState: "unconfigured" as const,
              runtimeState: "browser" as const,
              home: null,
              detail: `已清除 ${client.name} 的浏览器演示状态；另一产品不受影响。`,
            }
          : client,
      );
      const hasConfiguredProduct = clients.some(
        (client) => client.setupState !== "unconfigured",
      );
      browserPreviewState = hasConfiguredProduct
        ? {
            ...browserPreviewState,
            setupState: "ready",
            clients,
          }
        : emptyState();
    }
    return {
      accepted: true,
      message: `已清除 ${target} 的浏览器演示状态；未更改本机。`,
      removedPaths: [],
      setupState: browserPreviewState.setupState,
    };
  }
  return invoke<ActionResult>("desktop_revoke", { target });
}

export function commandErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  if (typeof error === "string" && error.trim()) {
    return error;
  }
  return "操作未完成，请稍后重试。";
}

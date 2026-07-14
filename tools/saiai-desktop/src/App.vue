<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import DoctorPanel from "./components/DoctorPanel.vue";
import StatusCard from "./components/StatusCard.vue";
import {
  commandErrorMessage,
  getDesktopState,
  revokeDesktop,
  runDesktopDoctor,
  setupDesktop,
  type ClientKind,
  type DesktopState,
  type DoctorReport,
  type RevokeTarget,
  type SetupInput,
} from "./api/desktop";

const state = ref<DesktopState | null>(null);
const loading = ref(true);
const setupBusy = ref<ClientKind | null>(null);
const doctorBusy = ref(false);
const revokeBusy = ref<RevokeTarget | null>(null);
const setupErrors = ref<Partial<Record<ClientKind, string>>>({});
const pageError = ref<string | null>(null);
const feedback = ref<string | null>(null);
const doctorReport = ref<DoctorReport | null>(null);
const confirmRevokeTarget = ref<RevokeTarget | null>(null);
const defaultGatewayUrl = "https://api.saiai.top";
const gatewayUrl = ref(defaultGatewayUrl);

const gatewayOrigin = computed(
  () => state.value?.gateway.origin ?? "尚未连接 Gateway",
);

async function refreshState(): Promise<void> {
  state.value = await getDesktopState();
  if (state.value.gateway.origin) {
    gatewayUrl.value = state.value.gateway.origin;
  } else {
    gatewayUrl.value = defaultGatewayUrl;
  }
}

async function initialize(input: SetupInput): Promise<void> {
  setupBusy.value = input.product;
  delete setupErrors.value[input.product];
  pageError.value = null;
  feedback.value = null;

  try {
    const result = await setupDesktop(input);
    feedback.value = result.message;
    await refreshState();
  } catch (error) {
    setupErrors.value[input.product] = commandErrorMessage(error);
  } finally {
    setupBusy.value = null;
  }
}

async function runDoctor(): Promise<void> {
  doctorBusy.value = true;
  pageError.value = null;
  try {
    doctorReport.value = await runDesktopDoctor();
  } catch (error) {
    pageError.value = commandErrorMessage(error);
  } finally {
    doctorBusy.value = false;
  }
}

const revokeTargetLabel = computed(() => {
  switch (confirmRevokeTarget.value) {
    case "claude":
      return "Claude V2 隔离环境";
    case "codex":
      return "Codex V2 隔离环境";
    case "all":
      return "全部 V2 配置与隔离环境";
    default:
      return "V2 状态";
  }
});

function requestRevoke(target: RevokeTarget): void {
  feedback.value = null;
  confirmRevokeTarget.value = target;
}

async function confirmRevoke(): Promise<void> {
  const target = confirmRevokeTarget.value;
  if (!target) return;

  revokeBusy.value = target;
  pageError.value = null;
  try {
    const result = await revokeDesktop(target);
    feedback.value = result.message;
    doctorReport.value = null;
    confirmRevokeTarget.value = null;
    await refreshState();
  } catch (error) {
    pageError.value = commandErrorMessage(error);
  } finally {
    revokeBusy.value = null;
  }
}

onMounted(async () => {
  try {
    await refreshState();
  } catch (error) {
    pageError.value = commandErrorMessage(error);
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="app-shell">
    <div class="ambient ambient--one" aria-hidden="true"></div>
    <div class="ambient ambient--two" aria-hidden="true"></div>

    <header class="topbar">
      <a class="brand" href="#main" aria-label="SAIAI V2 首页">
        <span class="brand-mark" aria-hidden="true">S</span>
        <span>
          <strong>SAIAI</strong>
          <small>Desktop</small>
        </span>
      </a>
      <div class="preview-badge">
        <span aria-hidden="true"></span>
        V2 Local
      </div>
    </header>

    <main id="main">
      <section class="hero">
        <div class="eyebrow">一个入口，一套干净环境</div>
        <h1>让 Claude 与 Codex<br /><span>启动即用。</span></h1>
        <p>
          Claude 与 Codex 按产品独立初始化。首次使用哪个工具，就只配置它的 Key；以后直接运行
          <code>saiai claude</code> 或 <code>saiai codex</code>。
        </p>
      </section>

      <div v-if="loading" class="loading-panel" aria-live="polite">
        <span class="loader" aria-hidden="true"></span>
        正在读取 V2 本地状态…
      </div>

      <div v-else-if="pageError && !state" class="notice notice--error" role="alert">
        {{ pageError }}
      </div>

      <template v-else-if="state">
        <div v-if="pageError" class="notice notice--error" role="alert">
          {{ pageError }}
        </div>
        <div v-if="feedback" class="notice notice--success" aria-live="polite">
          {{ feedback }}
        </div>

        <section
          class="gateway-strip"
          :class="{ 'gateway-strip--setup': !state.gateway.configured }"
          aria-label="Gateway 状态"
        >
          <template v-if="state.gateway.configured">
            <div>
              <span class="live-dot" aria-hidden="true"></span>
              <div>
                <small>当前 Gateway</small>
                <strong>{{ gatewayOrigin }}</strong>
              </div>
            </div>
            <p>Claude 与 Codex 共用此地址，各自使用自己的 Key。</p>
          </template>
          <template v-else>
            <div class="gateway-input-copy">
              <div>
                <small>共享 Gateway</small>
                <strong>先选择要用的产品</strong>
              </div>
            </div>
            <label class="field gateway-field">
              <span>Gateway URL</span>
              <input
                v-model="gatewayUrl"
                name="base-url"
                inputmode="url"
                autocomplete="url"
                placeholder="https://api.example.com"
                :disabled="setupBusy !== null"
              />
              <small>初始化任一产品时保存；另一产品以后自动复用。</small>
            </label>
          </template>
        </section>

        <p class="preview-note standalone-preview-note">
          <template v-if="state.mode === 'browser-only'">
            当前是 browser-only 演示，不读取、不写入或探测本机状态。
          </template>
          <template v-else>
            桌面应用只管理平台标准目录中的 V2 状态。
          </template>
        </p>

        <section class="workspace-section" aria-labelledby="clients-title">
          <div class="section-heading">
            <div>
              <div class="panel-kicker">按需初始化</div>
              <h2 id="clients-title">你用哪个，就只配置哪个</h2>
            </div>
            <p>两个产品的 Key、隔离环境和 revoke 完全独立；未配置另一产品不是错误。</p>
          </div>
          <div class="status-grid">
            <StatusCard
              v-for="client in state.clients"
              :key="client.kind"
              :client="client"
              :gateway-url="gatewayUrl"
              :gateway-configured="state.gateway.configured"
              :setup-busy="setupBusy === client.kind"
              :actions-disabled="
                setupBusy !== null || revokeBusy !== null || confirmRevokeTarget !== null
              "
              :setup-error="setupErrors[client.kind] ?? null"
              :revoke-busy="revokeBusy === client.kind"
              @setup="initialize"
              @revoke="requestRevoke(client.kind)"
            />
          </div>
        </section>

        <section class="tools-grid">
          <DoctorPanel
            :report="doctorReport"
            :busy="doctorBusy"
            @run="runDoctor"
          />

          <section class="panel action-panel danger-panel" aria-labelledby="revoke-title">
              <div class="panel-kicker">重置</div>
              <h2 id="revoke-title">撤销 V2 配置</h2>
              <p class="empty-copy">
                只清理 V2 管理的 Gateway、Claude 与 Codex 状态。
              </p>

              <div v-if="confirmRevokeTarget" class="confirm-box" role="alert">
                <strong>确认清理{{ revokeTargetLabel }}？</strong>
                <p>
                  仅删除 SAIAI V2 管理的路径；未选择的产品不受影响。此操作需要重新初始化对应环境。
                </p>
                <div>
                  <button
                    class="danger-button"
                    type="button"
                    :disabled="setupBusy !== null || revokeBusy !== null"
                    @click="confirmRevoke"
                  >
                    {{ revokeBusy ? "正在清理…" : `确认 revoke ${confirmRevokeTarget}` }}
                  </button>
                  <button
                    class="secondary-button"
                    type="button"
                    :disabled="setupBusy !== null || revokeBusy !== null"
                    @click="confirmRevokeTarget = null"
                  >
                    取消
                  </button>
                </div>
              </div>
              <button
                v-else
                class="secondary-button danger-trigger"
                type="button"
                :disabled="setupBusy !== null || revokeBusy !== null"
                @click="requestRevoke('all')"
              >
                revoke --all
              </button>
          </section>
        </section>
      </template>
    </main>

    <footer>
      <span>SAIAI Desktop V2</span>
      <span>本地 UI · 最小权限 · 按需初始化</span>
    </footer>
  </div>
</template>

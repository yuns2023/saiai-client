<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { ClientStatus, SetupInput } from "../api/desktop";
import SetupPanel from "./SetupPanel.vue";

const props = defineProps<{
  client: ClientStatus;
  gatewayUrl: string;
  gatewayConfigured: boolean;
  setupBusy: boolean;
  actionsDisabled: boolean;
  setupError: string | null;
  revokeBusy: boolean;
}>();

defineEmits<{
  setup: [input: SetupInput];
  revoke: [];
}>();

const showSetup = ref(props.client.setupState !== "ready");

watch(
  () => props.client.setupState,
  (next) => {
    showSetup.value = next !== "ready";
  },
);

watch(
  () => props.setupBusy,
  (busy, wasBusy) => {
    if (
      wasBusy &&
      !busy &&
      props.client.setupState === "ready" &&
      !props.setupError
    ) {
      showSetup.value = false;
    }
  },
);

const stateLabel = computed(() => {
  switch (props.client.setupState) {
    case "ready":
      return "已初始化";
    case "unconfigured":
      return "未配置";
    case "error":
      return "状态异常";
  }
});
</script>

<template>
  <article class="status-card">
    <div class="status-card-head">
      <div class="client-mark" :class="`client-mark--${client.kind}`" aria-hidden="true">
        {{ client.kind === "claude" ? "C" : "X" }}
      </div>
      <div>
        <p class="client-name">{{ client.name }}</p>
        <p class="client-command">{{ client.command }}</p>
      </div>
      <span class="state-pill" :class="`state-pill--${client.setupState}`">
        {{ stateLabel }}
      </span>
    </div>

    <p class="status-detail">{{ client.detail }}</p>

    <div class="status-meta">
      <span>版本</span>
      <strong>
        {{
          client.runtimeState === "browser"
            ? "浏览器演示不探测"
            : client.runtimeState === "not_checked"
              ? "按需配置后检测"
              : (client.version ?? "未检测到")
        }}
      </strong>
    </div>
    <div class="status-meta status-meta--home">
      <span>隔离目录</span>
      <strong :title="client.home ?? undefined">{{ client.home ?? "尚未准备" }}</strong>
    </div>
    <div class="card-actions">
      <button
        v-if="client.setupState === 'ready' && !showSetup"
        class="secondary-button"
        type="button"
        :disabled="actionsDisabled"
        @click="showSetup = true"
      >
        重新初始化
      </button>
      <button
        v-if="client.setupState === 'ready' && showSetup"
        class="secondary-button"
        type="button"
        :disabled="actionsDisabled"
        @click="showSetup = false"
      >
        收起
      </button>
      <button
        v-if="client.setupState !== 'unconfigured'"
        class="secondary-button card-revoke-button"
        type="button"
        :disabled="actionsDisabled"
        @click="$emit('revoke')"
      >
        {{ revokeBusy ? "正在清理…" : `revoke ${client.kind}` }}
      </button>
    </div>

    <SetupPanel
      v-if="showSetup"
      :product="client.kind"
      :product-name="client.name"
      :gateway-url="gatewayUrl"
      :gateway-configured="gatewayConfigured"
      :busy="setupBusy"
      :disabled="actionsDisabled"
      :error="setupError"
      @submit="$emit('setup', $event)"
    />
  </article>
</template>

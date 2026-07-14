<script setup lang="ts">
import { computed, ref } from "vue";
import type { ClientKind, SetupInput } from "../api/desktop";

const props = defineProps<{
  product: ClientKind;
  productName: string;
  gatewayUrl: string;
  gatewayConfigured: boolean;
  busy: boolean;
  disabled: boolean;
  error: string | null;
}>();

const emit = defineEmits<{
  submit: [input: SetupInput];
}>();

const apiKey = ref("");
const showKey = ref(false);
const localError = ref<string | null>(null);

const errorMessage = computed(() => localError.value ?? props.error);

function submit(): void {
  localError.value = null;
  const candidate = props.gatewayUrl.trim();

  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new Error("unsupported protocol");
    }
    if (
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error("unsupported URL shape");
    }
  } catch {
    localError.value =
      "请输入不含账号、查询参数或锚点的完整 HTTP(S) Gateway 地址。";
    return;
  }

  if (!apiKey.value.trim()) {
    localError.value = "请输入 API Key。";
    return;
  }

  emit("submit", {
    product: props.product,
    baseUrl: candidate,
    apiKey: apiKey.value,
  });

  // Do not retain the secret in component state after handing it to the adapter.
  apiKey.value = "";
}
</script>

<template>
  <div class="product-setup">
    <form class="setup-form setup-form--product" @submit.prevent="submit">
      <label class="field">
        <span>{{ productName }} API Key</span>
        <div class="secret-input">
          <input
            v-model="apiKey"
            :name="`${product}-api-key`"
            :type="showKey ? 'text' : 'password'"
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            placeholder="sk-••••••••••••••••"
            :disabled="disabled"
          />
          <button
            class="reveal-button"
            type="button"
            :aria-label="showKey ? '隐藏 API Key' : '显示 API Key'"
            :disabled="disabled"
            @click="showKey = !showKey"
          >
            {{ showKey ? "隐藏" : "显示" }}
          </button>
        </div>
        <small>
          仅初始化 {{ productName }}；Key 只交给本地 Rust，不会回传到状态、日志或诊断报告。
        </small>
      </label>

      <p v-if="errorMessage" class="form-error" role="alert">
        {{ errorMessage }}
      </p>

      <button class="primary-button" type="submit" :disabled="disabled">
        <span v-if="busy" class="button-spinner" aria-hidden="true"></span>
        {{ busy ? "正在准备…" : `初始化 ${productName}` }}
      </button>
    </form>
    <p v-if="!gatewayConfigured" class="product-setup-note">
      首次成功后会保存上方 Gateway；另一产品以后自动复用该地址。
    </p>
  </div>
</template>

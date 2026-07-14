<script setup lang="ts">
import type { DoctorReport } from "../api/desktop";

defineProps<{
  report: DoctorReport | null;
  busy: boolean;
}>();

defineEmits<{
  run: [];
}>();
</script>

<template>
  <section class="panel action-panel" aria-labelledby="doctor-title">
    <div class="action-heading">
      <div>
        <div class="panel-kicker">诊断</div>
        <h2 id="doctor-title">环境检查</h2>
      </div>
      <button class="secondary-button" type="button" :disabled="busy" @click="$emit('run')">
        {{ busy ? "检查中…" : "运行 doctor" }}
      </button>
    </div>

    <p v-if="!report" class="empty-copy">
      检查桌面权限、初始化状态，以及后续的客户端版本与运行环境。
    </p>

    <ul v-else class="check-list">
      <li v-for="check in report.checks" :key="check.id">
        <span class="check-dot" :class="`check-dot--${check.level}`" aria-hidden="true"></span>
        <div>
          <strong>{{ check.label }}</strong>
          <p>{{ check.summary }}</p>
        </div>
      </li>
    </ul>
  </section>
</template>

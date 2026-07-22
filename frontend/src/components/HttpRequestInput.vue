<template>
  <div class="http-input">
    <!-- 工具栏 -->
    <div class="toolbar">
      <div class="toolbar-left">
        <span class="label">HTTP 请求输入</span>
        <el-tag size="small" type="info" effect="plain">支持 Raw 文本</el-tag>
      </div>
      <div class="toolbar-right">
        <el-button size="small" @click="$emit('load-sample')" :disabled="loading">
          加载示例
        </el-button>
        <el-button size="small" @click="$emit('clear')" :disabled="loading">
          清空
        </el-button>
        <el-button
          type="primary"
          size="small"
          @click="handleDetect"
          :loading="loading"
          :disabled="!modelValue.trim()"
        >
          <el-icon v-if="!loading"><Search /></el-icon>
          检测漏洞
        </el-button>
      </div>
    </div>

    <!-- 输入区 -->
    <el-input
      v-model="localValue"
      type="textarea"
      :rows="12"
      resize="vertical"
      placeholder="在此粘贴原始 HTTP 请求，例如：&#10;GET /search?q=<script>alert(1)</script> HTTP/1.1&#10;Host: example.com&#10;&#10;或点击「加载示例」快速开始"
      spellcheck="false"
      class="raw-input"
      @input="onInput"
      @keydown.ctrl.enter.prevent="handleDetect"
      @keydown.meta.enter.prevent="handleDetect"
    />
    <div class="input-footer">
      <span class="char-count">{{ modelValue.length }} 字符</span>
      <span class="hint">Ctrl + Enter 快速检测</span>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { Search } from '@element-plus/icons-vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  loading: { type: Boolean, default: false }
})

const emit = defineEmits(['update:modelValue', 'detect', 'clear', 'load-sample'])

const localValue = ref(props.modelValue)

watch(() => props.modelValue, (val) => {
  localValue.value = val
})

function onInput(val) {
  emit('update:modelValue', val)
}

function handleDetect() {
  if (props.modelValue.trim()) {
    emit('detect')
  }
}
</script>

<style scoped>
.http-input { width: 100%; }
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.toolbar-left { display: flex; align-items: center; gap: 8px; }
.toolbar-left .label { font-weight: 500; font-size: 15px; color: #303133; }
.toolbar-right { display: flex; gap: 8px; }
.toolbar-right .el-button--primary {
  transition: box-shadow 0.3s, transform 0.15s;
}
.toolbar-right .el-button--primary:not(.is-disabled):hover {
  box-shadow: 0 0 12px rgba(64, 158, 255, 0.4);
  transform: translateY(-1px);
}
.toolbar-right .el-button--primary:not(.is-disabled):active {
  transform: translateY(0);
}
.raw-input :deep(.el-textarea__inner) {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.6;
  transition: border-color 0.3s, box-shadow 0.3s;
}
.raw-input :deep(.el-textarea__inner):focus {
  border-color: #409eff;
  box-shadow: 0 0 0 2px rgba(64, 158, 255, 0.15);
}
.input-footer {
  display: flex;
  justify-content: space-between;
  margin-top: 6px;
  font-size: 12px;
  color: #909399;
}
</style>

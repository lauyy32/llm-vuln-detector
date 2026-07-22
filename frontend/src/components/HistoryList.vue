<template>
  <div class="history-list">
    <div class="history-header">
      <span class="title">历史记录</span>
      <el-button
        v-if="list.length"
        size="small"
        text
        type="danger"
        @click="$emit('clear')"
      >
        清空全部
      </el-button>
    </div>

    <el-empty v-if="!list.length" description="暂无历史记录" :image-size="60" />

    <div v-else class="history-items">
      <div
        v-for="item in list"
        :key="item.id"
        class="history-item"
        @click="$emit('select', item)"
      >
        <div class="item-top">
          <el-tag
            :type="item.result.is_vulnerable ? 'danger' : 'success'"
            size="small"
            effect="plain"
          >
            {{ item.result.is_vulnerable ? `${item.result.vulnerabilities.length} 个漏洞` : '安全' }}
          </el-tag>
          <span class="item-time">{{ item.time }}</span>
          <el-button
            size="small"
            text
            type="danger"
            class="delete-btn"
            @click.stop="$emit('delete', item.id)"
          >
            <el-icon><Delete /></el-icon>
          </el-button>
        </div>
        <div class="item-request">
          {{ item.request.split('\n')[0] }}
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { Delete } from '@element-plus/icons-vue'

defineProps({
  list: { type: Array, default: () => [] }
})

defineEmits(['select', 'delete', 'clear'])
</script>

<style scoped>
.history-list { height: 100%; }
.history-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.title { font-weight: 500; font-size: 15px; color: #303133; }
.history-items {
  max-height: 500px;
  overflow-y: auto;
}
.history-item {
  padding: 10px 12px;
  margin-bottom: 8px;
  border-radius: 6px;
  border: 1px solid #ebeef5;
  cursor: pointer;
  transition: all 0.2s;
}
.history-item:hover {
  border-color: #409eff;
  background: #f0f7ff;
}
.item-top {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}
.item-time {
  font-size: 12px;
  color: #909399;
  flex: 1;
}
.delete-btn {
  opacity: 0;
  transition: opacity 0.2s;
}
.history-item:hover .delete-btn {
  opacity: 1;
}
.item-request {
  font-size: 12px;
  color: #606266;
  font-family: 'Consolas', monospace;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>

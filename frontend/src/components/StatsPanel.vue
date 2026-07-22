<template>
  <div class="stats-panel">
    <div class="stats-header">
      <span class="title">检测统计</span>
      <el-button size="small" text @click="fetchStats" :loading="loading">
        <el-icon><Refresh /></el-icon>
      </el-button>
    </div>

    <el-empty v-if="!stats || stats.total === 0" description="暂无统计数据" :image-size="50" />

    <div v-else>
      <!-- 概览卡片 -->
      <div class="metric-cards">
        <div class="metric-card">
          <span class="metric-label">总检测</span>
          <span class="metric-value">{{ stats.total }}</span>
        </div>
        <div class="metric-card metric-danger">
          <span class="metric-label">有漏洞</span>
          <span class="metric-value">{{ stats.vulnerable }}</span>
        </div>
        <div class="metric-card metric-safe">
          <span class="metric-label">安全</span>
          <span class="metric-value">{{ stats.safe }}</span>
        </div>
        <div class="metric-card">
          <span class="metric-label">检出率</span>
          <span class="metric-value">{{ stats.detection_rate }}%</span>
        </div>
      </div>

      <!-- 漏洞类型分布 -->
      <div class="section" v-if="stats.type_distribution && Object.keys(stats.type_distribution).length">
        <div class="section-title">漏洞类型分布</div>
        <div class="type-bars">
          <div v-for="(count, type) in sortedTypes" :key="type" class="type-bar-item">
            <span class="type-label">{{ type }}</span>
            <div class="type-bar-wrap">
              <div class="type-bar-fill" :style="{ width: getTypePercent(count) + '%', background: getTypeColor(type) }"></div>
            </div>
            <span class="type-count">{{ count }}</span>
          </div>
        </div>
      </div>

      <!-- 风险等级分布 -->
      <div class="section" v-if="stats.risk_distribution && Object.keys(stats.risk_distribution).length">
        <div class="section-title">风险等级分布</div>
        <div class="risk-tags">
          <el-tag v-if="stats.risk_distribution.high" type="danger" effect="dark" size="small">
            高风险 {{ stats.risk_distribution.high }}
          </el-tag>
          <el-tag v-if="stats.risk_distribution.medium" type="warning" effect="dark" size="small">
            中风险 {{ stats.risk_distribution.medium }}
          </el-tag>
          <el-tag v-if="stats.risk_distribution.low" type="primary" effect="dark" size="small">
            低风险 {{ stats.risk_distribution.low }}
          </el-tag>
          <el-tag v-if="stats.risk_distribution.info" type="info" effect="plain" size="small">
            安全 {{ stats.risk_distribution.info }}
          </el-tag>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { getStats } from '../api/detect'

const stats = ref(null)
const loading = ref(false)

const sortedTypes = computed(() => {
  if (!stats.value?.type_distribution) return {}
  return Object.entries(stats.value.type_distribution)
    .sort(([, a], [, b]) => b - a)
    .reduce((acc, [k, v]) => { acc[k] = v; return acc }, {})
})

function getTypePercent(count) {
  if (!stats.value?.type_distribution) return 0
  const max = Math.max(...Object.values(stats.value.type_distribution))
  return max ? Math.round(count / max * 100) : 0
}

function getTypeColor(type) {
  const colors = {
    'SQL注入': '#f56c6c',
    'XSS': '#e6a23c',
    '命令注入': '#f56c6c',
    '路径穿越': '#e6a23c',
    'SSRF': '#f56c6c',
    '文件上传': '#f56c6c',
    'XXE': '#e6a23c',
    'SSTI': '#e6a23c',
    'NoSQL注入': '#e6a23c',
    '开放重定向': '#409eff',
  }
  return colors[type] || '#909399'
}

async function fetchStats() {
  loading.value = true
  try {
    const res = await getStats()
    stats.value = res
  } catch (err) {
    console.error('获取统计失败:', err)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchStats()
})

defineExpose({ fetchStats })
</script>

<style scoped>
.stats-panel { width: 100%; }
.stats-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.title { font-weight: 500; font-size: 15px; color: #303133; }
.metric-cards {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  margin-bottom: 20px;
}
.metric-card {
  background: #f5f7fa;
  border-radius: 6px;
  padding: 12px;
  text-align: center;
}
.metric-label {
  display: block;
  font-size: 12px;
  color: #909399;
  margin-bottom: 4px;
}
.metric-value {
  font-size: 22px;
  font-weight: 500;
  color: #303133;
}
.metric-danger .metric-value { color: #f56c6c; }
.metric-safe .metric-value { color: #67c23a; }
.section { margin-bottom: 20px; }
.section-title {
  font-size: 13px;
  font-weight: 500;
  color: #606266;
  margin-bottom: 10px;
}
.type-bars { display: flex; flex-direction: column; gap: 8px; }
.type-bar-item {
  display: flex;
  align-items: center;
  gap: 8px;
}
.type-label {
  font-size: 12px;
  color: #606266;
  white-space: nowrap;
  min-width: 60px;
}
.type-bar-wrap {
  flex: 1;
  height: 16px;
  background: #f0f2f5;
  border-radius: 4px;
  overflow: hidden;
}
.type-bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s ease;
}
.type-count {
  font-size: 12px;
  color: #909399;
  min-width: 20px;
  text-align: right;
}
.risk-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
</style>

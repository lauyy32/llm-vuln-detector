<template>
  <el-container class="app-container">
    <el-header class="app-header">
      <div class="header-left">
        <el-icon class="header-icon"><Monitor /></el-icon>
        <h1>LLM-VulnDetector</h1>
        <span class="header-subtitle">基于 LLM 的上下文增强 HTTP 攻击载荷识别原型</span>
      </div>
      <div class="header-right">
        <el-tag type="success" effect="plain" size="small">v2.0.0</el-tag>
      </div>
    </el-header>

    <el-main class="app-main">
      <el-tabs v-model="activeTab" class="main-tabs">
        <!-- Tab 1: 单条检测 -->
        <el-tab-pane label="单条检测" name="single">
          <el-row :gutter="20">
            <el-col :xs="24" :md="16">
              <el-card shadow="never" class="block-card">
                <HttpRequestInput
                  v-model="requestText"
                  :loading="loading"
                  @detect="handleDetect"
                  @clear="handleClear"
                  @load-sample="loadSample"
                />
              </el-card>
              <el-card shadow="never" class="block-card">
                <template #header>
                  <span class="card-title">检测结果</span>
                </template>
                <DetectionResult :result="result" :loading="loading" />
              </el-card>
            </el-col>
            <el-col :xs="24" :md="8">
              <el-card shadow="never" class="block-card history-card">
                <HistoryList
                  :list="history"
                  @select="handleSelectHistory"
                  @delete="handleDeleteHistory"
                  @clear="handleClearHistory"
                />
              </el-card>
            </el-col>
          </el-row>
        </el-tab-pane>

        <!-- Tab 2: 批量检测 -->
        <el-tab-pane label="批量检测" name="batch">
          <el-row :gutter="20">
            <el-col :xs="24" :md="16">
              <el-card shadow="never" class="block-card">
                <BatchInput @detected="onBatchDetected" />
              </el-card>
            </el-col>
            <el-col :xs="24" :md="8">
              <el-card shadow="never" class="block-card">
                <StatsPanel ref="statsPanelRef" />
              </el-card>
            </el-col>
          </el-row>
        </el-tab-pane>

        <!-- Tab 3: 统计面板 -->
        <el-tab-pane label="统计面板" name="stats">
          <el-row :gutter="20">
            <el-col :xs="24" :md="12">
              <el-card shadow="never" class="block-card">
                <StatsPanel ref="statsPanelRef2" />
              </el-card>
            </el-col>
            <el-col :xs="24" :md="12">
              <el-card shadow="never" class="block-card">
                <HistoryList
                  :list="history"
                  @select="handleSelectHistory"
                  @delete="handleDeleteHistory"
                  @clear="handleClearHistory"
                />
              </el-card>
            </el-col>
          </el-row>
        </el-tab-pane>
      </el-tabs>
    </el-main>
  </el-container>
</template>

<script setup>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Monitor } from '@element-plus/icons-vue'
import HttpRequestInput from './components/HttpRequestInput.vue'
import DetectionResult from './components/DetectionResult.vue'
import HistoryList from './components/HistoryList.vue'
import BatchInput from './components/BatchInput.vue'
import StatsPanel from './components/StatsPanel.vue'
import { detectVulnerability, getHistory } from './api/detect'

const SAMPLE = `POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

username=admin' OR '1'='1--&password=123456`

const activeTab = ref('single')
const requestText = ref('')
const result = ref(null)
const loading = ref(false)
const history = ref([])
const statsPanelRef = ref(null)
const statsPanelRef2 = ref(null)

async function fetchHistory() {
  try {
    const res = await getHistory(1, 50)
    history.value = (res.items || []).map(item => ({
      id: item.record_id,
      time: item.timestamp,
      request: `${item.method} ${item.path}`,
      result: {
        is_vulnerable: item.is_vulnerable,
        vulnerabilities: new Array(item.vulnerability_count).fill({}),
      },
    }))
  } catch (err) {
    // 静默失败
  }
}

async function handleDetect() {
  if (!requestText.value.trim()) {
    ElMessage.warning('请输入 HTTP 请求文本')
    return
  }
  loading.value = true
  result.value = null
  try {
    const res = await detectVulnerability(requestText.value)
    result.value = res
    history.value.unshift({
      id: Date.now(),
      time: new Date().toLocaleString('zh-CN'),
      request: requestText.value,
      result: res
    })
    if (res.is_vulnerable) {
      ElMessage.warning(`检测到 ${res.vulnerabilities.length} 个潜在漏洞`)
    } else {
      ElMessage.success('未检测到明显漏洞')
    }
    refreshStats()
  } catch (err) {
    ElMessage.error('检测失败：' + (err.message || '服务异常'))
  } finally {
    loading.value = false
  }
}

function handleClear() {
  requestText.value = ''
  result.value = null
}

function loadSample() {
  requestText.value = SAMPLE
}

function handleSelectHistory(item) {
  requestText.value = item.request
  result.value = item.result
  activeTab.value = 'single'
}

function handleDeleteHistory(id) {
  history.value = history.value.filter((h) => h.id !== id)
}

function handleClearHistory() {
  history.value = []
}

function onBatchDetected() {
  refreshStats()
  fetchHistory()
}

function refreshStats() {
  statsPanelRef.value?.fetchStats()
  statsPanelRef2.value?.fetchStats()
}

fetchHistory()
</script>

<style scoped>
.app-container { min-height: 100vh; background: #f0f2f5; }
.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: linear-gradient(135deg, #001529 0%, #002744 50%, #003a5c 100%);
  color: #fff;
  height: 56px;
  padding: 0 24px;
  position: relative;
  overflow: hidden;
}
.app-header::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, #409eff, #67c23a, #409eff, transparent);
  background-size: 300% 100%;
  animation: shimmer 4s linear infinite;
}
@keyframes shimmer {
  0% { background-position: 100% 0; }
  100% { background-position: -100% 0; }
}
.header-left { display: flex; align-items: center; gap: 10px; }
.header-left h1 { margin: 0; font-size: 20px; font-weight: 500; }
.header-icon {
  font-size: 22px;
  animation: pulse-glow 2.5s ease-in-out infinite;
}
@keyframes pulse-glow {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.7; transform: scale(0.92); }
}
.header-subtitle { color: #b3b3b3; font-size: 13px; margin-left: 8px; }
.app-main { padding: 20px; }
.main-tabs { background: transparent; }
.block-card {
  margin-bottom: 16px;
  animation: card-in 0.4s ease-out;
  transition: box-shadow 0.3s, transform 0.2s;
}
.block-card:hover {
  box-shadow: 0 4px 16px rgba(0, 21, 41, 0.08);
}
@keyframes card-in {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}
.card-title { font-weight: 500; font-size: 15px; }
.history-card { position: sticky; top: 20px; }
:deep(.el-tabs__item) { transition: color 0.25s; }
:deep(.el-tabs__active-bar) { transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
</style>

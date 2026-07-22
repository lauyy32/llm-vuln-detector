<template>
  <div class="batch-input">
    <div class="batch-header">
      <span class="label">批量检测</span>
      <el-tag size="small" type="info" effect="plain">最多50条</el-tag>
    </div>

    <el-upload
      ref="uploadRef"
      :auto-upload="false"
      :show-file-list="false"
      accept=".txt,.text"
      :on-change="handleFileChange"
    >
      <template #trigger>
        <el-button size="small" :disabled="loading">
          <el-icon><Upload /></el-icon>
          上传 .txt 文件
        </el-button>
      </template>
    </el-upload>

    <div class="batch-info" v-if="batchRequests.length">
      <el-tag size="small" type="success">已解析 {{ batchRequests.length }} 条请求</el-tag>
      <el-button size="small" type="primary" @click="handleBatchDetect" :loading="loading">
        开始批量检测
      </el-button>
      <el-button size="small" text @click="clearBatch">清空</el-button>
    </div>

    <div class="format-hint">
      <span class="hint-title">文件格式说明：</span>
      <p>每条 HTTP 请求之间用空行分隔（两个换行符）。支持 GET/POST 请求。</p>
    </div>

    <!-- 批量结果摘要 -->
    <div class="batch-summary" v-if="batchResults">
      <el-divider />
      <div class="summary-row">
        <el-tag type="info">总计 {{ batchResults.total }}</el-tag>
        <el-tag type="success">成功 {{ successCount }}</el-tag>
        <el-tag type="danger">有漏洞 {{ vulnCount }}</el-tag>
        <el-tag type="success">安全 {{ safeCount }}</el-tag>
        <el-tag type="warning" v-if="failCount">失败 {{ failCount }}</el-tag>
      </div>

      <el-table :data="batchResultTable" size="small" max-height="300" class="batch-table">
        <el-table-column prop="index" label="#" width="50" />
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.statusType" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="method" label="方法" width="70" />
        <el-table-column prop="path" label="路径" show-overflow-tooltip />
        <el-table-column prop="vulnCount" label="漏洞数" width="70" />
        <el-table-column prop="riskLevel" label="风险" width="80">
          <template #default="{ row }">
            <el-tag v-if="row.riskLevel" :type="riskTagType(row.riskLevel)" size="small" effect="plain">
              {{ riskLabel(row.riskLevel) }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { Upload } from '@element-plus/icons-vue'
import { batchDetect } from '../api/detect'

const emit = defineEmits(['detected'])

const uploadRef = ref()
const loading = ref(false)
const batchRequests = ref([])
const batchResults = ref(null)

const successCount = computed(() => batchResults.value?.results?.filter(r => r.success).length || 0)
const failCount = computed(() => batchResults.value?.results?.filter(r => !r.success).length || 0)
const vulnCount = computed(() => batchResults.value?.results?.filter(r => r.success && r.result?.is_vulnerable).length || 0)
const safeCount = computed(() => batchResults.value?.results?.filter(r => r.success && !r.result?.is_vulnerable).length || 0)

const batchResultTable = computed(() => {
  if (!batchResults.value?.results) return []
  return batchResults.value.results.map(r => {
    if (r.success && r.result) {
      return {
        index: r.index + 1,
        status: '成功',
        statusType: 'success',
        method: r.result.method,
        path: r.result.path,
        vulnCount: r.result.vulnerabilities?.length || 0,
        riskLevel: r.result.risk_level,
      }
    }
    return {
      index: r.index + 1,
      status: '失败',
      statusType: 'danger',
      method: '-',
      path: r.error || '检测失败',
      vulnCount: '-',
      riskLevel: '',
    }
  })
})

function handleFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    const text = e.target.result
    const requests = text.split(/\n\s*\n/).map(s => s.trim()).filter(s => s.length > 10)
    if (requests.length === 0) {
      ElMessage.warning('文件中未找到有效的 HTTP 请求')
      return
    }
    if (requests.length > 50) {
      ElMessage.warning(`文件包含 ${requests.length} 条请求，仅取前50条`)
      batchRequests.value = requests.slice(0, 50)
    } else {
      batchRequests.value = requests
      ElMessage.success(`已解析 ${requests.length} 条请求`)
    }
  }
  reader.readAsText(file.raw)
}

async function handleBatchDetect() {
  if (batchRequests.value.length === 0) {
    ElMessage.warning('请先上传文件')
    return
  }
  loading.value = true
  batchResults.value = null
  try {
    const res = await batchDetect(batchRequests.value)
    batchResults.value = res
    ElMessage.success(`批量检测完成: ${res.total} 条`)
    emit('detected')
  } catch (err) {
    ElMessage.error('批量检测失败: ' + (err.message || '服务异常'))
  } finally {
    loading.value = false
  }
}

function clearBatch() {
  batchRequests.value = []
  batchResults.value = null
  uploadRef.value?.clearFiles()
}

function riskTagType(level) {
  const map = { high: 'danger', medium: 'warning', low: 'primary', info: 'info' }
  return map[level] || 'info'
}

function riskLabel(level) {
  const map = { high: '高风险', medium: '中风险', low: '低风险', info: '安全' }
  return map[level] || level
}
</script>

<style scoped>
.batch-input { width: 100%; }
.batch-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.batch-header .label { font-weight: 500; font-size: 15px; color: #303133; }
.batch-info {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 12px;
}
.format-hint {
  margin-top: 10px;
  padding: 8px 12px;
  background: #f5f7fa;
  border-radius: 4px;
  font-size: 12px;
  color: #909399;
}
.format-hint .hint-title { font-weight: 500; color: #606266; }
.format-hint p { margin: 4px 0 0 0; }
.batch-summary { margin-top: 12px; }
.summary-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}
.batch-table { margin-top: 8px; }
</style>

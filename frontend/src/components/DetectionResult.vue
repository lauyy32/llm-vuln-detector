<template>
  <div class="detection-result">
    <!-- 加载中 -->
    <div v-if="loading" class="loading-wrap">
      <div class="scan-container">
        <div class="scan-line"></div>
        <div class="scan-text">正在分析请求...</div>
      </div>
      <el-skeleton :rows="4" animated style="margin-top: 20px" />
    </div>

    <!-- 未检测 -->
    <el-empty
      v-else-if="!result"
      description="暂无检测结果，请输入 HTTP 请求后点击检测"
    />

    <div v-else>
      <!-- 汇总栏 -->
      <div class="result-summary">
        <el-tag
          :type="riskTagType(result.risk_level)"
          effect="dark"
          size="large"
        >
          {{ riskLabel(result.risk_level) }}
        </el-tag>
        <span class="summary-text">
          共检测到
          <b :class="result.is_vulnerable ? 'count-danger' : 'count-safe'">
            {{ result.vulnerabilities.length }}
          </b>
          个潜在漏洞
        </span>
        <span class="target-info" v-if="result.method">
          {{ result.method }} {{ result.path }}
        </span>
      </div>
      <el-divider />

      <!-- 无漏洞 -->
      <el-result
        v-if="result.vulnerabilities.length === 0"
        icon="success"
        title="未发现明显漏洞"
        :sub-title="result.summary || '该请求看起来是安全的'"
      />

      <!-- 漏洞列表 -->
      <el-card
        v-for="(vuln, idx) in result.vulnerabilities"
        :key="idx"
        shadow="hover"
        class="vuln-card"
        :style="{ animationDelay: (idx * 0.12) + 's' }"
      >
        <template #header>
          <div class="vuln-header">
            <el-tag :type="severityTagType(vuln.severity)" effect="dark" size="small">
              {{ severityLabel(vuln.severity) }}
            </el-tag>
            <span class="vuln-type">{{ vuln.type }}</span>
            <span class="vuln-confidence">置信度 {{ vuln.confidence }}%</span>
          </div>
        </template>

        <!-- 置信度进度条 -->
        <el-progress
          :percentage="vuln.confidence"
          :color="confidenceColor(vuln.confidence)"
          :stroke-width="10"
          :show-text="false"
          class="confidence-bar"
        />

        <el-descriptions :column="1" border class="vuln-desc">
          <el-descriptions-item label="漏洞位置">
            <el-tag size="small" type="info" effect="plain">{{ vuln.location }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="触发 Payload">
            <code class="payload-code">{{ vuln.payload }}</code>
          </el-descriptions-item>
          <el-descriptions-item label="成因分析">
            {{ vuln.description }}
          </el-descriptions-item>
          <el-descriptions-item label="修复建议">
            {{ vuln.remediation }}
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <!-- 分析摘要 -->
      <div class="analysis-summary" v-if="result.summary">
        <el-alert :title="result.summary" type="info" :closable="false" />
      </div>
    </div>
  </div>
</template>

<script setup>
const props = defineProps({
  result: { type: Object, default: null },
  loading: { type: Boolean, default: false }
})

// 严重等级 -> Tag 类型
function severityTagType(severity) {
  const map = { high: 'danger', medium: 'warning', low: 'primary', info: 'info' }
  return map[String(severity).toLowerCase()] || 'info'
}

// 严重等级 -> 中文
function severityLabel(severity) {
  const map = { high: '高危', medium: '中危', low: '低危', info: '提示' }
  return map[String(severity).toLowerCase()] || severity
}

// 风险等级 -> Tag 类型
function riskTagType(level) {
  const map = { high: 'danger', medium: 'warning', low: 'primary', info: 'info' }
  return map[String(level).toLowerCase()] || 'info'
}

// 风险等级 -> 中文
function riskLabel(level) {
  const map = { high: '高风险', medium: '中风险', low: '低风险', info: '安全' }
  return map[String(level).toLowerCase()] || level
}

// 置信度 -> 进度条颜色
function confidenceColor(val) {
  return [
    { color: '#409EFF', percentage: 50 },
    { color: '#E6A23C', percentage: 80 },
    { color: '#F56C6C', percentage: 100 }
  ]
}
</script>

<style scoped>
.detection-result { min-height: 200px; }
.result-summary {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  animation: fade-down 0.3s ease-out;
}
@keyframes fade-down {
  from { opacity: 0; transform: translateY(-8px); }
  to { opacity: 1; transform: translateY(0); }
}
.summary-text { color: #606266; font-size: 14px; }
.count-danger { color: #f56c6c; font-size: 18px; }
.count-safe { color: #67c23a; font-size: 18px; }
.target-info {
  color: #909399;
  font-size: 13px;
  font-family: 'Consolas', monospace;
  margin-left: auto;
}
.vuln-card {
  margin-bottom: 16px;
  animation: vuln-slide-in 0.4s ease-out backwards;
}
@keyframes vuln-slide-in {
  from { opacity: 0; transform: translateX(-16px); }
  to { opacity: 1; transform: translateX(0); }
}
.vuln-header {
  display: flex;
  align-items: center;
  gap: 10px;
}
.vuln-type {
  flex: 1;
  font-weight: 500;
  font-size: 15px;
  color: #303133;
}
.vuln-confidence { color: #909399; font-size: 13px; }
.confidence-bar { margin-bottom: 12px; }
.vuln-desc { margin-top: 8px; }
.payload-code {
  background: #f5f7fa;
  padding: 2px 6px;
  border-radius: 3px;
  font-family: 'Consolas', monospace;
  font-size: 13px;
  color: #e63946;
}
.analysis-summary { margin-top: 16px; }
.loading-wrap { padding: 10px 0; }
.scan-container {
  position: relative;
  height: 60px;
  border: 1px solid #e4e7ed;
  border-radius: 6px;
  background: #fafafa;
  overflow: hidden;
}
.scan-line {
  position: absolute;
  top: 0;
  left: -30%;
  width: 30%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(64, 158, 255, 0.15), rgba(64, 158, 255, 0.3), rgba(64, 158, 255, 0.15), transparent);
  animation: scan 1.5s ease-in-out infinite;
}
@keyframes scan {
  0% { left: -30%; }
  100% { left: 100%; }
}
.scan-text {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  color: #409eff;
  font-size: 14px;
  font-weight: 500;
}
</style>

// 检测 / 历史记录的编排逻辑 composable
// 将 App.vue 中的状态与检测方法抽离，避免单文件承载过多职责。
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { detectVulnerability, getHistory } from '../api/detect'

const SAMPLE = `POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

username=admin' OR '1'='1--&password=123456`

export function useDetection() {
  const requestText = ref('')
  const result = ref(null)
  const loading = ref(false)
  const history = ref([])

  async function fetchHistory() {
    try {
      const res = await getHistory(1, 50)
      history.value = (res.items || []).map((item) => ({
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
        result: res,
      })
      if (res.is_vulnerable) {
        ElMessage.warning(`检测到 ${res.vulnerabilities.length} 个潜在漏洞`)
      } else {
        ElMessage.success('未检测到明显漏洞')
      }
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

  return {
    SAMPLE,
    requestText,
    result,
    loading,
    history,
    fetchHistory,
    handleDetect,
    handleClear,
    loadSample,
  }
}

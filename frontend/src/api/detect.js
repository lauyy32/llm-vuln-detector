import request from '../utils/request'

/**
 * 提交 HTTP 请求文本进行漏洞检测
 */
export function detectVulnerability(rawRequest) {
  return request({
    url: '/api/detect',
    method: 'post',
    data: { raw_request: rawRequest }
  })
}

/**
 * 批量检测
 */
export function batchDetect(rawRequests) {
  return request({
    url: '/api/batch-detect',
    method: 'post',
    data: { requests: rawRequests },
    timeout: 300000
  })
}

/** 获取历史记录列表 */
export function getHistory(page = 1, pageSize = 20) {
  return request({
    url: '/api/history',
    method: 'get',
    params: { page, page_size: pageSize }
  })
}

/** 获取历史记录详情 */
export function getHistoryDetail(recordId) {
  return request({
    url: `/api/history/${recordId}`,
    method: 'get'
  })
}

/** 获取统计信息 */
export function getStats() {
  return request({
    url: '/api/stats',
    method: 'get'
  })
}

/** 清空所有历史记录 */
export function clearHistory() {
  return request({
    url: '/api/history',
    method: 'delete'
  })
}

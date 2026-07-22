import axios from 'axios'
import { ElMessage } from 'element-plus'

const request = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || '',
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' }
})

request.interceptors.response.use(
  (res) => res.data,
  (err) => {
    const msg = err.response?.data?.detail || err.message || '网络异常'
    ElMessage.error(msg)
    return Promise.reject(err)
  }
)

export default request

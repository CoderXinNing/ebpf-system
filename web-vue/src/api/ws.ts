type WSMessageHandler = (data: any) => void

let ws: WebSocket | null = null
const handlers: Map<string, WSMessageHandler[]> = new Map()

export function connectWS() {
  if (ws && ws.readyState === WebSocket.OPEN) return

  const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://'
  const url = `${protocol}${window.location.host}/ws`
  // 通过 vite proxy 代理到 Server 8080
  // vite.config.ts 已配置 proxy: '/ws' → 'ws://127.0.0.1:8080' 

  ws = new WebSocket(url)

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      const typeHandlers = handlers.get(msg.type)
      if (typeHandlers) {
        typeHandlers.forEach(fn => fn(msg.data))
      }
    } catch (err) {
      console.error('WS 消息解析失败:', err)
    }
  }

  ws.onclose = () => {
    ws = null
    // 5 秒后重连
    setTimeout(connectWS, 5000)
  }

  ws.onerror = (err) => {
    console.error('WS 错误:', err)
  }
}

export function onWSMessage(type: string, handler: WSMessageHandler) {
  if (!handlers.has(type)) {
    handlers.set(type, [])
  }
  handlers.get(type)!.push(handler)
}

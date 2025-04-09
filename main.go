package main

import (
	"log"
	"tls-proxy/proxy"
)

func main() {
	log.Println("[INFO] 启动 JA3 代理服务，监听 443 转发到 8443")
	err := proxy.StartProxy(":443", "127.0.0.1:8443")
	if err != nil {
		log.Fatalf("[FATAL] 启动失败: %v", err)
	}
}

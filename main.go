package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"tls-proxy/config"
	"tls-proxy/proxy"
)

func main() {
	redisAddr := flag.String("redis_addr", "127.0.0.1:6379", "Redis 地址")
	redisPassword := flag.String("redis_pass", "", "Redis 密码")
	listenPort := flag.Int("listen", 443, "本地监听端口")
	targetAddr := flag.String("target", "127.0.0.1:8443", "转发目标地址")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			`使用方法: ./tls-proxy [参数]
可用参数:
`)
		flag.PrintDefaults()
	}

	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	log.Printf("[INFO] 启动配置模块, Redis 地址: %s", *redisAddr)
	config.Init(*redisAddr, *redisPassword)

	log.Printf("[INFO] 启动 JA3 代理服务，监听 %d 转发到 %s", *listenPort, *targetAddr)
	err := proxy.StartProxy(fmt.Sprintf(":%d", *listenPort), *targetAddr)
	if err != nil {
		log.Fatalf("[FATAL] 启动失败: %v", err)
	}
}

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"tls-proxy/config"
	"tls-proxy/proxy"
)

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func main() {
	redisAddr := flag.String("redisaddr", "127.0.0.1:6379", "Redis 地址")
	redisPassword := flag.String("redispass", "", "Redis 密码")
	redisDbNum := flag.Int("redisdb", 0, "Redis Select DB")
	listenPort := flag.Int("listen", 443, "本地监听端口")
	targetAddr := flag.String("target", "127.0.0.1:8443", "转发目标地址")
	logLevel := flag.String("loglevel", "info", "日志级别（debug, info, warn, error）")

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

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(*logLevel),
	}))
	// 替换默认的全局 Logger
	slog.SetDefault(logger)

	slog.Info("启动配置模块", "RedisAddr", *redisAddr)
	config.Init(*redisAddr, *redisPassword, *redisDbNum)

	slog.Info("启动 JA3 代理服务", "listenPort", *listenPort, "targetAddr", *targetAddr)
	err := proxy.StartProxy(fmt.Sprintf(":%d", *listenPort), *targetAddr)
	if err != nil {
		slog.Error("启动失败", "err", err)
	}
}

// 文件路径: proxy/handler.go
package proxy

import (
	"io"
	"log"
	"net"
	"time"
	"tls-proxy/config"
	"tls-proxy/fingerprint"
	"tls-proxy/util"
)

// StartProxy 监听 listenAddr，转发到 forwardAddr，并进行 JA3/JA3S 指纹检查（根据开关控制）
func StartProxy(listenAddr, forwardAddr string) error {
	fingerprint.VerboseLogs = true
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Printf("[INFO] 监听 %s，转发到 %s", listenAddr, forwardAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[WARN] 接收连接失败: %v", err)
			continue
		}
		go handle(conn, forwardAddr)
	}
}

func handle(clientConn net.Conn, forwardAddr string) {
	defer clientConn.Close()

	// 读取客户端初始数据（预读 8KB 数据，用于解析 ClientHello）
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	clientBuf := make([]byte, 8192)
	n, err := clientConn.Read(clientBuf)
	if err != nil {
		log.Printf("[ERROR] 读取客户端握手数据失败: %v", err)
		return
	}
	clientData := clientBuf[:n]

	// 如果开启 JA3+ 检查，则提取并判断 JA3+ 指纹
	EnableJA3Check := config.EnableJA3Check()
	EnableJA3Collection := config.EnableJA3Collection()
	EnableJA3NCheck := config.EnableJA3NCheck()
	EnableJA3NCollection := config.EnableJA3NCollection()
	if EnableJA3Check || EnableJA3Collection || EnableJA3NCheck || EnableJA3NCollection {
		if util.IsTLSClientHello(clientData) {
			ja3Str, ja3nStr, err := fingerprint.JA3Fingerprint(&clientData)
			if err != nil {
				log.Printf("[WARN] 提取 JA3+ 失败: %v", err)
			} else {
				log.Printf("[INFO] 客户端 JA3: %s, JA3n: %s", ja3Str, ja3nStr)
				if EnableJA3Collection {
					config.ReportJA3(ja3Str)
				}
				if EnableJA3Check && config.ShouldBlockJA3(ja3Str) {
					log.Printf("[BLOCK] 客户端 JA3 阻断匹配，断开连接: %s", ja3Str)
					return
				}
				if EnableJA3NCollection {
					config.ReportJA3N(ja3nStr)
				}
				if EnableJA3NCheck && config.ShouldBlockJA3N(ja3nStr) {
					log.Printf("[BLOCK] 客户端 JA3N 阻断匹配，断开连接: %s", ja3nStr)
					return
				}
			}
		} else {
			log.Printf("[DEBUG] 客户端数据非 TLS ClientHello，不执行 JA3 检查")
		}
	} else {
		log.Printf("[INFO] 客户端 JA3+ 检查已关闭，跳过")
	}

	// 如果开启 JA4 检查，则提取并判断 JA4 指纹
	EnableJA4Check := config.EnableJA4Check()
	EnableJA4Collection := config.EnableJA4Collection()
	if EnableJA4Check || EnableJA4Collection {
		if util.IsTLSClientHello(clientData) {
			ja4Str, err := fingerprint.JA4Fingerprint(&clientData)
			if err != nil {
				log.Printf("[WARN] 提取 JA4 失败: %v", err)
			} else {
				log.Printf("[INFO] 客户端 JA4: %s", ja4Str)
				if EnableJA4Collection {
					config.ReportJA4(ja4Str)
				}
				if EnableJA4Check && config.ShouldBlockJA4(ja4Str) {
					log.Printf("[BLOCK] 客户端 JA4 阻断匹配，断开连接: %s", ja4Str)
					return
				}
			}
		} else {
			log.Printf("[DEBUG] 客户端数据非 TLS ClientHello，不执行 JA4 检查")
		}
	} else {
		log.Printf("[INFO] 客户端 JA3+ 检查已关闭，跳过")
	}

	// 与目标服务器建立连接
	targetConn, err := net.Dial("tcp", forwardAddr)
	if err != nil {
		log.Printf("[ERROR] 连接目标服务器失败: %v", err)
		return
	}
	defer targetConn.Close()

	// 将客户端已读取的数据立即发送给目标服务器
	_, err = targetConn.Write(clientData)
	if err != nil {
		log.Printf("[ERROR] 向目标服务器转发数据失败: %v", err)
		return
	}

	// 清除所有超时设置
	targetConn.SetReadDeadline(time.Time{})
	clientConn.SetReadDeadline(time.Time{})

	// 启动双向数据转发
	go io.Copy(targetConn, clientConn)
	// 使用 targetReader 以确保 Peek 后的数据不会丢失（若已使用）
	io.Copy(clientConn, targetConn)
}

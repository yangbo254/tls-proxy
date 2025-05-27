// 文件路径: proxy/handler.go
package proxy

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
	"tls-proxy/config"
	"tls-proxy/fingerprint"
	"tls-proxy/util"

	"github.com/panjf2000/gnet/v2"
)

type proxyServer struct {
	gnet.BuiltinEventEngine
	forwardAddr string
}

type connContext struct {
	handshakeDone bool
	clientBuffer  []byte
	targetConn    net.Conn
}

func (ps *proxyServer) OnOpened(c gnet.Conn) (out []byte, action gnet.Action) {
	c.SetContext(&connContext{})
	return
}

func (ps *proxyServer) OnClosed(c gnet.Conn, err error) (action gnet.Action) {
	ctx := c.Context().(*connContext)
	if ctx.targetConn != nil {
		ctx.targetConn.Close()
	}
	return
}

func (ps *proxyServer) OnTraffic(c gnet.Conn) (action gnet.Action) {
	ctx := c.Context().(*connContext)
	data, _ := c.Next(-1)

	if !ctx.handshakeDone {
		ctx.clientBuffer = append(ctx.clientBuffer, data...)
		if len(ctx.clientBuffer) < 5 {
			return
		}
		clientData := ctx.clientBuffer
		clientIP := strings.Split(c.RemoteAddr().String(), ":")[0]

		if util.IsTLSClientHello(clientData) {
			if config.EnableJA3Check() || config.EnableJA3Collection() || config.EnableJA3NCheck() || config.EnableJA3NCollection() {
				ja3Str, ja3nStr, err := fingerprint.JA3Fingerprint(&clientData)
				if err == nil {
					if config.EnableJA3Collection() {
						go config.ReportJA3(ja3Str)
					}
					if config.EnableJA3Check() && config.ShouldBlockJA3(ja3Str) {
						go config.ReportJA3BlockedEvent(ja3Str)
						slog.Info("[BLOCK] JA3", "ja3", ja3Str, "ip", clientIP)
						return gnet.Close
					}
					if config.EnableJA3NCollection() {
						go config.ReportJA3N(ja3nStr)
					}
					if config.EnableJA3NCheck() && config.ShouldBlockJA3N(ja3nStr) {
						go config.ReportJA3NBlockedEvent(ja3nStr)
						slog.Info("[BLOCK] JA3N", "ja3n", ja3nStr, "ip", clientIP)
						return gnet.Close
					}
				}
			}

			if config.EnableJA4Check() || config.EnableJA4Collection() {
				ja4Str, err := fingerprint.JA4Fingerprint(&clientData)
				if err == nil {
					if config.EnableJA4Collection() {
						go config.ReportJA4(ja4Str)
					}
					if config.EnableJA4Check() && config.ShouldBlockJA4(ja4Str) {
						go config.ReportJA4BlockedEvent(ja4Str)
						slog.Info("[BLOCK] JA4", "ja4", ja4Str, "ip", clientIP)
						return gnet.Close
					}
				}
			}
		}

		targetConn, err := net.DialTimeout("tcp", ps.forwardAddr, 2*time.Second)
		if err != nil {
			slog.Error("连接目标失败", "err", err)
			return gnet.Close
		}
		ctx.targetConn = targetConn
		ctx.handshakeDone = true

		go func() {
			defer c.Close()
			targetConn.Write(clientData)
			io.Copy(c, targetConn)
		}()

		return
	}

	if ctx.targetConn != nil {
		ctx.targetConn.Write(data)
	}
	return
}

func StartProxy(listenAddr, forwardAddr string) error {
	ps := &proxyServer{forwardAddr: forwardAddr}
	return gnet.Run(ps, "tcp://"+listenAddr, gnet.WithMulticore(true), gnet.WithReusePort(true))
}

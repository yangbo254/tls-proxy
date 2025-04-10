// Package `fingerprint` reads `metadata` and calculate the JA3, JA4,
// HTTP2 fingerprints, etc.
//
// It also implements `header_injector` interface from package `reverseproxy`,
// which allows passing fingerprints to the backend through the forwarding
// request headers.
package fingerprint

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"

	"tls-proxy/ja3"
	"tls-proxy/ja4"

	"github.com/dreadl0ck/tlsx"
)

var (
	VerboseLogs bool
	Logger      *log.Logger
)

func vlogf(format string, args ...any) {
	if VerboseLogs {
		if Logger != nil {
			Logger.Printf(format, args...)
		} else {
			log.Printf(format, args...)
		}
	}
}

// JA4Fingerprint is a FingerprintFunc
func JA4Fingerprint(data *[]byte) (string, error) {
	fp := &ja4.JA4Fingerprint{}
	err := fp.UnmarshalBytes(*data, 't') // TODO: identify connection protocol
	if err != nil {
		return "", fmt.Errorf("ja4: %w", err)
	}

	vlogf("ja4: %s", fp)
	return fp.String(), nil
}

// JA3Fingerprint is a FingerprintFunc
func JA3Fingerprint(data *[]byte) (string, string, error) {
	hellobasic := &tlsx.ClientHelloBasic{}
	if err := hellobasic.Unmarshal(*data); err != nil {
		return "", "", fmt.Errorf("ja3: %w", err)
	}

	j := ja3.OrigString(hellobasic)
	// JA3 字符串格式：TLSVersion,CipherSuites,Extensions,SupportedGroups,ECPointFormats
	parts := strings.Split(j, ",")
	if len(parts) != 5 {
		return "", "", fmt.Errorf("JA3 字符串格式错误")
	}
	// 对 Extensions 部分进行排序（如果非空）
	extField := parts[2]
	extTokens := strings.Split(extField, "-")
	// 判断是否存在有效扩展数据，防止空字符串排序异常
	if len(extTokens) > 0 && extTokens[0] != "" {
		sort.Strings(extTokens)
	}
	sortedExt := strings.Join(extTokens, "-")
	parts[2] = sortedExt

	// 重构 JA3N 字符串
	ja3nStr := strings.Join(parts, ",")
	// 对新字符串计算 MD5
	sum := md5.Sum([]byte(ja3nStr))
	ja3sHash := hex.EncodeToString(sum[:])

	fp := ja3.DigestHex(hellobasic)

	vlogf("ja3: %s ja3Hash: %s ja3s: %s ja3sHash: %s", j, fp, ja3nStr, ja3sHash)
	return fp, ja3sHash, nil
}

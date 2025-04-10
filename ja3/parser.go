package ja3

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	pkgJa3 "github.com/open-ch/ja3"
)

// IsTLSClientHello 判断数据是否为 TLS ClientHello 消息（仅简单判断记录头）。
func IsTLSClientHello(data []byte) bool {
	return len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03
}

// IsTLSServerHello 判断数据是否为 TLS ServerHello 消息（仅简单判断记录头）。
func IsTLSServerHello(data []byte) bool {
	return len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03
}

// ExtractJA3 从 TLS ClientHello 消息中提取 JA3 指纹字符串。
// 格式：TLSVersion,CipherSuites,Extensions,SupportedGroups,ECPointFormats
func ExtractJA3(data []byte) (string, error) {
	// 检查 TLS 记录头
	if len(data) < 5 {
		return "", errors.New("数据不足，无法解析 TLS 记录头")
	}
	if data[0] != 0x16 {
		return "", errors.New("非 TLS 握手记录")
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return "", errors.New("TLS 记录数据不完整")
	}
	// 提取握手数据（跳过记录头 5 字节）
	hsData := data[5 : 5+recordLen]
	if len(hsData) < 4 {
		return "", errors.New("握手头数据不足")
	}
	// 检查握手消息类型是否为 ClientHello（1）
	if hsData[0] != 0x01 {
		return "", errors.New("非 ClientHello 消息")
	}
	hsLen := int(hsData[1])<<16 | int(hsData[2])<<8 | int(hsData[3])
	if len(hsData)-4 < hsLen {
		return "", errors.New("ClientHello 消息长度不匹配")
	}
	clientHello := hsData[4 : 4+hsLen]

	// 开始解析 ClientHello 字段
	if len(clientHello) < 2 {
		return "", errors.New("ClientHello 中无 TLS 版本")
	}
	tlsVersion := int(binary.BigEndian.Uint16(clientHello[0:2]))
	offset := 2

	// 跳过 32 字节随机数
	if len(clientHello) < offset+32 {
		return "", errors.New("ClientHello 中随机数不足")
	}
	offset += 32

	// SessionID
	if len(clientHello) < offset+1 {
		return "", errors.New("缺少 SessionID 长度字段")
	}
	sessionIDLen := int(clientHello[offset])
	offset++
	if len(clientHello) < offset+sessionIDLen {
		return "", errors.New("SessionID 数据不完整")
	}
	offset += sessionIDLen

	// CipherSuites
	if len(clientHello) < offset+2 {
		return "", errors.New("缺少 CipherSuites 长度字段")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2
	if len(clientHello) < offset+cipherSuitesLen {
		return "", errors.New("CipherSuites 数据不完整")
	}
	var cipherSuites []string
	for i := 0; i < cipherSuitesLen; i += 2 {
		if offset+i+2 > len(clientHello) {
			break
		}
		cs := binary.BigEndian.Uint16(clientHello[offset+i : offset+i+2])
		cipherSuites = append(cipherSuites, fmt.Sprintf("%d", cs))
	}
	offset += cipherSuitesLen

	// Compression Methods
	if len(clientHello) < offset+1 {
		return "", errors.New("缺少 Compression Methods 长度字段")
	}
	compMethodsLen := int(clientHello[offset])
	offset++
	if len(clientHello) < offset+compMethodsLen {
		return "", errors.New("Compression Methods 数据不完整")
	}
	offset += compMethodsLen

	// Extensions（可选）
	var extensions []string
	var supportedGroups []string
	var ecPointFormats []string
	if len(clientHello) >= offset+2 {
		extTotalLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
		offset += 2
		endExt := offset + extTotalLen
		if endExt > len(clientHello) {
			return "", errors.New("Extensions 长度错误")
		}
		for offset+4 <= endExt { // 每个扩展至少 4 字节：2 字节类型 + 2 字节长度
			extType := binary.BigEndian.Uint16(clientHello[offset : offset+2])
			extLen := int(binary.BigEndian.Uint16(clientHello[offset+2 : offset+4]))
			extensions = append(extensions, fmt.Sprintf("%d", extType))
			offset += 4
			if offset+extLen > endExt {
				break
			}
			// 解析 supported groups（扩展类型 10）
			if extType == 10 && extLen >= 2 {
				// 第2个扩展的前2字节表示列表的总长度
				if offset+2 > endExt {
					return "", errors.New("Supported Groups 数据不完整")
				}
				groupListLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
				innerOffset := offset + 2
				groupListEnd := offset + 2 + groupListLen
				if groupListEnd > offset+extLen || groupListEnd > endExt {
					return "", errors.New("Supported Groups 列表长度错误")
				}
				for innerOffset+2 <= groupListEnd {
					group := binary.BigEndian.Uint16(clientHello[innerOffset : innerOffset+2])
					supportedGroups = append(supportedGroups, fmt.Sprintf("%d", group))
					innerOffset += 2
				}
			}
			// 解析 ec point formats（扩展类型 11）
			if extType == 11 && extLen >= 1 {
				if offset+1 > endExt {
					return "", errors.New("EC Point Formats 数据不完整")
				}
				pfLen := int(clientHello[offset])
				innerOffset := offset + 1
				for innerOffset < offset+extLen && innerOffset < endExt && (innerOffset-offset-1) < pfLen {
					pf := clientHello[innerOffset]
					ecPointFormats = append(ecPointFormats, fmt.Sprintf("%d", pf))
					innerOffset++
				}
			}
			offset += extLen
		}
	}
	if len(cipherSuites) == 0 {
		cipherSuites = append(cipherSuites, "0")
	}
	if len(supportedGroups) == 0 {
		supportedGroups = append(supportedGroups, "0")
	}
	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s",
		tlsVersion,
		strings.Join(cipherSuites[1:], "-"),
		strings.Join(extensions, "-"),
		strings.Join(supportedGroups[1:], "-"),
		strings.Join(ecPointFormats, "-"))
	return ja3, nil
}

// ExtractJA3S 从 TLS ServerHello 消息中提取 JA3S 指纹字符串。
// 格式：TLSVersion,CipherSuite,Extensions
func ExtractJA3S(data []byte) (string, error) {
	// 检查 TLS 记录头
	if len(data) < 5 {
		return "", errors.New("数据不足，无法解析 TLS 记录头")
	}
	if data[0] != 0x16 {
		return "", errors.New("非 TLS 握手记录")
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return "", errors.New("TLS 记录数据不完整")
	}
	// 提取握手数据
	hsData := data[5 : 5+recordLen]
	if len(hsData) < 4 {
		return "", errors.New("握手头数据不足")
	}
	// 检查 ServerHello 消息（类型为 0x02）
	if hsData[0] != 0x02 {
		return "", errors.New("非 ServerHello 消息")
	}
	hsLen := int(hsData[1])<<16 | int(hsData[2])<<8 | int(hsData[3])
	if len(hsData)-4 < hsLen {
		return "", errors.New("ServerHello 消息长度不匹配")
	}
	serverHello := hsData[4 : 4+hsLen]

	// 解析 ServerHello：TLS 版本
	if len(serverHello) < 2 {
		return "", errors.New("ServerHello 中无 TLS 版本")
	}
	tlsVersion := int(binary.BigEndian.Uint16(serverHello[0:2]))
	offset := 2

	// 跳过 32 字节随机数
	if len(serverHello) < offset+32 {
		return "", errors.New("ServerHello 中随机数不足")
	}
	offset += 32

	// SessionID
	if len(serverHello) < offset+1 {
		return "", errors.New("缺少 SessionID 长度字段")
	}
	sessionIDLen := int(serverHello[offset])
	offset++
	if len(serverHello) < offset+sessionIDLen {
		return "", errors.New("ServerHello SessionID 数据不完整")
	}
	offset += sessionIDLen

	// CipherSuite：2 字节
	if len(serverHello) < offset+2 {
		return "", errors.New("缺少 CipherSuite 字段")
	}
	cipherSuite := binary.BigEndian.Uint16(serverHello[offset : offset+2])
	offset += 2

	// Compression method（1 字节），跳过
	if len(serverHello) < offset+1 {
		return "", errors.New("缺少 Compression Method 字段")
	}
	offset++

	// Extensions（可选）
	var extensions []string
	if len(serverHello) >= offset+2 {
		extTotalLen := int(binary.BigEndian.Uint16(serverHello[offset : offset+2]))
		offset += 2
		endExt := offset + extTotalLen
		if endExt > len(serverHello) {
			return "", errors.New("ServerHello Extensions 数据不完整")
		}
		for offset+4 <= endExt { // 每个扩展至少 4 字节
			extType := binary.BigEndian.Uint16(serverHello[offset : offset+2])
			extensions = append(extensions, fmt.Sprintf("%d", extType))
			extLen := int(binary.BigEndian.Uint16(serverHello[offset+2 : offset+4]))
			offset += 4
			if offset+extLen > endExt {
				break
			}
			offset += extLen
		}
	}
	ja3s := fmt.Sprintf("%d,%d,%s",
		tlsVersion,
		cipherSuite,
		strings.Join(extensions, "-"))
	return ja3s, nil
}

// ExtractJA3N 计算 JA3N 指纹，与 JA3 的区别在于对 Extensions 部分进行排序，以确保指纹的一致性
func ExtractJA3N(data []byte) (string, string, error) {
	// 首先提取原始的 JA3 字符串
	// ja3Str, err := ExtractJA3(data)
	// if err != nil {
	// 	return "", "", err
	// }
	j, err := pkgJa3.ComputeJA3FromSegment(data)
	if err != nil {
		// If the packet is no Client Hello an error is thrown as soon as the parsing fails
		panic(err)
	}

	// Get the JA3 digest, string and SNI of the parsed Client Hello
	ja3Hash := j.GetJA3Hash()
	ja3String := j.GetJA3String()
	sni := j.GetSNI()
	fmt.Printf("JA3Hash: %v, JA3String: %v, SNI: %v\n", ja3Hash, ja3String, sni)
	//ja3Sum := md5.Sum([]byte(ja3Str))
	//ja3Hash := hex.EncodeToString(ja3Sum[:])
	// JA3 字符串格式：TLSVersion,CipherSuites,Extensions,SupportedGroups,ECPointFormats
	parts := strings.Split(ja3String, ",")
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
	return ja3String, hex.EncodeToString(sum[:]), nil
}

package util

// IsTLSClientHello 判断数据是否为 TLS ClientHello 消息（仅简单判断记录头）。
func IsTLSClientHello(data []byte) bool {
	return len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03
}

// IsTLSServerHello 判断数据是否为 TLS ServerHello 消息（仅简单判断记录头）。
func IsTLSServerHello(data []byte) bool {
	return len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03
}

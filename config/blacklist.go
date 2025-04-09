package config

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	blacklist   = make(map[string]struct{})
	blacklistMu sync.RWMutex

	EnableJA3Check  = true // 是否启用 JA3 检查
	EnableJA3SCheck = true // 是否启用 JA3S 检查
)

func init() {
	LoadBlacklist("blacklist.txt")
}

func LoadBlacklist(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("[WARN] 无法加载黑名单: %v", err)
		return
	}
	defer file.Close()

	temp := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			temp[line] = struct{}{}
		}
	}

	blacklistMu.Lock()
	blacklist = temp
	blacklistMu.Unlock()
	log.Printf("[INFO] 黑名单加载完毕，数量: %d", len(blacklist))
}

func IsBlacklisted(ja3 string) bool {
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()
	_, exists := blacklist[ja3]
	return exists
}

func IsServerBlacklisted(ja3 string) bool {
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()
	_, exists := blacklist[ja3]
	return exists
}

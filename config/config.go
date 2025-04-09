package config

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb *redis.Client
	ctx = context.Background()
	mu  sync.RWMutex

	// JA3 配置
	enableJA3Check      bool
	enableJA3Whitelist  bool
	enableJA3Collection bool
	ja3Blacklist        = make(map[string]bool)
	ja3Whitelist        = make(map[string]bool)

	// JA3S 配置
	enableJA3SCheck      bool
	enableJA3SWhitelist  bool
	enableJA3SCollection bool
	ja3sBlacklist        = make(map[string]bool)
	ja3sWhitelist        = make(map[string]bool)

	// JA3N 配置
	enableJA3NCheck      bool
	enableJA3NWhitelist  bool
	enableJA3NCollection bool
	ja3nBlacklist        = make(map[string]bool)
	ja3nWhitelist        = make(map[string]bool)

	// JA4 配置
	enableJA4Check      bool
	enableJA4Whitelist  bool
	enableJA4Collection bool
	ja4Blacklist        = make(map[string]bool)
	ja4Whitelist        = make(map[string]bool)
)

func Init(redisAddr string) {
	rdb = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	go refreshConfigLoop()
}

func refreshConfigLoop() {
	for {
		refreshFlags()
		refreshLists()
		time.Sleep(10 * time.Second)
	}
}

func refreshFlags() {
	enableJA3Check = getBool("config:ja3_check_enabled")
	enableJA3Whitelist = getBool("config:ja3_whitelist_enabled")
	enableJA3Collection = getBool("config:ja3_collection_enabled")

	enableJA3SCheck = getBool("config:ja3s_check_enabled")
	enableJA3SWhitelist = getBool("config:ja3s_whitelist_enabled")
	enableJA3SCollection = getBool("config:ja3s_collection_enabled")

	enableJA3NCheck = getBool("config:ja3n_check_enabled")
	enableJA3NWhitelist = getBool("config:ja3n_whitelist_enabled")
	enableJA3NCollection = getBool("config:ja3n_collection_enabled")

	enableJA4Check = getBool("config:ja4_check_enabled")
	enableJA4Whitelist = getBool("config:ja4_whitelist_enabled")
	enableJA4Collection = getBool("config:ja4_collection_enabled")
}

func getBool(key string) bool {
	val, _ := rdb.Get(ctx, key).Result()
	return val == "true"
}

func refreshLists() {
	ja3Blacklist = loadSet("ja3:blacklist")
	ja3Whitelist = loadSet("ja3:whitelist")

	ja3sBlacklist = loadSet("ja3s:blacklist")
	ja3sWhitelist = loadSet("ja3s:whitelist")

	ja3nBlacklist = loadSet("ja3n:blacklist")
	ja3nWhitelist = loadSet("ja3n:whitelist")

	ja4Blacklist = loadSet("ja4:blacklist")
	ja4Whitelist = loadSet("ja4:whitelist")
}

func loadSet(key string) map[string]bool {
	list, _ := rdb.SMembers(ctx, key).Result()
	m := make(map[string]bool, len(list))
	for _, v := range list {
		m[v] = true
	}
	return m
}

// 判断是否启用
func EnableJA3Check() bool  { mu.RLock(); defer mu.RUnlock(); return enableJA3Check }
func EnableJA3SCheck() bool { mu.RLock(); defer mu.RUnlock(); return enableJA3SCheck }
func EnableJA3NCheck() bool { mu.RLock(); defer mu.RUnlock(); return enableJA3NCheck }
func EnableJA4Check() bool  { mu.RLock(); defer mu.RUnlock(); return enableJA4Check }

func EnableJA3Collection() bool  { mu.RLock(); defer mu.RUnlock(); return enableJA3Collection }
func EnableJA3SCollection() bool { mu.RLock(); defer mu.RUnlock(); return enableJA3SCollection }
func EnableJA3NCollection() bool { mu.RLock(); defer mu.RUnlock(); return enableJA3NCollection }
func EnableJA4Collection() bool  { mu.RLock(); defer mu.RUnlock(); return enableJA4Collection }

// 拦截逻辑
func ShouldBlockJA3(ja3 string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if enableJA3Whitelist {
		return !ja3Whitelist[ja3]
	}
	return ja3Blacklist[ja3]
}

func ShouldBlockJA3S(ja3s string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if enableJA3SWhitelist {
		return !ja3sWhitelist[ja3s]
	}
	return ja3sBlacklist[ja3s]
}

func ShouldBlockJA3N(ja3n string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if enableJA3NWhitelist {
		return !ja3nWhitelist[ja3n]
	}
	return ja3nBlacklist[ja3n]
}

func ShouldBlockJA4(ja4 string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if enableJA4Whitelist {
		return !ja4Whitelist[ja4]
	}
	return ja4Blacklist[ja4]
}

// 上报逻辑
func ReportJA3(ja3 string) {
	if EnableJA3Collection() {
		rdb.Set(ctx, "ja3:report:"+ja3, time.Now().Format(time.RFC3339), time.Hour)
	}
}

func ReportJA3S(ja3s string) {
	if EnableJA3SCollection() {
		rdb.Set(ctx, "ja3s:report:"+ja3s, time.Now().Format(time.RFC3339), time.Hour)
	}
}

func ReportJA3N(ja3n string) {
	if EnableJA3NCollection() {
		rdb.Set(ctx, "ja3n:report:"+ja3n, time.Now().Format(time.RFC3339), time.Hour)
	}
}

func ReportJA4(ja4 string) {
	if EnableJA4Collection() {
		rdb.Set(ctx, "ja4:report:"+ja4, time.Now().Format(time.RFC3339), time.Hour)
	}
}

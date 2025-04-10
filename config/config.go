package config

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb = redis.NewClient(&redis.Options{})
	ctx = context.Background()
	mu  sync.RWMutex

	redisAvailable bool

	// JA3 配置
	enableJA3Check       = false
	enableJA3Blacklist   = false
	enableJA3Whitelist   = false
	enableJA3Collection  = false
	ja3Blacklist         = make(map[string]bool)
	ja3Whitelist         = make(map[string]bool)

	// JA3S 配置
	enableJA3SCheck      = false
	enableJA3SBlacklist  = false
	enableJA3SWhitelist  = false
	enableJA3SCollection = false
	ja3sBlacklist        = make(map[string]bool)
	ja3sWhitelist        = make(map[string]bool)

	// JA3N 配置
	enableJA3NCheck      = false
	enableJA3NBlacklist  = false
	enableJA3NWhitelist  = false
	enableJA3NCollection = false
	ja3nBlacklist        = make(map[string]bool)
	ja3nWhitelist        = make(map[string]bool)

	// JA4 配置
	enableJA4Check       = false
	enableJA4Blacklist   = false
	enableJA4Whitelist   = false
	enableJA4Collection  = false
	ja4Blacklist         = make(map[string]bool)
	ja4Whitelist         = make(map[string]bool)
)

func Init(redisAddr string) {
	rdb = redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DialTimeout: 3 * time.Second,
		ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	// 测试初始连接
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Printf("[WARN] Redis 初始连接失败，使用默认配置: %v", err)
		redisAvailable = false
	} else {
		redisAvailable = true
	}
	go refreshConfigLoop()
}

func refreshConfigLoop() {
	for {
		if redisAvailable {
			err := refreshFlags()
			err2 := refreshLists()
			if err != nil || err2 != nil {
				log.Printf("[WARN] Redis 刷新配置失败，保持当前状态")
				redisAvailable = false
			}
		} else {
			if _, err := rdb.Ping(ctx).Result(); err == nil {
				log.Printf("[INFO] Redis 连接恢复")
				redisAvailable = true
				refreshFlags()
				refreshLists()
			}
		}
		time.Sleep(10 * time.Second)
	}
}

func refreshFlags() error {
	mu.Lock()
	defer mu.Unlock()
	var err error
	enableJA3Check, err = getBool("config:ja3_check_enabled")
	enableJA3Blacklist, _ = getBool("config:ja3_blacklist_enabled")
	enableJA3Whitelist, _ = getBool("config:ja3_whitelist_enabled")
	enableJA3Collection, _ = getBool("config:ja3_collection_enabled")

	enableJA3SCheck, _ = getBool("config:ja3s_check_enabled")
	enableJA3SBlacklist, _ = getBool("config:ja3s_blacklist_enabled")
	enableJA3SWhitelist, _ = getBool("config:ja3s_whitelist_enabled")
	enableJA3SCollection, _ = getBool("config:ja3s_collection_enabled")

	enableJA3NCheck, _ = getBool("config:ja3n_check_enabled")
	enableJA3NBlacklist, _ = getBool("config:ja3n_blacklist_enabled")
	enableJA3NWhitelist, _ = getBool("config:ja3n_whitelist_enabled")
	enableJA3NCollection, _ = getBool("config:ja3n_collection_enabled")

	enableJA4Check, _ = getBool("config:ja4_check_enabled")
	enableJA4Blacklist, _ = getBool("config:ja4_blacklist_enabled")
	enableJA4Whitelist, _ = getBool("config:ja4_whitelist_enabled")
	enableJA4Collection, _ = getBool("config:ja4_collection_enabled")

	return err
}

func getBool(key string) (bool, error) {
	val, err := rdb.Get(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return val == "true", nil
}

func refreshLists() error {
	mu.Lock()
	defer mu.Unlock()
	var err error
	ja3Blacklist, err = loadSet("ja3:blacklist")
	ja3Whitelist, _ = loadSet("ja3:whitelist")
	ja3sBlacklist, _ = loadSet("ja3s:blacklist")
	ja3sWhitelist, _ = loadSet("ja3s:whitelist")
	ja3nBlacklist, _ = loadSet("ja3n:blacklist")
	ja3nWhitelist, _ = loadSet("ja3n:whitelist")
	ja4Blacklist, _ = loadSet("ja4:blacklist")
	ja4Whitelist, _ = loadSet("ja4:whitelist")
	return err
}

func loadSet(key string) (map[string]bool, error) {
	list, err := rdb.SMembers(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(list))
	for _, v := range list {
		m[v] = true
	}
	return m, nil
}

func ShouldBlockJA3(ja3 string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if !enableJA3Check {
		return false
	}
	if enableJA3Whitelist && ja3Whitelist[ja3] {
		return false
	}
	if enableJA3Blacklist && ja3Blacklist[ja3] {
		return true
	}
	return false
}

func ShouldBlockJA3S(ja3s string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if !enableJA3SCheck {
		return false
	}
	if enableJA3SWhitelist && ja3sWhitelist[ja3s] {
		return false
	}
	if enableJA3SBlacklist && ja3sBlacklist[ja3s] {
		return true
	}
	return false
}

func ShouldBlockJA3N(ja3n string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if !enableJA3NCheck {
		return false
	}
	if enableJA3NWhitelist && ja3nWhitelist[ja3n] {
		return false
	}
	if enableJA3NBlacklist && ja3nBlacklist[ja3n] {
		return true
	}
	return false
}

func ShouldBlockJA4(ja4 string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if !enableJA4Check {
		return false
	}
	if enableJA4Whitelist && ja4Whitelist[ja4] {
		return false
	}
	if enableJA4Blacklist && ja4Blacklist[ja4] {
		return true
	}
	return false
}

func ReportJA3(ja3 string) {
	if !redisAvailable {
		return
	}
	if enableJA3Collection {
		_ = rdb.SAdd(ctx, "ja3:collected", ja3).Err()
	}
}

func ReportJA3S(ja3s string) {
	if !redisAvailable {
		return
	}
	if enableJA3SCollection {
		_ = rdb.SAdd(ctx, "ja3s:collected", ja3s).Err()
	}
}

func ReportJA3N(ja3n string) {
	if !redisAvailable {
		return
	}
	if enableJA3NCollection {
		_ = rdb.SAdd(ctx, "ja3n:collected", ja3n).Err()
	}
}

func ReportJA4(ja4 string) {
	if !redisAvailable {
		return
	}
	if enableJA4Collection {
		_ = rdb.SAdd(ctx, "ja4:collected", ja4).Err()
	}
}

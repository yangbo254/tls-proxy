package config

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb            = redis.NewClient(&redis.Options{})
	ctx            = context.Background()
	mu             sync.RWMutex
	cleanupOnce    sync.Once
	redisAvailable bool

	// JA3 配置
	enableJA3Check      = false
	enableJA3Blacklist  = false
	enableJA3Whitelist  = false
	enableJA3Collection = false
	ja3Blacklist        = make(map[string]bool)
	ja3Whitelist        = make(map[string]bool)

	// JA3N 配置
	enableJA3NCheck      = false
	enableJA3NBlacklist  = false
	enableJA3NWhitelist  = false
	enableJA3NCollection = false
	ja3nBlacklist        = make(map[string]bool)
	ja3nWhitelist        = make(map[string]bool)

	// JA4 配置
	enableJA4Check      = false
	enableJA4Blacklist  = false
	enableJA4Whitelist  = false
	enableJA4Collection = false
	ja4Blacklist        = make(map[string]bool)
	ja4Whitelist        = make(map[string]bool)
)

func Init(redisAddr, redisPasswd string, dbNum int) {
	rdb = redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     redisPasswd,
		DB:           dbNum,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
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
			} else {
				// 启动清理任务（只启动一次）
				cleanupOnce.Do(func() {
					log.Printf("[INFO] 启动定时清理任务")
					scheduleCleanup()
				})
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
	enableJA3Check, err = getBool("config:ja3_check_enabled", enableJA3Check)
	enableJA3Blacklist, _ = getBool("config:ja3_blacklist_enabled", enableJA3Blacklist)
	enableJA3Whitelist, _ = getBool("config:ja3_whitelist_enabled", enableJA3Whitelist)
	enableJA3Collection, _ = getBool("config:ja3_collection_enabled", enableJA3Collection)

	enableJA3NCheck, _ = getBool("config:ja3n_check_enabled", enableJA3NCheck)
	enableJA3NBlacklist, _ = getBool("config:ja3n_blacklist_enabled", enableJA3NBlacklist)
	enableJA3NWhitelist, _ = getBool("config:ja3n_whitelist_enabled", enableJA3NWhitelist)
	enableJA3NCollection, _ = getBool("config:ja3n_collection_enabled", enableJA3NCollection)

	enableJA4Check, _ = getBool("config:ja4_check_enabled", enableJA4Check)
	enableJA4Blacklist, _ = getBool("config:ja4_blacklist_enabled", enableJA4Blacklist)
	enableJA4Whitelist, _ = getBool("config:ja4_whitelist_enabled", enableJA4Whitelist)
	enableJA4Collection, _ = getBool("config:ja4_collection_enabled", enableJA4Collection)

	return err
}

func getBool(key string, defaultVal bool) (bool, error) {
	val, err := rdb.Get(ctx, key).Result()
	if err != nil {
		if defaultVal {
			rdb.Set(ctx, key, "true", 0)
		} else {
			rdb.Set(ctx, key, "false", 0)
		}

		return false, err
	}
	return val == "true", nil
}

func refreshLists() error {
	mu.Lock()
	defer mu.Unlock()
	var err error
	ja3Blacklist, _ = loadSet("ja3:blacklist")
	ja3Whitelist, _ = loadSet("ja3:whitelist")
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

// 判断是否启用
func EnableJA3Check() bool       { mu.RLock(); defer mu.RUnlock(); return enableJA3Check }
func EnableJA3NCheck() bool      { mu.RLock(); defer mu.RUnlock(); return enableJA3NCheck }
func EnableJA4Check() bool       { mu.RLock(); defer mu.RUnlock(); return enableJA4Check }
func EnableJA3Collection() bool  { mu.RLock(); defer mu.RUnlock(); return enableJA3Collection }
func EnableJA3NCollection() bool { mu.RLock(); defer mu.RUnlock(); return enableJA3NCollection }
func EnableJA4Collection() bool  { mu.RLock(); defer mu.RUnlock(); return enableJA4Collection }

func ShouldBlockJA3(ja3 string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if !enableJA3Check {
		return false
	}
	if enableJA3Whitelist && !ja3Whitelist[ja3] {
		return true
	}
	if enableJA3Blacklist && ja3Blacklist[ja3] {
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
	if enableJA3NWhitelist && !ja3nWhitelist[ja3n] {
		return true
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
	if enableJA4Whitelist && !ja4Whitelist[ja4] {
		return true
	}
	if enableJA4Blacklist && ja4Blacklist[ja4] {
		return true
	}
	return false
}

func ReportJA3(ja3 string) {
	if !redisAvailable || !enableJA3Collection {
		return
	}
	now := float64(time.Now().Unix())

	pipe := rdb.TxPipeline()
	pipe.ZIncrBy(ctx, "ja3:count", 1, ja3)
	pipe.ZAdd(ctx, "ja3:last_seen", redis.Z{Score: now, Member: ja3})
	pipe.SAdd(ctx, "ja3:collected", ja3)
	_, err := pipe.Exec(ctx)
	if err != nil {
		log.Printf("[WARN] Redis 上报 JA3 失败: %v", err)
	}
}

func ReportJA3N(ja3n string) {
	if !redisAvailable || !enableJA3NCollection {
		return
	}
	now := float64(time.Now().Unix())

	pipe := rdb.TxPipeline()
	pipe.ZIncrBy(ctx, "ja3n:count", 1, ja3n)
	pipe.ZAdd(ctx, "ja3n:last_seen", redis.Z{Score: now, Member: ja3n})
	pipe.SAdd(ctx, "ja3n:collected", ja3n)
	_, err := pipe.Exec(ctx)
	if err != nil {
		log.Printf("[WARN] Redis 上报 JA3N 失败: %v", err)
	}
}

func ReportJA4(ja4 string) {
	if !redisAvailable || !enableJA4Collection {
		return
	}
	now := float64(time.Now().Unix())

	pipe := rdb.TxPipeline()
	pipe.ZIncrBy(ctx, "ja4:count", 1, ja4)
	pipe.ZAdd(ctx, "ja4:last_seen", redis.Z{Score: now, Member: ja4})
	pipe.SAdd(ctx, "ja4:collected", ja4)
	_, err := pipe.Exec(ctx)
	if err != nil {
		log.Printf("[WARN] Redis 上报 JA4 失败: %v", err)
	}
}

func CleanupOldFingerprintEntries(expireSeconds int64) {
	if !redisAvailable {
		log.Printf("[INFO] Redis 不可用，跳过指纹清理")
		return
	}

	expireBefore := float64(time.Now().Unix() - expireSeconds)
	expireScore := fmt.Sprintf("%f", expireBefore)

	targets := []string{
		"ja3:last_seen",
		"ja3n:last_seen",
		"ja4:last_seen",
	}

	for _, key := range targets {
		if deleted, err := rdb.ZRemRangeByScore(ctx, key, "-inf", expireScore).Result(); err != nil {
			log.Printf("[WARN] 清理指纹 %s 失败: %v", key, err)
		} else {
			log.Printf("[INFO] 清理指纹 %s 过期项 %d 个", key, deleted)
		}
	}
}

func scheduleCleanup() {
	ticker := time.NewTicker(6 * time.Hour)
	go func() {
		for range ticker.C {
			CleanupOldFingerprintEntries(8 * 3600) // 清理 8h 前的指纹数据
			log.Printf("[INFO] 清理过期指纹数据完成")
		}
	}()
}

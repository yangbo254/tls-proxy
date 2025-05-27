package config

import (
	"context"
	"fmt"
	"log/slog"
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

	// blockedCounter 存储每个 JA3 阻止的事件计数，map[ja3]map[timeStr]count
	ja3blockedCounter   = make(map[string]map[string]int)
	ja3blockedCounterMu sync.Mutex

	ja3nblockedCounter   = make(map[string]map[string]int)
	ja3nblockedCounterMu sync.Mutex

	ja4blockedCounter   = make(map[string]map[string]int)
	ja4blockedCounterMu sync.Mutex

	// 内存中缓存上报的计数（按指纹字符串累加）
	ja3ReportCounter = make(map[string]int)
	ja3ReportMu      sync.Mutex

	ja3nReportCounter = make(map[string]int)
	ja3nReportMu      sync.Mutex

	ja4ReportCounter = make(map[string]int)
	ja4ReportMu      sync.Mutex

	// 用于确保定时上报任务仅启动一次
	reportFlushOnce sync.Once
)

func Init(redisAddr, redisPasswd string, dbNum int) {
	rdb = redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     redisPasswd,
		DB:           dbNum,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		PoolSize:     512,
	})

	// 测试初始连接
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		slog.Warn("[WARN] Redis 初始连接失败，使用默认配置", "err", err)
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
				slog.Warn("[WARN] Redis 刷新配置失败，保持当前状态")
				redisAvailable = false
			} else {
				// 启动清理任务（只启动一次）
				cleanupOnce.Do(func() {
					slog.Info("[INFO] 启动定时清理任务")
					scheduleCleanup()
					slog.Info("[INFO] 启动阻止事件统计任务")
					startBlockedAggregation()
					slog.Info("[INFO] 启动上报任务")
					scheduleReportFlush()
				})
			}
		} else {
			if _, err := rdb.Ping(ctx).Result(); err == nil {
				slog.Info("[INFO] Redis 连接恢复")
				redisAvailable = true
				refreshFlags()
				refreshLists()
			}
		}
		time.Sleep(20 * time.Second)
	}
}

func refreshFlags() error {

	_enableJA3Check, err := getBool("config:ja3_check_enabled", enableJA3Check)
	_enableJA3Blacklist, _ := getBool("config:ja3_blacklist_enabled", enableJA3Blacklist)
	_enableJA3Whitelist, _ := getBool("config:ja3_whitelist_enabled", enableJA3Whitelist)
	_enableJA3Collection, _ := getBool("config:ja3_collection_enabled", enableJA3Collection)

	_enableJA3NCheck, _ := getBool("config:ja3n_check_enabled", enableJA3NCheck)
	_enableJA3NBlacklist, _ := getBool("config:ja3n_blacklist_enabled", enableJA3NBlacklist)
	_enableJA3NWhitelist, _ := getBool("config:ja3n_whitelist_enabled", enableJA3NWhitelist)
	_enableJA3NCollection, _ := getBool("config:ja3n_collection_enabled", enableJA3NCollection)

	_enableJA4Check, _ := getBool("config:ja4_check_enabled", enableJA4Check)
	_enableJA4Blacklist, _ := getBool("config:ja4_blacklist_enabled", enableJA4Blacklist)
	_enableJA4Whitelist, _ := getBool("config:ja4_whitelist_enabled", enableJA4Whitelist)
	_enableJA4Collection, _ := getBool("config:ja4_collection_enabled", enableJA4Collection)

	mu.Lock()
	enableJA3Check = _enableJA3Check
	enableJA3Blacklist = _enableJA3Blacklist
	enableJA3Whitelist = _enableJA3Whitelist
	enableJA3Collection = _enableJA3Collection

	enableJA3NCheck = _enableJA3NCheck
	enableJA3NBlacklist = _enableJA3NBlacklist
	enableJA3NWhitelist = _enableJA3NWhitelist
	enableJA3NCollection = _enableJA3NCollection

	enableJA4Check = _enableJA4Check
	enableJA4Blacklist = _enableJA4Blacklist
	enableJA4Whitelist = _enableJA4Whitelist
	enableJA4Collection = _enableJA4Collection
	mu.Unlock()
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

	var err error
	_ja3Blacklist, _ := loadSet("ja3:blacklist")
	_ja3Whitelist, _ := loadSet("ja3:whitelist")
	_ja3nBlacklist, _ := loadSet("ja3n:blacklist")
	_ja3nWhitelist, _ := loadSet("ja3n:whitelist")
	_ja4Blacklist, _ := loadSet("ja4:blacklist")
	_ja4Whitelist, _ := loadSet("ja4:whitelist")

	mu.Lock()
	ja3Blacklist = _ja3Blacklist
	ja3Whitelist = _ja3Whitelist
	ja3nBlacklist = _ja3nBlacklist
	ja3nWhitelist = _ja3nWhitelist
	ja4Blacklist = _ja4Blacklist
	ja4Whitelist = _ja4Whitelist
	mu.Unlock()

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

// ReportJA3 仅记录到内存中，不直接调用 Redis
func ReportJA3(ja3 string) {
	if !redisAvailable || !enableJA3Collection {
		return
	}
	ja3ReportMu.Lock()
	ja3ReportCounter[ja3]++
	ja3ReportMu.Unlock()
}

// ReportJA3N 同理
func ReportJA3N(ja3n string) {
	if !redisAvailable || !enableJA3NCollection {
		return
	}
	ja3nReportMu.Lock()
	ja3nReportCounter[ja3n]++
	ja3nReportMu.Unlock()
}

// ReportJA4 同理
func ReportJA4(ja4 string) {
	if !redisAvailable || !enableJA4Collection {
		return
	}
	ja4ReportMu.Lock()
	ja4ReportCounter[ja4]++
	ja4ReportMu.Unlock()
}

// flushReports 将内存中记录的上报数据一次性批量写入 Redis，并清空缓存
func flushReports() {
	now := float64(time.Now().Unix())

	// 处理 JA3
	ja3ReportMu.Lock()
	tmpJA3 := ja3ReportCounter
	ja3ReportCounter = make(map[string]int)
	ja3ReportMu.Unlock()

	go func(tmpJA3 map[string]int) {
		if len(tmpJA3) > 0 {
			pipe := rdb.TxPipeline()
			for fp, count := range tmpJA3 {
				pipe.ZIncrBy(ctx, "ja3:count", float64(count), fp)
				pipe.ZAdd(ctx, "ja3:last_seen", redis.Z{Score: now, Member: fp})
				pipe.SAdd(ctx, "ja3:collected", fp)
			}
			if _, err := pipe.Exec(ctx); err != nil {
				slog.Warn("[WARN] Redis 上报 JA3 失败", "err", err)
			}
		}
	}(tmpJA3)

	// 处理 JA3N
	ja3nReportMu.Lock()
	tmpJA3N := ja3nReportCounter
	ja3nReportCounter = make(map[string]int)
	ja3nReportMu.Unlock()

	go func(tmpJA3N map[string]int) {
		if len(tmpJA3N) > 0 {
			pipe := rdb.TxPipeline()
			for fp, count := range tmpJA3N {
				pipe.ZIncrBy(ctx, "ja3n:count", float64(count), fp)
				pipe.ZAdd(ctx, "ja3n:last_seen", redis.Z{Score: now, Member: fp})
				pipe.SAdd(ctx, "ja3n:collected", fp)
			}
			if _, err := pipe.Exec(ctx); err != nil {
				slog.Warn("[WARN] Redis 上报 JA3N 失败", "err", err)
			}
		}
	}(tmpJA3N)

	// 处理 JA4
	ja4ReportMu.Lock()
	tmpJA4 := ja4ReportCounter
	ja4ReportCounter = make(map[string]int)
	ja4ReportMu.Unlock()
	go func(tmpJA4 map[string]int) {
		if len(tmpJA4) > 0 {
			pipe := rdb.TxPipeline()
			for fp, count := range tmpJA4 {
				pipe.ZIncrBy(ctx, "ja4:count", float64(count), fp)
				pipe.ZAdd(ctx, "ja4:last_seen", redis.Z{Score: now, Member: fp})
				pipe.SAdd(ctx, "ja4:collected", fp)
			}
			if _, err := pipe.Exec(ctx); err != nil {
				slog.Warn("[WARN] Redis 上报 JA4 失败", "err", err)
			}
		}
	}(tmpJA4)
}

// scheduleReportFlush 每隔 5 秒批量上报一次上报数据（确保只启动一次）
func scheduleReportFlush() {
	reportFlushOnce.Do(func() {
		ticker := time.NewTicker(15 * time.Second)
		go func() {
			for range ticker.C {
				flushReports()
			}
		}()
	})
}

func CleanupOldFingerprintEntries(expireSeconds int64) {
	if !redisAvailable {
		slog.Info("[INFO] Redis 不可用，跳过指纹清理")
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
			slog.Warn("[WARN] 清理指纹失败", "key", key, "err", err)
		} else {
			slog.Info("[INFO] 清理指纹过期项", "key", key, "deleted", deleted)
		}
	}
}

func scheduleCleanup() {
	ticker := time.NewTicker(6 * time.Hour)
	go func() {
		for range ticker.C {
			CleanupOldFingerprintEntries(8 * 3600) // 清理 8h 前的指纹数据
			slog.Info("[INFO] 清理过期指纹数据完成")
		}
	}()
}

// ReportBlockedEvent 被阻止时调用，记录指纹阻止事件。
func ReportJA3BlockedEvent(ja3 string) {
	// 获取当前时间的秒数表示，例如 "15:04:05"
	now := time.Now().Format("2006-01-02 15:04:05")

	ja3blockedCounterMu.Lock()
	defer ja3blockedCounterMu.Unlock()

	if _, exists := ja3blockedCounter[ja3]; !exists {
		ja3blockedCounter[ja3] = make(map[string]int)
	}
	ja3blockedCounter[ja3][now]++
}

func ReportJA3NBlockedEvent(ja3n string) {
	// 获取当前时间的秒数表示，例如 "15:04:05"
	now := time.Now().Format("2006-01-02 15:04:05")

	ja3nblockedCounterMu.Lock()
	defer ja3nblockedCounterMu.Unlock()

	if _, exists := ja3nblockedCounter[ja3n]; !exists {
		ja3nblockedCounter[ja3n] = make(map[string]int)
	}
	ja3nblockedCounter[ja3n][now]++
}

func ReportJA4BlockedEvent(ja4 string) {
	// 获取当前时间的秒数表示，例如 "15:04:05"
	now := time.Now().Format("2006-01-02 15:04:05")

	ja4blockedCounterMu.Lock()
	defer ja4blockedCounterMu.Unlock()

	if _, exists := ja4blockedCounter[ja4]; !exists {
		ja4blockedCounter[ja4] = make(map[string]int)
	}
	ja4blockedCounter[ja4][now]++
}

// startBlockedAggregation 启动定时任务，每隔30秒上报 blockedCounter 数据到 Redis
func startBlockedAggregation() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			flushJA3BlockedCounters()
			flushJA3NBlockedCounters()
			flushJA4BlockedCounters()
		}
	}()
}

// flushBlockedCounters 将 blockedCounter 数据写入 Redis，并清空内存中已统计的数据
func flushJA3BlockedCounters() {
	ja3blockedCounterMu.Lock()
	// 备份当前数据，并重置全局计数
	data := ja3blockedCounter
	ja3blockedCounter = make(map[string]map[string]int)
	ja3blockedCounterMu.Unlock()

	// 对每个 ja3，将对应数据上报到 Redis 哈希结构中
	for ja3, timeMap := range data {
		redisKey := fmt.Sprintf("ja3:blocked:%s", ja3)
		pipe := rdb.TxPipeline()
		for tStr, count := range timeMap {
			// 使用 HINCRBY 方法更新字段，便于多个周期累加
			pipe.HIncrBy(ctx, redisKey, tStr, int64(count))
		}
		_, err := pipe.Exec(ctx)
		if err != nil {
			slog.Warn("[WARN] 上报 JA3 阻止计数失败", "ja3", ja3, "err", err)
		} else {
			slog.Info("[INFO] 上报 JA3 阻止计数", "ja3", ja3, "timeMap", timeMap)
		}
	}
}

// flushBlockedCounters 将 blockedCounter 数据写入 Redis，并清空内存中已统计的数据
func flushJA3NBlockedCounters() {
	ja3nblockedCounterMu.Lock()
	// 备份当前数据，并重置全局计数
	data := ja3nblockedCounter
	ja3nblockedCounter = make(map[string]map[string]int)
	ja3nblockedCounterMu.Unlock()

	// 对每个 ja3，将对应数据上报到 Redis 哈希结构中
	for ja3, timeMap := range data {
		redisKey := fmt.Sprintf("ja3n:blocked:%s", ja3)
		pipe := rdb.TxPipeline()
		for tStr, count := range timeMap {
			// 使用 HINCRBY 方法更新字段，便于多个周期累加
			pipe.HIncrBy(ctx, redisKey, tStr, int64(count))
		}
		_, err := pipe.Exec(ctx)
		if err != nil {
			slog.Warn("[WARN] 上报 JA3N 阻止计数失败", "ja3", ja3, "err", err)
		} else {
			slog.Info("[INFO] 上报 JA3N 阻止计数", "ja3", ja3, "timeMap", timeMap)
		}
	}
}

// flushBlockedCounters 将 blockedCounter 数据写入 Redis，并清空内存中已统计的数据
func flushJA4BlockedCounters() {
	ja4blockedCounterMu.Lock()
	// 备份当前数据，并重置全局计数
	data := ja4blockedCounter
	ja4blockedCounter = make(map[string]map[string]int)
	ja4blockedCounterMu.Unlock()

	// 对每个 ja3，将对应数据上报到 Redis 哈希结构中
	for ja3, timeMap := range data {
		redisKey := fmt.Sprintf("ja4:blocked:%s", ja3)
		pipe := rdb.TxPipeline()
		for tStr, count := range timeMap {
			// 使用 HINCRBY 方法更新字段，便于多个周期累加
			pipe.HIncrBy(ctx, redisKey, tStr, int64(count))
		}
		_, err := pipe.Exec(ctx)
		if err != nil {
			slog.Warn("[WARN] 上报 JA4 阻止计数失败", "ja3", ja3, "err", err)
		} else {
			slog.Info("[INFO] 上报 JA4 阻止计数", "ja3", ja3, "timeMap", timeMap)
		}
	}
}

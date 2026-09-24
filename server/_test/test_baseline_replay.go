package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"

	_ "github.com/mattn/go-sqlite3"
	"github.com/CoderXinNing/ebpf-system/server/internal/alert"
)

func main() {
	// 打开数据库
	db, err := sql.Open("sqlite3", "sentinel.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 创建基线引擎（学习期设为 0，直接进入防护）
	engine := alert.NewBaselineEngine("server/configs/baseline.toml")

	// 读取历史 exec 事件，按分钟聚合
	rows, err := db.Query("SELECT timestamp FROM events WHERE probe_name='execve' AND timestamp > (strftime('%s','now') - 3600) ORDER BY timestamp")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// 按分钟聚合
	minuteCounts := make(map[int64]int)
	for rows.Next() {
		var ts int64
		rows.Scan(&ts)
		minute := ts / 60
		minuteCounts[minute]++
	}

	fmt.Printf("历史数据: %d 个分钟窗口\n", len(minuteCounts))

	// 用前 80% 数据训练
	var counts []int
	for _, c := range minuteCounts {
		counts = append(counts, c)
	}

	trainSize := int(float64(len(counts)) * 0.8)
	fmt.Printf("训练窗口: %d 个\n", trainSize)

	engine.ForceProtectMode() // 跳过学习期

	for i := 0; i < trainSize; i++ {
		engine.Update(alert.Feature{IP: "172.16.2.145", Key: "exec_count", Value: float64(counts[i])})
	}

	// 看训练后的基线
	fmt.Printf("\n训练完成，测试异常检测:\n")
	fmt.Printf("正常范围: 大部分窗口执行 %d-%d 次\n", min(counts), max(counts))

	// 测试：正常值
	for i := 0; i < 3; i++ {
		val := float64(10 + rand.Intn(10))
		isAnomaly, z := engine.Update(alert.Feature{IP: "172.16.2.145", Key: "exec_count", Value: val})
		fmt.Printf("正常值 %.0f → 异常=%v z=%.2f\n", val, isAnomaly, z)
	}

	// 测试：轻微异常
	for i := 0; i < 3; i++ {
		val := float64(100 + rand.Intn(50))
		isAnomaly, z := engine.Update(alert.Feature{IP: "172.16.2.145", Key: "exec_count", Value: val})
		fmt.Printf("轻微异常 %.0f → 异常=%v z=%.2f\n", val, isAnomaly, z)
	}

	// 测试：极端异常
	for i := 0; i < 3; i++ {
		val := float64(500 + rand.Intn(100))
		isAnomaly, z := engine.Update(alert.Feature{IP: "172.16.2.145", Key: "exec_count", Value: val})
		fmt.Printf("极端异常 %.0f → 异常=%v z=%.2f\n", val, isAnomaly, z)
	}
}

func min(arr []int) int {
	m := arr[0]
	for _, v := range arr { if v < m { m = v } }
	return m
}

func max(arr []int) int {
	m := arr[0]
	for _, v := range arr { if v > m { m = v } }
	return m
}

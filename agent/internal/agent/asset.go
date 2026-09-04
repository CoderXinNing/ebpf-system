package agent

import (
	"context"
	"log"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/collector"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

func (a *Agent) collectAndReportAssets() {
	if a.client == nil || a.token == "" {
		log.Println("⚠️ Server未连接，跳过资产上报")
		return
	}

	// 1. 进程资产
	procs, err := collector.CollectAllProcesses()
	if err != nil {
		log.Printf("⚠️ 进程采集失败: %v", err)
	} else {
		processReport := &pb.ProcessReport{AgentId: a.id}
		for _, p := range procs {
			processReport.Processes = append(processReport.Processes, &pb.ProcessAsset{
				Pid: int32(p.PID), Ppid: int32(p.PPID), Name: p.Name, Cmdline: p.Cmdline,
				ExePath: p.ExePath, User: p.User, State: p.State, ListeningPorts: p.Ports,
				StartTime: collector.GetProcessStartTimeFormatted(p.PID),
			})
			// 上报进程事件用于告警检测
			if len(p.Cmdline) > 0 {
				a.eventQueue.Push(&pb.ProbeEvent{
					ProbeName: "process",
					Timestamp: time.Now().Unix(),
					EventType: "process_scan",
					Pid:       int32(p.PID),
					Comm:      p.Name,
					Filename:  p.Cmdline,
				}, PriorityNormal)
			}
		}
		a.reportWithTimeout(func(ctx context.Context) error {
			_, err := a.client.ReportProcesses(a.getAuthContext(ctx), processReport)
			return err
		})
		log.Printf("📊 进程资产: %d个", len(procs))
	}

	// 2. 用户资产
	users, err := collector.CollectAllUsers()
	if err != nil {
		log.Printf("⚠️ 用户采集失败: %v", err)
	} else {
		userReport := &pb.UserReport{AgentId: a.id}
		for _, u := range users {
			userReport.Users = append(userReport.Users, &pb.UserAsset{
				Username: u.Username, Uid: int32(u.UID), Gid: int32(u.GID),
				Home: u.Home, Shell: u.Shell, HasShell: u.HasShell,
				IsRoot: u.IsRoot, IsDisabled: u.IsDisabled, HasSudo: u.HasSudo,
				LastLogin: u.LastLogin, LastLoginIp: u.LastLoginIP,
			})
		}
		a.reportWithTimeout(func(ctx context.Context) error {
			_, err := a.client.ReportUsers(a.getAuthContext(ctx), userReport)
			return err
		})
		log.Printf("👤 用户资产: %d个", len(users))
	}

	// 3. 系统信息
	sysInfo, err := collector.CollectSystemInfo()
	if err != nil {
		log.Printf("⚠️ 系统信息采集失败: %v", err)
	} else if sysInfo != nil {
		systemReport := &pb.SystemReport{AgentId: a.id, System: &pb.SystemAsset{
			Os:     &pb.OSAsset{Name: sysInfo.OS.Name, Version: sysInfo.OS.Version, Kernel: sysInfo.OS.Kernel},
			Cpu:    &pb.CPUAsset{Model: sysInfo.CPU.Model, Cores: int32(sysInfo.CPU.Cores)},
			Memory: &pb.MemoryAsset{TotalMb: int32(sysInfo.Memory.TotalMB), SwapTotalMb: int32(sysInfo.Memory.SwapTotalMB)},
			Locale: sysInfo.Locale, Timezone: sysInfo.Timezone,
		}}
		for _, d := range sysInfo.Disks {
			systemReport.System.Disks = append(systemReport.System.Disks, &pb.DiskAsset{
				MountPoint: d.MountPoint, Filesystem: d.Filesystem, TotalMb: int32(d.TotalMB),
			})
		}
		for _, n := range sysInfo.Networks {
			systemReport.System.Networks = append(systemReport.System.Networks, &pb.NetworkAsset{
				Name: n.Name, Mac: n.MAC, Ips: n.IPs,
			})
		}
		systemReport.System.KernelModules = sysInfo.Modules
		for _, s := range sysInfo.Services {
			systemReport.System.Services = append(systemReport.System.Services, &pb.ServiceAsset{
				Name: s.Name, Enabled: s.Enabled,
			})
		}
		a.reportWithTimeout(func(ctx context.Context) error {
			_, err := a.client.ReportSystemInfo(a.getAuthContext(ctx), systemReport)
			return err
		})
		log.Printf("🖥️ 系统: %s %s CPU=%d核 Mem=%dMB", sysInfo.OS.Name, sysInfo.OS.Kernel, sysInfo.CPU.Cores, sysInfo.Memory.TotalMB)
	}

	// 4. 软件包
	pkgs := collector.CollectAllPackages()
	pkgReport := &pb.PackageReport{AgentId: a.id}
	for _, p := range pkgs {
		pkgReport.Packages = append(pkgReport.Packages, &pb.PackageAsset{
			Name: p.Name, Version: p.Version, Manager: p.Manager,
			SizeKb: collector.GetPkgSize(p.Name),
		})
	}
	for _, j := range collector.CollectJarPackages() {
		pkgReport.JarPackages = append(pkgReport.JarPackages, &pb.JarPackageAsset{Name: j.Name, Type: j.Type, Executable: j.Executable, Version: j.Version, Path: j.Path})
	}
	for _, p := range collector.CollectPythonPackages() {
		pkgReport.PythonPackages = append(pkgReport.PythonPackages, &pb.PythonPackageAsset{Name: p.Name, Version: p.Version, Path: p.Path, Scope: p.Scope})
	}
	for _, p := range collector.CollectNpmPackages() {
		pkgReport.NpmPackages = append(pkgReport.NpmPackages, &pb.NpmPackageAsset{Name: p.Name, Version: p.Version, Path: p.Path, Scope: p.Scope})
	}
	a.reportWithTimeout(func(ctx context.Context) error {
		_, err := a.client.ReportPackages(a.getAuthContext(ctx), pkgReport)
		return err
	})
	log.Printf("📦 软件包: %d个", len(pkgs))

	// 5. 定时任务
	crons := collector.CollectAllCronJobs()
	cronReport := &pb.CronReport{AgentId: a.id}
	for _, c := range crons {
		cronReport.Crons = append(cronReport.Crons, &pb.CronAsset{
			User: c.User, Schedule: c.Schedule, Command: c.Command, Source: c.Source,
		})
		a.eventQueue.Push(&pb.ProbeEvent{
			ProbeName: "cron", Timestamp: time.Now().Unix(),
			EventType: "cron_scan", Pid: 0,
			Comm: c.User, Filename: c.Command,
		}, PriorityNormal)
	}
	a.reportWithTimeout(func(ctx context.Context) error {
		_, err := a.client.ReportCronJobs(a.getAuthContext(ctx), cronReport)
		return err
	})
	log.Printf("⏰ 定时任务: %d个", len(crons))

	// 6. 服务
	svcs := collector.IdentifyServices()
	svcReport := &pb.ServiceReport{AgentId: a.id}
	for _, s := range svcs {
		svcReport.Services = append(svcReport.Services, &pb.IdentifiedService{
			Name: s.Name, Version: s.Version, Type: s.Type,
			Pid: int32(s.PID), ExePath: s.ExePath, ConfigPath: s.ConfigPath,
			ListenPort: s.ListenPort,
		})
	}
	for _, s := range collector.CollectServiceStatus() {
		svcReport.ServiceStatus = append(svcReport.ServiceStatus, &pb.ServiceStatusAsset{Name: s.Name, Enabled: s.Enabled, Active: s.Active})
	}
	a.reportWithTimeout(func(ctx context.Context) error {
		_, err := a.client.ReportServices(a.getAuthContext(ctx), svcReport)
		return err
	})
	log.Printf("🔍 服务: %d个", len(svcs))

	// 7. Web 组件
	wcs := collector.IdentifyWebComponents()
	wcReport := &pb.WebComponentReport{AgentId: a.id}
	for _, w := range wcs {
		wcReport.WebComponents = append(wcReport.WebComponents, &pb.WebComponentAsset{
			Name: w.Name, Type: w.Type, Version: w.Version,
			BasePath: w.BasePath, ConfigPath: w.ConfigPath, Pid: int32(w.PID),
		})
	}
	a.reportWithTimeout(func(ctx context.Context) error {
		_, err := a.client.ReportWebComponents(a.getAuthContext(ctx), wcReport)
		return err
	})
	log.Printf("🌐 Web组件: %d个", len(wcs))

	// 8. 硬件
	hw := collector.CollectHardwareInfo()
	hwReport := &pb.HardwareReport{AgentId: a.id, Hardware: &pb.HardwareAsset{
		Manufacturer: hw.Manufacturer, Model: hw.Model, SerialNumber: hw.SerialNumber, Uuid: hw.UUID, BootTime: hw.BootTime,
	}}
	for _, m := range collector.CollectKernelModuleDetails() {
		hwReport.KernelModules = append(hwReport.KernelModules, &pb.KernelModuleAsset{Name: m.Name, Description: m.Description, Path: m.Path, Version: m.Version, Size: m.Size, UsedBy: int32(m.UsedBy), Parameters: m.Parameters})
	}
	for _, e := range collector.CollectEnvVariables() {
		hwReport.EnvVariables = append(hwReport.EnvVariables, &pb.EnvVariableAsset{Name: e.Name, Value: e.Value, Type: e.Type, User: e.User})
	}
	a.reportWithTimeout(func(ctx context.Context) error {
		_, err := a.client.ReportHardware(a.getAuthContext(ctx), hwReport)
		return err
	})

	// 9. 网络
	gw := collector.CollectGatewayDNS()
	netReport := &pb.NetworkReport{AgentId: a.id}
	if gw != nil {
		netReport.GatewayDns = &pb.NetworkGatewayAsset{Gateway: gw.Gateway, Dns: gw.DNS}
	}
	for _, n := range collector.CollectNetworkDetails() {
		netReport.NetworkDetails = append(netReport.NetworkDetails, &pb.NetworkDetailAsset{Name: n.Name, Mac: n.MAC, Ips: n.IPs, Speed: n.Speed, Duplex: n.Duplex, Mtu: n.MTU})
	}
	for _, d := range collector.CollectDiskUsage() {
		netReport.DiskUsages = append(netReport.DiskUsages, &pb.DiskUsageAsset{MountPoint: d.MountPoint, TotalMb: int32(d.TotalMB), UsedMb: int32(d.UsedMB), UsePercent: d.UsePercent})
	}
	a.reportWithTimeout(func(ctx context.Context) error {
		_, err := a.client.ReportNetwork(a.getAuthContext(ctx), netReport)
		return err
	})

	// 10. 性能
	perf := collector.CollectPerfData()
	perfReport := &pb.PerfReport{AgentId: a.id, Perf: &pb.PerfDataAsset{
		CpuPercent: perf.CPUPercent,
		MemPercent: perf.MemPercent,
		MemUsedMb:  int32(perf.MemUsedMB),
		MemTotalMb: int32(perf.MemTotalMB),
	}}
	for _, d := range perf.DiskUsage {
		perfReport.Perf.DiskUsage = append(perfReport.Perf.DiskUsage, &pb.DiskPerfAsset{
			MountPoint: d.MountPoint, UsedMb: int32(d.UsedMB), TotalMb: int32(d.TotalMB), Percent: d.Percent,
		})
	}
	a.reportWithTimeout(func(ctx context.Context) error {
		_, err := a.client.ReportPerformance(a.getAuthContext(ctx), perfReport)
		return err
	})

	// 11. Agent 自信息
	self := collector.CollectAgentSelfInfo()
	selfReport := &pb.AgentSelfReport{AgentId: a.id, AgentSelf: &pb.AgentSelfAsset{
		InstallPath: self.InstallPath, ConfigPath: self.ConfigPath, LogPath: self.LogPath,
		RunUser: self.RunUser, RunPid: int32(self.RunPID), Version: self.Version,
	}}
	a.reportWithTimeout(func(ctx context.Context) error {
		_, err := a.client.ReportAgentSelf(a.getAuthContext(ctx), selfReport)
		return err
	})
}

// reportWithTimeout 统一上报超时处理
func (a *Agent) reportWithTimeout(fn func(ctx context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := fn(ctx); err != nil {
		log.Printf("⚠️ 资产上报失败: %v", err)
	}
}

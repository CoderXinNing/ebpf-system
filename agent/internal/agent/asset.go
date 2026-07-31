package agent

import (
	"context"
	"log"
	"time"

	"github.com/CoderXinNing/ebpf-system/agent/internal/collector"
	pb "github.com/CoderXinNing/ebpf-system/proto/pb"
)

func (a *Agent) collectAndReportAssets() {
	procs, err := collector.CollectAllProcesses()
	if err != nil {
		log.Printf("⚠️ 进程采集失败: %v", err)
		return
	}
	users, _ := collector.CollectAllUsers()
	crons := collector.CollectAllCronJobs()
	pkgs := collector.CollectAllPackages()
	sysInfo, _ := collector.CollectSystemInfo()

	log.Printf("📊 资产采集: %d进程 %d用户 %d定时任务 %d软件包", len(procs), len(users), len(crons), len(pkgs))

	assetReq := &pb.AssetReport{AgentId: a.id, AgentToken: a.token}

	for _, p := range procs {
		assetReq.Processes = append(assetReq.Processes, &pb.ProcessAsset{
			Pid: int32(p.PID), Ppid: int32(p.PPID), Name: p.Name, Cmdline: p.Cmdline,
			ExePath: p.ExePath, User: p.User, State: p.State, ListeningPorts: p.Ports,
				StartTime: collector.GetProcessStartTimeFormatted(p.PID),
		})
	}
	for _, u := range users {
		assetReq.Users = append(assetReq.Users, &pb.UserAsset{
			Username: u.Username, Uid: int32(u.UID), Gid: int32(u.GID),
			Home: u.Home, Shell: u.Shell, HasShell: u.HasShell,
			IsRoot: u.IsRoot, IsDisabled: u.IsDisabled, HasSudo: u.HasSudo,
			LastLogin: u.LastLogin, LastLoginIp: u.LastLoginIP,
		})
	}
	for _, c := range crons {
		assetReq.Crons = append(assetReq.Crons, &pb.CronAsset{
			User: c.User, Schedule: c.Schedule, Command: c.Command, Source: c.Source,
		})
	}
	pkgSizes := collector.GetAllPackageSizes()
	log.Printf("包大小map: %d个", len(pkgSizes))
	for _, p := range pkgs {
		assetReq.Packages = append(assetReq.Packages, &pb.PackageAsset{
			Name: p.Name, Version: p.Version, Manager: p.Manager,
				SizeKb: pkgSizes[p.Name],
		})
	}

	svcs := collector.IdentifyServices()
	for _, s := range svcs {
		assetReq.Services = append(assetReq.Services, &pb.IdentifiedService{
			Name: s.Name, Version: s.Version, Type: s.Type,
			Pid: int32(s.PID), ExePath: s.ExePath, ConfigPath: s.ConfigPath,
			ListenPort: s.ListenPort,
		})
	}
	log.Printf("🔍 服务识别: %d个", len(svcs))

	wcs := collector.IdentifyWebComponents()
	for _, w := range wcs {
		assetReq.WebComponents = append(assetReq.WebComponents, &pb.WebComponentAsset{
			Name: w.Name, Type: w.Type, Version: w.Version,
			BasePath: w.BasePath, ConfigPath: w.ConfigPath, Pid: int32(w.PID),
		})
	}
	log.Printf("🌐 Web组件: %d个", len(wcs))

	if sysInfo != nil {
		assetReq.System = &pb.SystemAsset{
			Os:     &pb.OSAsset{Name: sysInfo.OS.Name, Version: sysInfo.OS.Version, Kernel: sysInfo.OS.Kernel},
			Cpu:    &pb.CPUAsset{Model: sysInfo.CPU.Model, Cores: int32(sysInfo.CPU.Cores)},
			Memory: &pb.MemoryAsset{TotalMb: int32(sysInfo.Memory.TotalMB), SwapTotalMb: int32(sysInfo.Memory.SwapTotalMB)},
			Locale: sysInfo.Locale, Timezone: sysInfo.Timezone,
		}
		for _, d := range sysInfo.Disks {
			assetReq.System.Disks = append(assetReq.System.Disks, &pb.DiskAsset{
				MountPoint: d.MountPoint, Filesystem: d.Filesystem, TotalMb: int32(d.TotalMB),
			})
		}
		for _, n := range sysInfo.Networks {
			assetReq.System.Networks = append(assetReq.System.Networks, &pb.NetworkAsset{
				Name: n.Name, Mac: n.MAC, Ips: n.IPs,
			})
		}
		assetReq.System.KernelModules = sysInfo.Modules
		for _, s := range sysInfo.Services {
			assetReq.System.Services = append(assetReq.System.Services, &pb.ServiceAsset{
				Name: s.Name, Enabled: s.Enabled,
			})
		}
		log.Printf("🖥️  系统: %s %s CPU=%d核 Mem=%dMB 磁盘=%d 服务=%d",
			sysInfo.OS.Name, sysInfo.OS.Kernel, sysInfo.CPU.Cores, sysInfo.Memory.TotalMB, len(sysInfo.Disks), len(sysInfo.Services))
	}

	// 新增采集字段
	hw := collector.CollectHardwareInfo()
	assetReq.Hardware = &pb.HardwareAsset{Manufacturer: hw.Manufacturer, Model: hw.Model, SerialNumber: hw.SerialNumber, Uuid: hw.UUID, BootTime: hw.BootTime}
	for _, m := range collector.CollectKernelModuleDetails() {
		assetReq.KernelModules = append(assetReq.KernelModules, &pb.KernelModuleAsset{Name: m.Name, Description: m.Description, Path: m.Path, Version: m.Version, Size: m.Size, UsedBy: int32(m.UsedBy), Parameters: m.Parameters})
	}
	for _, e := range collector.CollectEnvVariables() {
		assetReq.EnvVariables = append(assetReq.EnvVariables, &pb.EnvVariableAsset{Name: e.Name, Value: e.Value, Type: e.Type, User: e.User})
	}
	for _, d := range collector.CollectDiskUsage() {
		assetReq.DiskUsages = append(assetReq.DiskUsages, &pb.DiskUsageAsset{MountPoint: d.MountPoint, TotalMb: int32(d.TotalMB), UsedMb: int32(d.UsedMB), UsePercent: d.UsePercent})
	}
	for _, n := range collector.CollectNetworkDetails() {
	// 网关和DNS
	gw := collector.CollectGatewayDNS()
	if gw != nil {
		assetReq.GatewayDns = &pb.NetworkGatewayAsset{Gateway: gw.Gateway, Dns: gw.DNS}
	}
		assetReq.NetworkDetails = append(assetReq.NetworkDetails, &pb.NetworkDetailAsset{Name: n.Name, Mac: n.MAC, Ips: n.IPs, Speed: n.Speed, Duplex: n.Duplex, Mtu: n.MTU})
	}
	for _, s := range collector.CollectServiceStatus() {
		assetReq.ServiceStatus = append(assetReq.ServiceStatus, &pb.ServiceStatusAsset{Name: s.Name, Enabled: s.Enabled, Active: s.Active})
	}
	for _, j := range collector.CollectJarPackages() {
		assetReq.JarPackages = append(assetReq.JarPackages, &pb.JarPackageAsset{Name: j.Name, Type: j.Type, Executable: j.Executable, Version: j.Version, Path: j.Path})
	}
	for _, p := range collector.CollectPythonPackages() {
		assetReq.PythonPackages = append(assetReq.PythonPackages, &pb.PythonPackageAsset{Name: p.Name, Version: p.Version, Path: p.Path, Scope: p.Scope})
	}
	for _, p := range collector.CollectNpmPackages() {
		assetReq.NpmPackages = append(assetReq.NpmPackages, &pb.NpmPackageAsset{Name: p.Name, Version: p.Version, Path: p.Path, Scope: p.Scope})
	}
	self := collector.CollectAgentSelfInfo()
	assetReq.AgentSelf = &pb.AgentSelfAsset{InstallPath: self.InstallPath, ConfigPath: self.ConfigPath, LogPath: self.LogPath, RunUser: self.RunUser, RunPid: int32(self.RunPID), Version: self.Version}
	log.Printf("📊 新增字段: hw=%v km=%d env=%d disk=%d net=%d svc=%d jar=%d py=%d npm=%d",
		assetReq.Hardware != nil, len(assetReq.KernelModules), len(assetReq.EnvVariables),
		len(assetReq.DiskUsages), len(assetReq.NetworkDetails), len(assetReq.ServiceStatus),
		len(assetReq.JarPackages), len(assetReq.PythonPackages), len(assetReq.NpmPackages))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := a.client.ReportAssets(ctx, assetReq); err != nil {
		log.Printf("⚠️ 资产上报失败: %v", err)
	}
}

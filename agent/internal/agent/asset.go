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
	for _, p := range pkgs {
		assetReq.Packages = append(assetReq.Packages, &pb.PackageAsset{
			Name: p.Name, Version: p.Version, Manager: p.Manager,
		})
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := a.client.ReportAssets(ctx, assetReq); err != nil {
		log.Printf("⚠️ 资产上报失败: %v", err)
	}
}

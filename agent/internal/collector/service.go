package collector

import (
	"os"
	"path/filepath"
	"strings"
)

type ServiceDetail struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Type       string   `json:"type"`
	PID        int      `json:"pid"`
	ExePath    string   `json:"exe_path"`
	ConfigPath string   `json:"config_path"`
	ListenPort []string `json:"listen_port"`
}

type servicePattern struct {
	name     string
	svcType  string
	keywords []string
}

var knownServices = []servicePattern{
	{name: "MySQL", svcType: "数据库", keywords: []string{"mysqld", "mysql"}},
	{name: "PostgreSQL", svcType: "数据库", keywords: []string{"postgres", "postmaster"}},
	{name: "Redis", svcType: "数据库", keywords: []string{"redis-server"}},
	{name: "MongoDB", svcType: "数据库", keywords: []string{"mongod", "mongos"}},
	{name: "Nginx", svcType: "Web服务器", keywords: []string{"nginx"}},
	{name: "Apache", svcType: "Web服务器", keywords: []string{"httpd", "apache2"}},
	{name: "Tomcat", svcType: "Web服务器", keywords: []string{"tomcat", "catalina", "bootstrap.jar"}},
	{name: "RabbitMQ", svcType: "中间件", keywords: []string{"rabbitmq", "rabbit"}},
	{name: "Kafka", svcType: "中间件", keywords: []string{"kafka"}},
	{name: "Elasticsearch", svcType: "中间件", keywords: []string{"elasticsearch"}},
	{name: "Java", svcType: "语言脚本应用", keywords: []string{"java", "jsvc"}},
	{name: "Python", svcType: "语言脚本应用", keywords: []string{"python", "gunicorn", "uvicorn"}},
	{name: "Node.js", svcType: "语言脚本应用", keywords: []string{"node", "nodejs"}},
	{name: "Prometheus", svcType: "监控", keywords: []string{"prometheus"}},
	{name: "Grafana", svcType: "监控", keywords: []string{"grafana"}},
	{name: "Docker", svcType: "容器", keywords: []string{"dockerd", "containerd"}},
	{name: "Kubernetes", svcType: "容器", keywords: []string{"kubelet", "kube-apiserver"}},
}

func IdentifyServices() []ServiceDetail {
	procs, _ := CollectAllProcesses()
	pkgs := CollectAllPackages()

	var services []ServiceDetail
	found := make(map[string]bool)

	for _, proc := range procs {
		// 跳过内核线程
		if proc.PPID <= 2 {
			continue
		}
		if strings.HasPrefix(proc.Name, "kworker") || strings.HasPrefix(proc.Name, "ksoftirqd") ||
			strings.HasPrefix(proc.Name, "rcu") || proc.Name == "kdevtmpfs" ||
			strings.HasPrefix(proc.Name, "irq/") || strings.HasPrefix(proc.Name, "watchdog") {
			continue
		}

		cmdline := strings.ToLower(proc.Cmdline)
		name := strings.ToLower(proc.Name)

		for _, svc := range knownServices {
			if found[svc.name] {
				continue
			}
			for _, kw := range svc.keywords {
				if strings.Contains(name, kw) || strings.Contains(cmdline, kw) {
					detail := ServiceDetail{
						Name:       svc.name,
						Type:       svc.svcType,
						PID:        proc.PID,
						ExePath:    proc.ExePath,
						ListenPort: proc.Ports,
					}
					detail.Version = extractPkgVersion(svc.keywords, pkgs)
					detail.ConfigPath = findConfigPath(svc.name)
					services = append(services, detail)
					found[svc.name] = true
					break
				}
			}
		}
	}

	// 从软件包补充未运行的服务
	for _, pkg := range pkgs {
		pkgName := strings.ToLower(pkg.Name)
		for _, svc := range knownServices {
			if found[svc.name] {
				continue
			}
			for _, kw := range svc.keywords {
				if strings.Contains(pkgName, kw) && !strings.Contains(pkgName, "lib") {
					services = append(services, ServiceDetail{
						Name:    svc.name,
						Type:    svc.svcType,
						Version: pkg.Version,
					})
					found[svc.name] = true
					break
				}
			}
		}
	}

	// 兜底：未识别的归入"其他"
	otherFound := make(map[string]bool)
	for _, proc := range procs {
		if proc.Name == "" || found[proc.Name] || otherFound[proc.Name] {
			continue
		}
		if proc.PPID <= 2 {
			continue
		}
		services = append(services, ServiceDetail{
			Name:       proc.Name,
			Type:       "其他",
			PID:        proc.PID,
			ExePath:    proc.ExePath,
			ListenPort: proc.Ports,
		})
		otherFound[proc.Name] = true
	}

	return services
}

func extractPkgVersion(keywords []string, pkgs []PackageInfo) string {
	for _, pkg := range pkgs {
		name := strings.ToLower(pkg.Name)
		for _, kw := range keywords {
			if strings.Contains(name, kw) && !strings.Contains(name, "lib") {
				return pkg.Version
			}
		}
	}
	return "未知"
}

func findConfigPath(svcName string) string {
	defaultPaths := map[string][]string{
		"Nginx":      {"/etc/nginx/nginx.conf"},
		"Apache":     {"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf"},
		"MySQL":      {"/etc/mysql/my.cnf", "/etc/my.cnf"},
		"PostgreSQL": {"/etc/postgresql"},
		"Redis":      {"/etc/redis/redis.conf"},
		"Tomcat":     {"/etc/tomcat9/server.xml", "/opt/tomcat/conf/server.xml"},
		"MongoDB":    {"/etc/mongod.conf"},
		"Docker":     {"/etc/docker/daemon.json"},
		"Prometheus": {"/etc/prometheus/prometheus.yml"},
		"Grafana":    {"/etc/grafana/grafana.ini"},
	}
	if paths, ok := defaultPaths[svcName]; ok {
		for _, p := range paths {
			if strings.Contains(p, "*") {
				matches, _ := filepath.Glob(p)
				if len(matches) > 0 {
					return matches[0]
				}
			} else {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	return ""
}

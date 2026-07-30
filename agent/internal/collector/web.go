package collector

import (
	"os"
	"path/filepath"
	"strings"
)

// WebComponent Web组件信息
type WebComponent struct {
	Name       string `json:"name"`        // 组件名称
	Type       string `json:"type"`        // 框架/服务器/静态资源
	Version    string `json:"version"`     // 版本号
	BasePath   string `json:"base_path"`   // 部署路径
	ConfigPath string `json:"config_path"` // 配置文件路径
	PID        int    `json:"pid"`         // 关联进程PID
}

// webPattern Web组件识别模式
type webPattern struct {
	name         string
	compType     string // 框架/服务器/静态资源
	jarKeywords  []string // jar包关键字
	procKeywords []string // 进程关键字
	pathKeywords []string // 路径关键字
}

var knownWebComponents = []webPattern{
	// Java Web框架
	{name: "SpringBoot", compType: "框架", jarKeywords: []string{"spring-boot", "springboot"}},
	{name: "SpringMVC", compType: "框架", jarKeywords: []string{"spring-webmvc", "spring-web"}},
	{name: "Struts2", compType: "框架", jarKeywords: []string{"struts2-core", "struts2"}},
	{name: "Tomcat", compType: "Web应用", procKeywords: []string{"tomcat", "catalina"}, jarKeywords: []string{"tomcat-embed", "catalina"}},
	{name: "Jetty", compType: "Web应用", jarKeywords: []string{"jetty-server", "jetty"}},
	{name: "Netty", compType: "Web应用", jarKeywords: []string{"netty-all", "netty"}},

	// Python Web框架
	{name: "Flask", compType: "框架", procKeywords: []string{"flask"}, pathKeywords: []string{"flask"}},
	{name: "Django", compType: "框架", procKeywords: []string{"django"}, pathKeywords: []string{"django"}},
	{name: "FastAPI", compType: "框架", procKeywords: []string{"fastapi", "uvicorn"}},
	{name: "Gunicorn", compType: "Web应用", procKeywords: []string{"gunicorn"}},

	// Node.js Web框架
	{name: "Express", compType: "框架", pathKeywords: []string{"express"}},
	{name: "Koa", compType: "框架", pathKeywords: []string{"koa"}},
	{name: "Next.js", compType: "框架", pathKeywords: []string{"next", "next.js"}},
	{name: "NestJS", compType: "框架", pathKeywords: []string{"nestjs", "nest"}},

	// PHP
	{name: "PHP-FPM", compType: "Web应用", procKeywords: []string{"php-fpm"}},
	{name: "Laravel", compType: "框架", pathKeywords: []string{"laravel", "artisan"}},

	// Go
	{name: "Gin", compType: "框架", pathKeywords: []string{"gin"}},
	{name: "Echo", compType: "框架", pathKeywords: []string{"echo", "labstack"}},

	// Web服务器
	{name: "Nginx", compType: "Web应用", procKeywords: []string{"nginx"}},
	{name: "Apache", compType: "Web应用", procKeywords: []string{"httpd", "apache2"}},
	{name: "Caddy", compType: "Web应用", procKeywords: []string{"caddy"}},
	{name: "Traefik", compType: "Web应用", procKeywords: []string{"traefik"}},
	{name: "Envoy", compType: "Web应用", procKeywords: []string{"envoy"}},

	// 静态资源/CDN
	{name: "Vue.js", compType: "框架", pathKeywords: []string{"vue", "vue.js"}},
	{name: "React", compType: "框架", pathKeywords: []string{"react"}},
	{name: "jQuery", compType: "框架", pathKeywords: []string{"jquery"}},
	{name: "Bootstrap", compType: "框架", pathKeywords: []string{"bootstrap"}},
}

// IdentifyWebComponents 识别Web组件
func IdentifyWebComponents() []WebComponent {
	procs, _ := CollectAllProcesses()
	pkgs := CollectAllPackages()

	var components []WebComponent
	found := make(map[string]bool)

	for _, proc := range procs {
		cmdline := strings.ToLower(proc.Cmdline)
		name := strings.ToLower(proc.Name)
		exePath := strings.ToLower(proc.ExePath)

		for _, wc := range knownWebComponents {
			compKey := wc.name + "_proc"
			if found[compKey] {
				continue
			}

			// 匹配进程关键字
			for _, kw := range wc.procKeywords {
				if strings.Contains(name, kw) || strings.Contains(cmdline, kw) {
					comp := WebComponent{
						Name:    wc.name,
						Type:    wc.compType,
						PID:     proc.PID,
						Version: extractPkgVersion(wc.procKeywords, pkgs),
					}
					// 找部署路径
					comp.BasePath = extractBasePath(proc.Cmdline, proc.ExePath)
					comp.ConfigPath = findWebConfigPath(wc.name, comp.BasePath)
					components = append(components, comp)
					found[compKey] = true
					break
				}
			}

			// 匹配路径关键字（从进程的jar包或工作目录）
			for _, kw := range wc.pathKeywords {
				if strings.Contains(cmdline, kw) || strings.Contains(exePath, kw) {
					if found[compKey] {
						continue
					}
					comp := WebComponent{
						Name:    wc.name,
						Type:    wc.compType,
						PID:     proc.PID,
						Version: extractPkgVersion(wc.pathKeywords, pkgs),
					}
					comp.BasePath = extractBasePath(proc.Cmdline, proc.ExePath)
					components = append(components, comp)
					found[compKey] = true
					break
				}
			}
		}
	}

	// 从软件包补充
	for _, pkg := range pkgs {
		pkgName := strings.ToLower(pkg.Name)
		for _, wc := range knownWebComponents {
			compKey := wc.name + "_pkg"
			if found[compKey] {
				continue
			}
			for _, kw := range wc.jarKeywords {
				if strings.Contains(pkgName, kw) {
					components = append(components, WebComponent{
						Name:    wc.name,
						Type:    wc.compType,
						Version: pkg.Version,
					})
					found[compKey] = true
					break
				}
			}
		}
	}

	// 搜索常见Web目录
	webDirs := []string{"/var/www", "/opt/web", "/usr/share/nginx", "/var/lib/tomcat", "/opt/tomcat"}
	for _, dir := range webDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			entries, _ := os.ReadDir(dir)
			for _, entry := range entries {
				if entry.IsDir() {
					subPath := dir + "/" + entry.Name()
					// 检查是否有package.json、requirements.txt等
					for _, marker := range []string{"package.json", "requirements.txt", "pom.xml", "composer.json"} {
						if _, err := os.Stat(subPath + "/" + marker); err == nil {
							compName := entry.Name()
							if !found[compName] {
								components = append(components, WebComponent{
									Name:     compName,
									Type:     "Web应用",
									BasePath: subPath,
								})
								found[compName] = true
							}
							break
						}
					}
				}
			}
		}
	}

	// 合并服务识别中的Web服务器
	svcs := IdentifyServices()
	for _, svc := range svcs {
		if svc.Type == "Web服务器" {
			found := false
			for _, c := range components {
				if c.Name == svc.Name {
					found = true
					break
				}
			}
			if !found {
				components = append(components, WebComponent{
					Name:    svc.Name,
					Type:    svc.Type,
					Version: svc.Version,
					PID:     svc.PID,
					BasePath: svc.ExePath,
					ConfigPath: svc.ConfigPath,
				})
			}
		}
	}
	return components
}

// extractBasePath 从cmdline提取Web应用根路径
func extractBasePath(cmdline, exePath string) string {
	// 找 -Dcatalina.base=xxx 或 /path/app.jar
	parts := strings.Fields(cmdline)
	for _, part := range parts {
		if strings.HasPrefix(part, "-Dcatalina.base=") || strings.HasPrefix(part, "-Duser.dir=") {
			return strings.SplitN(part, "=", 2)[1]
		}
	}

	// 如果cmdline里有.jar，取其所在目录
	for _, part := range parts {
		if strings.HasSuffix(part, ".jar") && strings.HasPrefix(part, "/") {
			if idx := strings.LastIndex(part, "/"); idx > 0 {
				return part[:idx]
			}
		}
	}

	// 从可执行文件路径推断
	if strings.HasPrefix(exePath, "/") {
		if idx := strings.LastIndex(exePath, "/"); idx > 0 {
			return exePath[:idx]
		}
	}

	return ""
}

// findWebConfigPath 查找Web组件配置文件
func findWebConfigPath(name, basePath string) string {
	configs := map[string][]string{
		"Nginx":    {basePath + "/nginx.conf", "/etc/nginx/nginx.conf"},
		"Apache":   {basePath + "/conf/httpd.conf", "/etc/apache2/apache2.conf"},
		"Tomcat":   {basePath + "/conf/server.xml", "/etc/tomcat9/server.xml"},
		"SpringBoot": {basePath + "/application.properties", basePath + "/application.yml"},
		"Django":   {basePath + "/settings.py"},
		"Flask":    {basePath + "/app.py", basePath + "/wsgi.py"},
		"Express":  {basePath + "/package.json"},
		"PHP-FPM":  {"/etc/php/*/fpm/php-fpm.conf"},
	}

	if paths, ok := configs[name]; ok {
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

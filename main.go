package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ============================================================
// 配置结构体定义
// ============================================================

type SwitchMode string

const (
	SwitchModePriority SwitchMode = "priority"
	SwitchModeLatency  SwitchMode = "latency"
)

type Config struct {
	LoopTime         int             `json:"loop_time"`
	ProbeCount       int             `json:"probe_count"`
	ProbeRetry       int             `json:"probe_retry"`
	ProbeTimeout     int             `json:"probe_timeout"`
	ProbeProxy       string          `json:"probe_proxy"`
	CFProxy          string          `json:"cf_proxy"`
	SwitchMode       string          `json:"switch_mode"`
	SyncCandidateDNS bool            `json:"sync_candidate_dns"`
	CF               CFConfig        `json:"cf"`
	List             []CandidateNode `json:"list"`

	// 兼容旧版及别名配置字段
	Count     int `json:"count"`
	FailCount int `json:"fail_count"`
	RiseCount int `json:"rise_count"`
	Retry     int `json:"retry"`
}

type CFConfig struct {
	APIToken         string `json:"api_token"`
	ZoneID           string `json:"zone_id"`
	RecordName       string `json:"record_name"`
	RecordType       string `json:"record_type"`
	TTL              int    `json:"ttl"`
	Proxied          bool   `json:"proxied"`
	Proxy            string `json:"proxy"`
	SyncCandidateDNS bool   `json:"sync_candidate_dns"`
}

type CandidateNode struct {
	Detect string `json:"detect"`
	Value  string `json:"value"`
}

// ============================================================
// 状态机与模型定义
// ============================================================

type NodeStatus string

const (
	StatusUnknown   NodeStatus = "unknown"
	StatusHealthy   NodeStatus = "healthy"
	StatusUnhealthy NodeStatus = "unhealthy"
)

type NodeState struct {
	Index        int
	Detect       string
	Value        string
	Status       NodeStatus
	OkStreak     int
	FailStreak   int
	LastDuration int64
	LastError    string
}

type Decision struct {
	TargetIndex int
}

type DnsRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type CFResponse struct {
	Success  bool        `json:"success"`
	Errors   []CFError   `json:"errors"`
	Messages []string    `json:"messages"`
	Result   []DnsRecord `json:"result"`
}

type CFError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var ErrRecordNotFound = errors.New("未在 zone 中找到记录")

// ============================================================
// 日志辅助工具
// ============================================================

func nowTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func logInfo(format string, args ...any) {
	fmt.Printf("[%s] "+format+"\n\n", append([]any{nowTime()}, args...)...)
}

// ============================================================
// 原生 YAML 轻量解析器
// ============================================================

type lineInfo struct {
	indent int
	text   string
}

func parseYAML(content []byte) (map[string]any, error) {
	trimmedContent := bytes.TrimSpace(content)
	if len(trimmedContent) > 0 && trimmedContent[0] == '{' {
		var m map[string]any
		if err := json.Unmarshal(trimmedContent, &m); err == nil {
			return m, nil
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var lines []lineInfo

	for scanner.Scan() {
		raw := scanner.Text()
		stripped := stripComment(raw)
		clean := strings.ReplaceAll(stripped, "\t", "  ")
		trimmed := strings.TrimRight(clean, " \t\r\n")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}

		indent := 0
		for indent < len(trimmed) && trimmed[indent] == ' ' {
			indent++
		}
		text := strings.TrimSpace(trimmed)
		lines = append(lines, lineInfo{indent: indent, text: text})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	root := make(map[string]any)
	_, err := parseMapping(lines, 0, 0, root)
	if err != nil {
		return nil, err
	}
	return root, nil
}

func stripComment(s string) string {
	inSingle := false
	inDouble := false
	for i := range len(s) {
		ch := s[i]
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
		} else if ch == '#' && !inSingle && !inDouble {
			return s[:i]
		}
	}
	return s
}

func parseMapping(lines []lineInfo, startIdx int, minIndent int, target map[string]any) (int, error) {
	i := startIdx
	for i < len(lines) {
		line := lines[i]
		if line.indent < minIndent {
			break
		}
		if line.indent > minIndent {
			return i, fmt.Errorf("unexpected indent at line: %s", line.text)
		}

		colonIdx := strings.Index(line.text, ":")
		if colonIdx == -1 {
			return i, fmt.Errorf("missing colon in mapping: %s", line.text)
		}

		key := strings.TrimSpace(line.text[:colonIdx])
		valPart := strings.TrimSpace(line.text[colonIdx+1:])

		if valPart != "" {
			target[key] = parseScalar(valPart)
			i++
			continue
		}

		if i+1 >= len(lines) {
			target[key] = nil
			i++
			break
		}

		nextLine := lines[i+1]
		if nextLine.indent <= line.indent {
			target[key] = nil
			i++
			continue
		}

		if strings.HasPrefix(nextLine.text, "- ") || nextLine.text == "-" {
			var list []any
			nextI, err := parseSequence(lines, i+1, nextLine.indent, &list)
			if err != nil {
				return i, err
			}
			target[key] = list
			i = nextI
		} else {
			subMap := make(map[string]any)
			nextI, err := parseMapping(lines, i+1, nextLine.indent, subMap)
			if err != nil {
				return i, err
			}
			target[key] = subMap
			i = nextI
		}
	}
	return i, nil
}

func parseSequence(lines []lineInfo, startIdx int, seqIndent int, list *[]any) (int, error) {
	i := startIdx
	for i < len(lines) {
		line := lines[i]
		if line.indent < seqIndent {
			break
		}
		if line.indent > seqIndent {
			return i, fmt.Errorf("unexpected sequence indent at: %s", line.text)
		}

		if !strings.HasPrefix(line.text, "- ") && line.text != "-" {
			break
		}

		itemContent := strings.TrimSpace(strings.TrimPrefix(line.text, "-"))
		if itemContent == "" {
			if i+1 < len(lines) && lines[i+1].indent > line.indent {
				nextLine := lines[i+1]
				if strings.HasPrefix(nextLine.text, "- ") || nextLine.text == "-" {
					var subList []any
					nextI, err := parseSequence(lines, i+1, nextLine.indent, &subList)
					if err != nil {
						return i, err
					}
					*list = append(*list, subList)
					i = nextI
				} else {
					subMap := make(map[string]any)
					nextI, err := parseMapping(lines, i+1, nextLine.indent, subMap)
					if err != nil {
						return i, err
					}
					*list = append(*list, subMap)
					i = nextI
				}
				continue
			}
			*list = append(*list, nil)
			i++
			continue
		}

		colonIdx := strings.Index(itemContent, ":")
		if colonIdx != -1 {
			subMap := make(map[string]any)
			key := strings.TrimSpace(itemContent[:colonIdx])
			valPart := strings.TrimSpace(itemContent[colonIdx+1:])
			if valPart != "" {
				subMap[key] = parseScalar(valPart)
			} else {
				subMap[key] = nil
			}

			if i+1 < len(lines) && lines[i+1].indent > line.indent {
				nextI, err := parseMapping(lines, i+1, lines[i+1].indent, subMap)
				if err != nil {
					return i, err
				}
				*list = append(*list, subMap)
				i = nextI
				continue
			}

			*list = append(*list, subMap)
			i++
			continue
		}

		*list = append(*list, parseScalar(itemContent))
		i++
	}
	return i, nil
}

func parseScalar(s string) any {
	s = strings.TrimSpace(s)
	if (strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"")) ||
		(strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'")) {
		if len(s) >= 2 {
			return s[1 : len(s)-1]
		}
	}
	lower := strings.ToLower(s)
	if lower == "true" || lower == "yes" || lower == "on" {
		return true
	}
	if lower == "false" || lower == "no" || lower == "off" {
		return false
	}
	if s == "null" || s == "~" || s == "" {
		return nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

// extractDomain 从探测地址中提取规范化的域名 (转换为小写并剔除协议、端口与路径)
func extractDomain(detect string) (string, error) {
	detect = strings.TrimSpace(detect)
	if detect == "" {
		return "", errors.New("detect 地址为空")
	}

	raw := detect
	if strings.HasPrefix(raw, "//") {
		raw = "http:" + raw
	} else {
		schemeIdx := strings.Index(raw, "://")
		firstSepIdx := strings.IndexAny(raw, "/?#")
		hasScheme := schemeIdx != -1 && (firstSepIdx == -1 || schemeIdx < firstSepIdx)
		if !hasScheme {
			raw = "http://" + raw
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("解析 detect 地址失败: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("未能从 [%s] 中提取有效主机名", detect)
	}

	host = strings.TrimSuffix(host, ".")

	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("[%s] 是 IP 地址而非域名", host)
	}

	if !strings.Contains(host, ".") {
		return "", fmt.Errorf("[%s] 不是有效域名", host)
	}

	parts := strings.Split(host, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return "", fmt.Errorf("域名标签长度不合法: [%s]", host)
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return "", fmt.Errorf("域名标签不能以短横线开头或结尾: [%s]", host)
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				return "", fmt.Errorf("域名包含非法字符 %q: [%s]", r, host)
			}
		}
	}

	return strings.ToLower(host), nil
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败 (%s): %w", path, err)
	}

	m, err := parseYAML(data)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件 YAML 失败: %w", err)
	}

	rawJSON, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("格式化配置失败: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return nil, fmt.Errorf("反序列化配置失败: %w", err)
	}

	// 环境变量覆盖
	if envToken := os.Getenv("CF_API_TOKEN"); envToken != "" {
		cfg.CF.APIToken = envToken
	}
	if envZone := os.Getenv("CF_ZONE_ID"); envZone != "" {
		cfg.CF.ZoneID = envZone
	}

	// 代理字段兼容
	if cfg.CF.Proxy == "" && cfg.CFProxy != "" {
		cfg.CF.Proxy = cfg.CFProxy
	}

	// 候选节点 DNS 同步开关兼容 (支持顶层 sync_candidate_dns 或 cf.sync_candidate_dns)
	if cfg.SyncCandidateDNS || cfg.CF.SyncCandidateDNS {
		cfg.SyncCandidateDNS = true
		cfg.CF.SyncCandidateDNS = true
	}

	// 默认参数补齐
	if cfg.LoopTime <= 0 {
		cfg.LoopTime = 10
	}

	// 合并 fail_count 和 rise_count 为 probe_count (探测次数)
	if cfg.ProbeCount <= 0 {
		if cfg.Count > 0 {
			cfg.ProbeCount = cfg.Count
		} else if cfg.FailCount > 0 {
			cfg.ProbeCount = cfg.FailCount
		} else if cfg.RiseCount > 0 {
			cfg.ProbeCount = cfg.RiseCount
		} else {
			cfg.ProbeCount = 2
		}
	}
	cfg.FailCount = cfg.ProbeCount
	cfg.RiseCount = cfg.ProbeCount

	// 探测失败重试次数 probe_retry
	if cfg.ProbeRetry <= 0 {
		if cfg.Retry > 0 {
			cfg.ProbeRetry = cfg.Retry
		} else {
			cfg.ProbeRetry = 2
		}
	}

	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 7
	}
	if cfg.CF.TTL <= 0 {
		cfg.CF.TTL = 60
	}
	if cfg.CF.RecordType == "" {
		cfg.CF.RecordType = "CNAME"
	}

	cfg.SwitchMode = strings.ToLower(strings.TrimSpace(cfg.SwitchMode))
	switch cfg.SwitchMode {
	case "", "priority", "order", "list", "顺序", "列表顺序":
		cfg.SwitchMode = string(SwitchModePriority)
	case "latency", "lowest_latency", "min_latency", "延迟", "最低延迟":
		cfg.SwitchMode = string(SwitchModeLatency)
	default:
		return nil, fmt.Errorf("不支持的切换模式 (switch_mode): %s (可选: priority / latency)", cfg.SwitchMode)
	}

	return &cfg, nil
}

// ============================================================
// HTTP 客户端构建
// ============================================================

func buildHTTPClient(proxyStr string, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// 连接池与生命周期管理: 长期运行时复用 TCP/TLS 连接, 避免连接数无限增长
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}

	if proxyStr != "" {
		proxyURL, err := url.Parse(proxyStr)
		if err != nil {
			return nil, fmt.Errorf("解析代理地址失败 (%s): %w", proxyStr, err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// drainAndCloseBody 排空并关闭响应体: 未读完的 body 会阻止 keep-alive 连接归还连接池,
// 导致每次请求都重新建立 TCP/TLS 连接, 长期运行产生海量连接
func drainAndCloseBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	_ = body.Close()
}

// ============================================================
// Failover 核心应用
// ============================================================

type FailoverApp struct {
	cfg         *Config
	cfClient    *http.Client
	probeClient *http.Client
	cfBaseURL   string

	state         []*NodeState
	dnsRecordID   string
	activeIndex   int
	initialProbed bool

	runningMu sync.Mutex
	isRunning bool
}

func NewFailoverApp(cfg *Config) (*FailoverApp, error) {
	if cfg.ProbeCount <= 0 {
		if cfg.Count > 0 {
			cfg.ProbeCount = cfg.Count
		} else if cfg.FailCount > 0 {
			cfg.ProbeCount = cfg.FailCount
		} else if cfg.RiseCount > 0 {
			cfg.ProbeCount = cfg.RiseCount
		} else {
			cfg.ProbeCount = 2
		}
	}
	cfg.FailCount = cfg.ProbeCount
	cfg.RiseCount = cfg.ProbeCount

	if cfg.ProbeRetry <= 0 {
		if cfg.Retry > 0 {
			cfg.ProbeRetry = cfg.Retry
		} else {
			cfg.ProbeRetry = 2
		}
	}

	var probeTimeout time.Duration
	if cfg.ProbeTimeout > 1000 {
		probeTimeout = time.Duration(cfg.ProbeTimeout) * time.Millisecond
	} else {
		probeTimeout = time.Duration(cfg.ProbeTimeout) * time.Second
	}

	probeClient, err := buildHTTPClient(cfg.ProbeProxy, probeTimeout)
	if err != nil {
		return nil, fmt.Errorf("初始化探测网络客户端失败: %w", err)
	}

	cfClient, err := buildHTTPClient(cfg.CF.Proxy, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("初始化 Cloudflare 网络客户端失败: %w", err)
	}

	state := make([]*NodeState, len(cfg.List))
	for i, item := range cfg.List {
		state[i] = &NodeState{
			Index:      i,
			Detect:     item.Detect,
			Value:      item.Value,
			Status:     StatusUnknown,
			OkStreak:   0,
			FailStreak: 0,
		}
	}

	return &FailoverApp{
		cfg:         cfg,
		cfClient:    cfClient,
		probeClient: probeClient,
		cfBaseURL:   "https://api.cloudflare.com/client/v4",
		state:       state,
		activeIndex: -1,
	}, nil
}

func (a *FailoverApp) cfRequest(method, path string, bodyData []byte) (*CFResponse, error, bool) {
	baseURL := a.cfBaseURL
	if baseURL == "" {
		baseURL = "https://api.cloudflare.com/client/v4"
	}
	apiURL := baseURL + path

	var bodyReader io.Reader
	if len(bodyData) > 0 {
		bodyReader = bytes.NewReader(bodyData)
	}

	req, err := http.NewRequest(method, apiURL, bodyReader)
	if err != nil {
		return nil, err, false
	}

	req.Header.Set("Authorization", "Bearer "+a.cfg.CF.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.cfClient.Do(req)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "Client.Timeout") || strings.Contains(errStr, "timeout") {
			errStr = "请求超时"
		}
		return nil, errors.New(errStr), false
	}
	respBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err, false
	}

	var cfResp CFResponse
	_ = json.Unmarshal(respBytes, &cfResp)

	isAuthError := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	var errMsgs []string
	for _, e := range cfResp.Errors {
		errMsgs = append(errMsgs, fmt.Sprintf("%d: %s", e.Code, e.Message))
		if e.Code == 10000 || e.Code == 6003 || e.Code == 9109 {
			isAuthError = true
		}
		lowerMsg := strings.ToLower(e.Message)
		if strings.Contains(lowerMsg, "auth") || strings.Contains(lowerMsg, "unauthorized") || strings.Contains(lowerMsg, "token") {
			isAuthError = true
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !cfResp.Success {
		errMsg := strings.Join(errMsgs, "; ")
		if errMsg == "" {
			errMsg = resp.Status
		}
		return nil, errors.New(errMsg), isAuthError
	}

	return &cfResp, nil, false
}

func (a *FailoverApp) fetchDnsRecordByName(name, recordType string) (*DnsRecord, error, bool) {
	qs := url.Values{}
	if recordType != "" {
		qs.Set("type", recordType)
	}
	qs.Set("name", name)

	path := fmt.Sprintf("/zones/%s/dns_records?%s", a.cfg.CF.ZoneID, qs.Encode())
	cfResp, err, isAuth := a.cfRequest("GET", path, nil)
	if err != nil {
		return nil, err, isAuth
	}

	if len(cfResp.Result) == 0 {
		if recordType != "" {
			return nil, fmt.Errorf("%w [%s]: %s (%s)", ErrRecordNotFound, a.cfg.CF.ZoneID, name, recordType), false
		}
		return nil, fmt.Errorf("%w [%s]: %s", ErrRecordNotFound, a.cfg.CF.ZoneID, name), false
	}

	return &cfResp.Result[0], nil, false
}

func (a *FailoverApp) fetchDnsRecord() (*DnsRecord, error, bool) {
	return a.fetchDnsRecordByName(a.cfg.CF.RecordName, a.cfg.CF.RecordType)
}

func (a *FailoverApp) updateDnsRecord(recordID, content string, ttl int, proxied bool) (error, bool) {
	path := fmt.Sprintf("/zones/%s/dns_records/%s", a.cfg.CF.ZoneID, recordID)
	payload := map[string]any{
		"content": content,
		"ttl":     ttl,
		"proxied": proxied,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err, false
	}

	_, err, isAuth := a.cfRequest("PATCH", path, payloadBytes)
	return err, isAuth
}

func (a *FailoverApp) patchDnsRecord(item *CandidateNode) error {
	err, _ := a.updateDnsRecord(a.dnsRecordID, item.Value, a.cfg.CF.TTL, a.cfg.CF.Proxied)
	return err
}

func (a *FailoverApp) syncCandidateDnsRecords() error {
	if !a.cfg.SyncCandidateDNS {
		return nil
	}

	seen := make(map[string]bool)
	type candidateTarget struct {
		domain    string
		candidate CandidateNode
	}
	var targets []candidateTarget

	for _, item := range a.cfg.List {
		domain, err := extractDomain(item.Detect)
		if err != nil {
			continue
		}
		if seen[domain] {
			continue
		}
		seen[domain] = true
		targets = append(targets, candidateTarget{
			domain:    domain,
			candidate: item,
		})
	}

	if len(targets) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	var authErrMu sync.Mutex
	var authErr error

	for _, t := range targets {
		wg.Add(1)
		go func(target candidateTarget) {
			defer wg.Done()

			authErrMu.Lock()
			hasAuthErr := (authErr != nil)
			authErrMu.Unlock()
			if hasAuthErr {
				return
			}

			expectedType := "CNAME"
			if ip := net.ParseIP(strings.TrimSpace(target.candidate.Value)); ip != nil {
				if ip.To4() != nil {
					expectedType = "A"
				} else {
					expectedType = "AAAA"
				}
			}

			record, err, isAuth := a.fetchDnsRecordByName(target.domain, expectedType)
			if isAuth {
				authErrMu.Lock()
				if authErr == nil {
					authErr = err
				}
				authErrMu.Unlock()
				return
			}

			if err != nil {
				if errors.Is(err, ErrRecordNotFound) {
					logInfo("警告: 未在 zone [%s] 中找到候选域名 [%s] 的 DNS 记录, 跳过更新", a.cfg.CF.ZoneID, target.domain)
				} else {
					logInfo("查询候选域名 [%s] DNS 记录失败: %s", target.domain, err.Error())
				}
				return
			}

			ipRecord := net.ParseIP(strings.TrimSpace(record.Content))
			ipCandidate := net.ParseIP(strings.TrimSpace(target.candidate.Value))
			equal := false
			if ipRecord != nil && ipCandidate != nil {
				equal = ipRecord.Equal(ipCandidate)
			} else {
				equal = strings.EqualFold(strings.TrimSpace(record.Content), strings.TrimSpace(target.candidate.Value))
			}

			if equal {
				logInfo("候选域名 [%s] DNS 记录已对等 (%s), 无需更新", target.domain, record.Content)
				return
			}

			updateErr, updateIsAuth := a.updateDnsRecord(record.ID, target.candidate.Value, record.TTL, record.Proxied)
			if updateIsAuth {
				authErrMu.Lock()
				if authErr == nil {
					authErr = updateErr
				}
				authErrMu.Unlock()
				return
			}
			if updateErr != nil {
				logInfo("更新候选域名 [%s] DNS 记录失败: %s", target.domain, updateErr.Error())
				return
			}

			logInfo("候选域名 [%s] DNS 记录已更新: %s -> %s", target.domain, record.Content, target.candidate.Value)
		}(t)
	}

	wg.Wait()

	if authErr != nil {
		return authErr
	}
	return nil
}

func (a *FailoverApp) initPrimaryRecord() error {
	for {
		record, err, isAuth := a.fetchDnsRecord()
		if err == nil {
			a.dnsRecordID = record.ID
			a.activeIndex = -1
			for i, s := range a.state {
				if s.Value == record.Content {
					a.activeIndex = i
					logInfo("当前 DNS 记录指向候选 [%d] %s -> %s", i+1, a.cfg.CF.RecordName, record.Content)
					break
				}
			}
			if a.activeIndex == -1 {
				logInfo("当前 DNS 记录指向未知候选 %s -> %s", a.cfg.CF.RecordName, record.Content)
			}
			return nil
		}

		logInfo("查询 DNS 记录失败: %s", err.Error())
		if isAuth || errors.Is(err, ErrRecordNotFound) {
			return err
		}

		time.Sleep(5 * time.Second)
	}
}

func (a *FailoverApp) Initialize() error {
	var wg sync.WaitGroup
	var primaryErr error
	var candidateErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		primaryErr = a.initPrimaryRecord()
	}()

	if a.cfg.SyncCandidateDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidateErr = a.syncCandidateDnsRecords()
		}()
	}

	wg.Wait()

	if primaryErr != nil {
		return primaryErr
	}
	if candidateErr != nil {
		return candidateErr
	}
	return nil
}

type probeResult struct {
	ok       bool
	status   int
	duration int64
	errStr   string
}

func (a *FailoverApp) probeNodeOnce(s *NodeState) probeResult {
	start := time.Now()
	resp, err := a.probeClient.Get(s.Detect)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "Client.Timeout") || strings.Contains(errStr, "timeout") {
			errStr = "请求超时"
		}
		return probeResult{
			ok:       false,
			status:   0,
			duration: duration,
			errStr:   errStr,
		}
	}
	drainAndCloseBody(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return probeResult{
			ok:       true,
			status:   resp.StatusCode,
			duration: duration,
		}
	}

	return probeResult{
		ok:       false,
		status:   resp.StatusCode,
		duration: duration,
		errStr:   fmt.Sprintf("HTTP %d", resp.StatusCode),
	}
}

func (a *FailoverApp) probeNode(s *NodeState) probeResult {
	maxTries := a.cfg.ProbeRetry
	if maxTries <= 0 {
		maxTries = 1
	}

	var lastRes probeResult
	for attempt := 1; attempt <= maxTries; attempt++ {
		res := a.probeNodeOnce(s)
		if res.ok {
			return res
		}
		lastRes = res
		// 失败退避: 节点不可达时立即重试只会在短窗口内高频建立连接, 逐次递增等待缓解连接风暴
		if attempt < maxTries {
			time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
		}
	}
	return lastRes
}

func (a *FailoverApp) applyProbeResult(s *NodeState, res probeResult) bool {
	statusChanged := false
	s.LastDuration = res.duration

	if res.ok {
		s.OkStreak++
		s.FailStreak = 0
		s.LastError = ""

		if s.Status != StatusHealthy && s.OkStreak >= a.cfg.ProbeCount {
			s.Status = StatusHealthy
			statusChanged = true
		}
	} else {
		s.FailStreak++
		s.OkStreak = 0
		s.LastError = res.errStr

		if s.Status == StatusHealthy && s.FailStreak >= a.cfg.ProbeCount {
			s.Status = StatusUnhealthy
			statusChanged = true
		} else if s.Status == StatusUnknown && s.FailStreak >= a.cfg.ProbeCount {
			s.Status = StatusUnhealthy
			statusChanged = true
		}
	}

	return statusChanged
}

func (a *FailoverApp) printInitialStatus() {
	var lines []string
	lines = append(lines, fmt.Sprintf("[%s] 初始候选状态", nowTime()))
	for _, s := range a.state {
		sign := "-"
		suffix := s.LastError
		if s.Status == StatusHealthy {
			sign = "+"
			suffix = fmt.Sprintf("%dms", s.LastDuration)
		} else if suffix == "" {
			suffix = "未就绪"
		}
		lines = append(lines, fmt.Sprintf("  - [%s] [%d] %s -> %s - %s",
			sign, s.Index+1, s.Detect, s.Value, suffix))
	}
	fmt.Print(strings.Join(lines, "\n") + "\n\n")
}

func (a *FailoverApp) printStatusChangeWithTarget(targetIndex int) {
	target := a.state[targetIndex]
	var lines []string
	lines = append(lines, fmt.Sprintf("[%s] 候选状态变更, 切换到候选 [%d] %s -> %s",
		nowTime(), targetIndex+1, a.cfg.CF.RecordName, target.Value))
	for _, s := range a.state {
		sign := "-"
		suffix := s.LastError
		if s.Status == StatusHealthy {
			sign = "+"
			suffix = fmt.Sprintf("%dms", s.LastDuration)
		} else if suffix == "" {
			suffix = "未就绪"
		}
		lines = append(lines, fmt.Sprintf("  - [%s] [%d] %s -> %s - %s",
			sign, s.Index+1, s.Detect, s.Value, suffix))
	}
	fmt.Print(strings.Join(lines, "\n") + "\n\n")
}

func (a *FailoverApp) evaluateTarget() Decision {
	if a.cfg.SwitchMode == string(SwitchModeLatency) {
		bestIndex := -1
		var minLatency int64 = -1

		for i, s := range a.state {
			if s.Status == StatusHealthy {
				if bestIndex == -1 || s.LastDuration < minLatency {
					bestIndex = i
					minLatency = s.LastDuration
				}
			}
		}

		if bestIndex == -1 {
			return Decision{TargetIndex: -1}
		}

		if a.activeIndex != -1 && a.state[a.activeIndex].Status == StatusHealthy {
			if a.state[a.activeIndex].LastDuration <= minLatency {
				return Decision{TargetIndex: a.activeIndex}
			}
			return Decision{TargetIndex: bestIndex}
		}

		return Decision{TargetIndex: bestIndex}
	}

	healthyIndex := -1
	for i, s := range a.state {
		if s.Status == StatusHealthy {
			healthyIndex = i
			break
		}
	}

	// 1. 当前活跃候选仍健康: 仅当更高优先级的候选确认就绪时才执行回切抢占
	if a.activeIndex != -1 && a.state[a.activeIndex].Status == StatusHealthy {
		if healthyIndex != -1 && healthyIndex < a.activeIndex {
			return Decision{TargetIndex: healthyIndex}
		}
		return Decision{TargetIndex: a.activeIndex}
	}

	// 2. 当前活跃节点不可用或冷启动尚未绑定: 选择当前最高优先级的已就绪健康候选
	if healthyIndex != -1 {
		return Decision{TargetIndex: healthyIndex}
	}

	// 3. 所有候选均无就绪健康节点: 保持现状
	return Decision{TargetIndex: -1}
}

func (a *FailoverApp) switchTo(targetIndex int) {
	// 仅在发生切换候选时打印一次候选状态变更
	a.printStatusChangeWithTarget(targetIndex)

	target := a.state[targetIndex]
	item := &CandidateNode{
		Detect: target.Detect,
		Value:  target.Value,
	}

	maxRetries := 3
	var patchErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		patchErr = a.patchDnsRecord(item)
		if patchErr == nil {
			a.activeIndex = targetIndex
			return // 切换成功不打印消息，静默成功
		}
		if attempt < maxRetries {
			time.Sleep(1 * time.Second)
		}
	}

	// 切换失败打印错误日志
	logInfo("切换候选失败: %s", patchErr.Error())
}

func (a *FailoverApp) RunCycle() {
	a.runningMu.Lock()
	if a.isRunning {
		a.runningMu.Unlock()
		return
	}
	a.isRunning = true
	a.runningMu.Unlock()

	defer func() {
		a.runningMu.Lock()
		a.isRunning = false
		a.runningMu.Unlock()
	}()

	var wg sync.WaitGroup
	results := make([]probeResult, len(a.state))
	for i, s := range a.state {
		wg.Add(1)
		go func(idx int, node *NodeState) {
			defer wg.Done()
			results[idx] = a.probeNode(node)
		}(i, s)
	}
	wg.Wait()

	if !a.initialProbed {
		// 初始候选状态为启动后的第一次探测结果, 不遵循 fail_count/rise_count, 每个节点各完成第一次探测时即可打印
		for i, s := range a.state {
			res := results[i]
			s.LastDuration = res.duration
			if res.ok {
				s.Status = StatusHealthy
				s.OkStreak = 1
				s.FailStreak = 0
				s.LastError = ""
			} else {
				s.Status = StatusUnhealthy
				s.OkStreak = 0
				s.FailStreak = 1
				s.LastError = res.errStr
			}
		}
		a.initialProbed = true
		a.printInitialStatus()
	} else {
		// 后续探测周期遵循 fail_count / rise_count
		for i, s := range a.state {
			a.applyProbeResult(s, results[i])
		}
	}

	decision := a.evaluateTarget()
	if decision.TargetIndex == -1 {
		return
	}

	if decision.TargetIndex != a.activeIndex {
		a.switchTo(decision.TargetIndex)
	}
}

// ============================================================
// 程序入口
// ============================================================

func main() {
	configPath := flag.String("c", "config.yml", "配置文件路径 (config.yml)")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logInfo("加载配置文件失败: %v", err)
		os.Exit(1)
	}

	logInfo("启动 cf-dns-failover: loop_time=%ds probe_count=%d probe_retry=%d sync_candidate_dns=%v 候选数=%d",
		cfg.LoopTime, cfg.ProbeCount, cfg.ProbeRetry, cfg.SyncCandidateDNS, len(cfg.List))

	app, err := NewFailoverApp(cfg)
	if err != nil {
		logInfo("初始化应用失败: %v", err)
		os.Exit(1)
	}

	if err := app.Initialize(); err != nil {
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	app.RunCycle()

	ticker := time.NewTicker(time.Duration(cfg.LoopTime) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			app.RunCycle()
		case <-ctx.Done():
			return
		}
	}
}

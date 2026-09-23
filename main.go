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
	LoopTime     int             `json:"loop_time"`
	ProbeCount   int             `json:"probe_count"`
	ProbeRetry   int             `json:"probe_retry"`
	ProbeTimeout int             `json:"probe_timeout"`
	ProbeProxy   string          `json:"probe_proxy"`
	CFProxy      string          `json:"cf_proxy"`
	SwitchMode   string          `json:"switch_mode"`
	CF           CFConfig        `json:"cf"`
	List         []CandidateNode `json:"list"`

	// 兼容旧版及别名配置字段
	Count     int `json:"count"`
	FailCount int `json:"fail_count"`
	RiseCount int `json:"rise_count"`
	Retry     int `json:"retry"`
}

type CFConfig struct {
	APIToken   string `json:"api_token"`
	ZoneID     string `json:"zone_id"`
	RecordName string `json:"record_name"`
	RecordType string `json:"record_type"`
	TTL        int    `json:"ttl"`
	Proxied    bool   `json:"proxied"`
	Proxy      string `json:"proxy"`
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
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var res map[string]any
		err := json.Unmarshal(content, &res)
		return res, err
	}

	var lines []lineInfo
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		raw := scanner.Text()
		clean := stripComment(raw)
		if strings.TrimSpace(clean) == "" {
			continue
		}
		clean = strings.ReplaceAll(clean, "\t", "  ")
		indent := len(clean) - len(strings.TrimLeft(clean, " "))
		text := strings.TrimSpace(clean)
		lines = append(lines, lineInfo{indent: indent, text: text})
	}

	if len(lines) == 0 {
		return make(map[string]any), nil
	}

	root := make(map[string]any)
	_, err := parseMapping(lines, 0, 0, root)
	return root, err
}

func stripComment(s string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		} else if c == '#' && !inSingle && !inDouble {
			return s[:i]
		}
	}
	return s
}

func parseMapping(lines []lineInfo, startIdx int, minIndent int, target map[string]any) (int, error) {
	idx := startIdx
	for idx < len(lines) {
		line := lines[idx]
		if line.indent < minIndent {
			break
		}
		if line.indent > minIndent && minIndent != 0 {
			break
		}

		colonPos := strings.Index(line.text, ":")
		if colonPos == -1 {
			idx++
			continue
		}

		key := strings.TrimSpace(line.text[:colonPos])
		valPart := strings.TrimSpace(line.text[colonPos+1:])

		if valPart != "" {
			target[key] = parseScalar(valPart)
			idx++
		} else {
			if idx+1 >= len(lines) {
				target[key] = nil
				idx++
				break
			}
			nextLine := lines[idx+1]
			if nextLine.indent <= line.indent {
				target[key] = nil
				idx++
				continue
			}

			if strings.HasPrefix(nextLine.text, "- ") || nextLine.text == "-" {
				var list []any
				nextIdx, err := parseSequence(lines, idx+1, nextLine.indent, &list)
				if err != nil {
					return idx, err
				}
				target[key] = list
				idx = nextIdx
			} else {
				subMap := make(map[string]any)
				nextIdx, err := parseMapping(lines, idx+1, nextLine.indent, subMap)
				if err != nil {
					return idx, err
				}
				target[key] = subMap
				idx = nextIdx
			}
		}
	}
	return idx, nil
}

func parseSequence(lines []lineInfo, startIdx int, seqIndent int, list *[]any) (int, error) {
	idx := startIdx
	for idx < len(lines) {
		line := lines[idx]
		if line.indent < seqIndent {
			break
		}
		if !strings.HasPrefix(line.text, "-") {
			break
		}

		content := strings.TrimSpace(line.text[1:])
		if content == "" {
			if idx+1 < len(lines) && lines[idx+1].indent > line.indent {
				subMap := make(map[string]any)
				nextIdx, err := parseMapping(lines, idx+1, lines[idx+1].indent, subMap)
				if err != nil {
					return idx, err
				}
				*list = append(*list, subMap)
				idx = nextIdx
			} else {
				*list = append(*list, nil)
				idx++
			}
		} else if strings.Contains(content, ":") {
			itemMap := make(map[string]any)
			colonPos := strings.Index(content, ":")
			subKey := strings.TrimSpace(content[:colonPos])
			subVal := strings.TrimSpace(content[colonPos+1:])
			if subVal != "" {
				itemMap[subKey] = parseScalar(subVal)
			} else {
				itemMap[subKey] = nil
			}

			nextIdx := idx + 1
			itemIndent := -1
			for nextIdx < len(lines) {
				nLine := lines[nextIdx]
				if nLine.indent <= seqIndent {
					break
				}
				if itemIndent == -1 {
					itemIndent = nLine.indent
				}
				if nLine.indent < itemIndent {
					break
				}
				subColon := strings.Index(nLine.text, ":")
				if subColon != -1 {
					k := strings.TrimSpace(nLine.text[:subColon])
					v := strings.TrimSpace(nLine.text[subColon+1:])
					itemMap[k] = parseScalar(v)
				}
				nextIdx++
			}
			*list = append(*list, itemMap)
			idx = nextIdx
		} else {
			*list = append(*list, parseScalar(content))
			idx++
		}
	}
	return idx, nil
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

// ============================================================
// Failover 核心应用
// ============================================================

type FailoverApp struct {
	cfg         *Config
	cfClient    *http.Client
	probeClient *http.Client

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
		state:       state,
		activeIndex: -1,
	}, nil
}

func (a *FailoverApp) cfRequest(method, path string, bodyData []byte) (*CFResponse, error, bool) {
	apiURL := "https://api.cloudflare.com/client/v4" + path

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
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
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

func (a *FailoverApp) fetchDnsRecord() (*DnsRecord, error, bool) {
	qs := url.Values{}
	qs.Set("type", a.cfg.CF.RecordType)
	qs.Set("name", a.cfg.CF.RecordName)

	path := fmt.Sprintf("/zones/%s/dns_records?%s", a.cfg.CF.ZoneID, qs.Encode())
	cfResp, err, isAuth := a.cfRequest("GET", path, nil)
	if err != nil {
		return nil, err, isAuth
	}

	if len(cfResp.Result) == 0 {
		return nil, fmt.Errorf("未在 zone [%s] 中找到记录: %s (%s)",
			a.cfg.CF.ZoneID, a.cfg.CF.RecordName, a.cfg.CF.RecordType), false
	}

	return &cfResp.Result[0], nil, false
}

func (a *FailoverApp) patchDnsRecord(item *CandidateNode) error {
	path := fmt.Sprintf("/zones/%s/dns_records/%s", a.cfg.CF.ZoneID, a.dnsRecordID)
	payload := map[string]any{
		"content": item.Value,
		"ttl":     a.cfg.CF.TTL,
		"proxied": a.cfg.CF.Proxied,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err, _ = a.cfRequest("PATCH", path, payloadBytes)
	return err
}

func (a *FailoverApp) Initialize() error {
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
		if isAuth {
			return err
		}

		time.Sleep(5 * time.Second)
	}
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
	defer resp.Body.Close()

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

	logInfo("启动 cf-dns-failover: loop_time=%ds probe_count=%d probe_retry=%d 候选数=%d",
		cfg.LoopTime, cfg.ProbeCount, cfg.ProbeRetry, len(cfg.List))

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

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtractDomain_Valid(t *testing.T) {
	tests := []struct {
		detect string
		want   string
	}{
		{detect: "https://xx1.xxx.cc", want: "xx1.xxx.cc"},
		{detect: "http://xx1.xxx.cc", want: "xx1.xxx.cc"},
		{detect: "http://xx1.xxx.cc:8080", want: "xx1.xxx.cc"},
		{detect: "https://xx1.xxx.cc:443/health", want: "xx1.xxx.cc"},
		{detect: "https://xx1.xxx.cc:8080/path/to/check?query=1#hash", want: "xx1.xxx.cc"},
		{detect: "xx1.xxx.cc", want: "xx1.xxx.cc"},
		{detect: "xx1.xxx.cc:8080", want: "xx1.xxx.cc"},
		{detect: "xx1.xxx.cc/path", want: "xx1.xxx.cc"},
		{detect: "xx1.xxx.cc:8080/path", want: "xx1.xxx.cc"},
		{detect: "//xx1.xxx.cc", want: "xx1.xxx.cc"},
		{detect: "  HTTPS://XX1.XXX.CC/  ", want: "xx1.xxx.cc"},
		{detect: "sub-node.example.com", want: "sub-node.example.com"},
		{detect: "sub_node.example.com", want: "sub_node.example.com"},
		{detect: "node1.sub.example.com.", want: "node1.sub.example.com"},
		{detect: "https://my.domain.cn:9000/api", want: "my.domain.cn"},
		{detect: "my.domain.cn/path?url=https://other.com", want: "my.domain.cn"},
		{detect: "my.domain.cn:8080/path?url=ftp://files.org#anchor://test", want: "my.domain.cn"},
	}
	for _, tc := range tests {
		got, err := extractDomain(tc.detect)
		if err != nil {
			t.Errorf("extractDomain(%q) 期望成功，但返回错误: %v", tc.detect, err)
			continue
		}
		if got != tc.want {
			t.Errorf("extractDomain(%q) = %q, 期望 %q", tc.detect, got, tc.want)
		}
	}
}

func TestExtractDomain_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		detect string
	}{
		{name: "空字符串", detect: ""},
		{name: "纯空格", detect: "   "},
		{name: "只有协议", detect: "http://"},
		{name: "协议加根路径", detect: "http:///"},
		{name: "IPv4 直连", detect: "192.168.1.1"},
		{name: "IPv4 带协议", detect: "http://192.168.1.1"},
		{name: "IPv4 带端口", detect: "http://192.168.1.1:8080"},
		{name: "IPv4 带路径", detect: "http://192.168.1.1/path"},
		{name: "IPv6 括号格式", detect: "[2001:db8::1]"},
		{name: "IPv6 带协议端口", detect: "http://[2001:db8::1]:8080"},
		{name: "无顶级域名单标签", detect: "localhost"},
		{name: "带协议的 localhost", detect: "http://localhost:8080"},
		{name: "单域名无点", detect: "myserver"},
		{name: "标签以短横线开头", detect: "-invalid.example.com"},
		{name: "标签以短横线结尾", detect: "invalid-.example.com"},
		{name: "连续点空标签", detect: "invalid..example.com"},
		{name: "包含空格的非法字符", detect: "http://bad host.com"},
		{name: "超长标签", detect: strings.Repeat("a", 64) + ".com"},
	}

	for _, tc := range tests {
		got, err := extractDomain(tc.detect)
		if err == nil {
			t.Errorf("extractDomain(%q) [%s] 期望返回错误，但得到了: %q", tc.detect, tc.name, got)
		}
	}
}

func writeTempConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test_config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("创建临时测试配置文件失败: %v", err)
	}
	return path
}

func TestLoadConfig_SyncCandidateDNS_TopLevel(t *testing.T) {
	content := `
loop_time: 5
sync_candidate_dns: true
cf:
  record_name: "test.example.com"
  record_type: "CNAME"
list:
  - detect: "https://node1.example.com"
    value: "target1.com"
`
	path := writeTempConfigFile(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}

	if !cfg.SyncCandidateDNS {
		t.Errorf("期望 cfg.SyncCandidateDNS 为 true, 实际为 false")
	}
	if !cfg.CF.SyncCandidateDNS {
		t.Errorf("期望 cfg.CF.SyncCandidateDNS 兼容设置为 true, 实际为 false")
	}
}

func TestLoadConfig_SyncCandidateDNS_InCFBlock(t *testing.T) {
	content := `
loop_time: 5
cf:
  record_name: "test.example.com"
  record_type: "CNAME"
  sync_candidate_dns: true
list:
  - detect: "https://node1.example.com"
    value: "target1.com"
`
	path := writeTempConfigFile(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}

	if !cfg.CF.SyncCandidateDNS {
		t.Errorf("期望 cfg.CF.SyncCandidateDNS 为 true, 实际为 false")
	}
	if !cfg.SyncCandidateDNS {
		t.Errorf("期望 cfg.SyncCandidateDNS 兼容设置为 true, 实际为 false")
	}
}

func TestLoadConfig_SyncCandidateDNS_BothTrue(t *testing.T) {
	content := `
sync_candidate_dns: true
cf:
  record_name: "test.example.com"
  sync_candidate_dns: true
`
	path := writeTempConfigFile(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}

	if !cfg.SyncCandidateDNS || !cfg.CF.SyncCandidateDNS {
		t.Errorf("期望配置两处均为 true")
	}
}

func TestLoadConfig_SyncCandidateDNS_DefaultFalse(t *testing.T) {
	content := `
loop_time: 5
cf:
  record_name: "test.example.com"
`
	path := writeTempConfigFile(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}

	if cfg.SyncCandidateDNS {
		t.Errorf("期望 cfg.SyncCandidateDNS 默认为 false, 实际为 true")
	}
	if cfg.CF.SyncCandidateDNS {
		t.Errorf("期望 cfg.CF.SyncCandidateDNS 默认为 false, 实际为 true")
	}
}
func TestLoadConfig_RealConfigFile(t *testing.T) {
	cfg, err := loadConfig("config.yml")
	if err != nil {
		t.Fatalf("加载 config.yml 失败: %v", err)
	}
	if len(cfg.List) != 2 {
		t.Errorf("期望候选列表包含 2 个节点, 实际为 %d", len(cfg.List))
	}
	if cfg.List[0].Detect != "https://xx1.xxx.cc" || cfg.List[0].Value != "frp1.cc" {
		t.Errorf("候选节点 0 解析不符合预期: %+v", cfg.List[0])
	}
	if cfg.List[1].Detect != "https://xx2.xxx.cc" || cfg.List[1].Value != "frp2.cc" {
		t.Errorf("候选节点 1 解析不符合预期: %+v", cfg.List[1])
	}
	if cfg.CF.RecordName != "xxx.xxx.cc" {
		t.Errorf("cfg.CF.RecordName 期望为 xxx.xxx.cc, 实际为 %s", cfg.CF.RecordName)
	}
	if cfg.SwitchMode != "stability,latency,priority" {
		t.Errorf("cfg.SwitchMode 期望为 stability,latency,priority, 实际为 %s", cfg.SwitchMode)
	}
	if cfg.StabilityWindow != 30 {
		t.Errorf("cfg.StabilityWindow 期望为 30, 实际为 %d", cfg.StabilityWindow)
	}
}

func TestSyncCandidateDnsRecords_Disabled(t *testing.T) {
	cfg := &Config{
		SyncCandidateDNS: false,
		List: []CandidateNode{
			{Detect: "https://node1.example.com", Value: "target1.com"},
		},
	}
	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = "http://127.0.0.1:0"

	if err := app.syncCandidateDnsRecords(); err != nil {
		t.Errorf("未开启 sync_candidate_dns 时期望直接返回 nil, 实际为: %v", err)
	}
}
func TestFetchDnsRecordByName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		recType := r.URL.Query().Get("type")

		if name == "auth-fail.example.com" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: false,
				Errors:  []CFError{{Code: 10000, Message: "Authentication error"}},
			})
			return
		}

		if name == "missing.example.com" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: true,
				Result:  []DnsRecord{},
			})
			return
		}

		if name == "found.example.com" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: true,
				Result: []DnsRecord{
					{
						ID:      "rec-123",
						Name:    name,
						Type:    recType,
						Content: "target.com",
						TTL:     60,
						Proxied: false,
					},
				},
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &Config{
		CF: CFConfig{
			ZoneID:     "test-zone",
			RecordName: "found.example.com",
			RecordType: "CNAME",
			APIToken:   "test-token",
		},
	}
	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	// 1. 查询存在的记录
	rec, err, isAuth := app.fetchDnsRecordByName("found.example.com", "CNAME")
	if err != nil || isAuth {
		t.Fatalf("期望成功获取记录，但返回错误: %v, isAuth=%v", err, isAuth)
	}
	if rec.ID != "rec-123" || rec.Content != "target.com" {
		t.Errorf("获取记录内容不符合预期: %+v", rec)
	}

	// 2. 查询不存在的记录
	_, err, isAuth = app.fetchDnsRecordByName("missing.example.com", "CNAME")
	if err == nil {
		t.Fatalf("期望不存在记录返回错误，但返回成功")
	}
	if !errors.Is(err, ErrRecordNotFound) {
		t.Errorf("期望错误满足 errors.Is(err, ErrRecordNotFound), 实际为: %v", err)
	}
	if isAuth {
		t.Errorf("不存在记录不应被标记为鉴权错误")
	}

	// 3. 鉴权失败
	_, err, isAuth = app.fetchDnsRecordByName("auth-fail.example.com", "CNAME")
	if err == nil || !isAuth {
		t.Errorf("期望鉴权错误返回 isAuth=true, 实际 isAuth=%v, err=%v", isAuth, err)
	}
}

func TestUpdateDnsRecord(t *testing.T) {
	var receivedContent string
	var receivedTTL int
	var receivedProxied bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" && strings.Contains(r.URL.Path, "/dns_records/rec-456") {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if c, ok := body["content"].(string); ok {
				receivedContent = c
			}
			if ttl, ok := body["ttl"].(float64); ok {
				receivedTTL = int(ttl)
			}
			if p, ok := body["proxied"].(bool); ok {
				receivedProxied = p
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{Success: true})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := &Config{
		CF: CFConfig{
			ZoneID:   "test-zone",
			APIToken: "test-token",
		},
	}
	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	err, isAuth := app.updateDnsRecord("rec-456", "new-target.com", 120, true)
	if err != nil || isAuth {
		t.Fatalf("updateDnsRecord 失败: %v (isAuth=%v)", err, isAuth)
	}
	if receivedContent != "new-target.com" || receivedTTL != 120 || !receivedProxied {
		t.Errorf("更新内容不符合预期: content=%s, ttl=%d, proxied=%v", receivedContent, receivedTTL, receivedProxied)
	}
}

func TestSyncCandidateDnsRecords(t *testing.T) {
	var patchCount int32
	var updatedDomains []string
	var queriesCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/dns_records") {
			atomic.AddInt32(&queriesCount, 1)
			name := r.URL.Query().Get("name")

			switch name {
			case "node1.example.com":
				// 记录内容与配置相同
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(CFResponse{
					Success: true,
					Result: []DnsRecord{
						{ID: "rec-node1", Name: name, Content: "target1.com", Type: "CNAME"},
					},
				})
			case "node2.example.com":
				// 记录内容与配置不同 (旧值 old-target2.com -> 应更新为 target2.com)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(CFResponse{
					Success: true,
					Result: []DnsRecord{
						{ID: "rec-node2", Name: name, Content: "old-target2.com", Type: "CNAME"},
					},
				})
			case "missing.example.com":
				// 记录未找到
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(CFResponse{
					Success: true,
					Result:  []DnsRecord{},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}

		if r.Method == "PATCH" && strings.Contains(r.URL.Path, "/dns_records/rec-node2") {
			atomic.AddInt32(&patchCount, 1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if c, ok := body["content"].(string); ok {
				updatedDomains = append(updatedDomains, c)
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{Success: true})
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	cfg := &Config{
		SyncCandidateDNS: true,
		CF: CFConfig{
			ZoneID:     "zone-123",
			RecordName: "main.example.com",
			RecordType: "CNAME",
			APIToken:   "token",
			TTL:        60,
			Proxied:    false,
		},
		List: []CandidateNode{
			// 对等：应跳过更新
			{Detect: "https://node1.example.com:8080/health", Value: "target1.com"},
			// 不对等：应触发更新
			{Detect: "http://node2.example.com/check", Value: "target2.com"},
			// 重复域名：应自动去重，不重复发起探测
			{Detect: "https://node2.example.com/another", Value: "target2.com"},
			// 记录未找到：应跳过更新并打印警告
			{Detect: "https://missing.example.com", Value: "missing-target.com"},
			// IP 地址候选：应跳过
			{Detect: "http://192.168.1.100:8080", Value: "192.168.1.100"},
			// 非法地址：应跳过
			{Detect: "   ", Value: "bad"},
		},
	}

	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	err = app.syncCandidateDnsRecords()
	if err != nil {
		t.Fatalf("syncCandidateDnsRecords 期望成功，但返回错误: %v", err)
	}

	// 期望只对 node1, node2, missing 发起探测 (共 3 次，node2 去重，IP 与非法地址跳过)
	if queries := atomic.LoadInt32(&queriesCount); queries != 3 {
		t.Errorf("期望发起 3 次探测查询, 实际发起 %d 次", queries)
	}

	// 期望只有 node2 被 PATCH 更新 1 次
	if patches := atomic.LoadInt32(&patchCount); patches != 1 {
		t.Errorf("期望更新 1 次，实际更新 %d 次", patches)
	}

	if len(updatedDomains) > 0 && updatedDomains[0] != "target2.com" {
		t.Errorf("更新值期望为 target2.com, 实际为 %v", updatedDomains)
	}
}

func TestSyncCandidateDnsRecords_AuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(CFResponse{
			Success: false,
			Errors:  []CFError{{Code: 10000, Message: "Authentication error"}},
		})
	}))
	defer server.Close()

	cfg := &Config{
		SyncCandidateDNS: true,
		CF: CFConfig{
			ZoneID:     "zone-123",
			RecordName: "main.example.com",
			RecordType: "CNAME",
			APIToken:   "bad-token",
		},
		List: []CandidateNode{
			{Detect: "https://node1.example.com", Value: "target1.com"},
		},
	}

	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	err = app.syncCandidateDnsRecords()
	if err == nil {
		t.Fatalf("期望鉴权错误时立即返回错误，但返回了 nil")
	}
}

func TestInitialize_Concurrent(t *testing.T) {
	primaryProbed := make(chan struct{})
	candidateProbed := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "main.example.com" {
			close(primaryProbed)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: true,
				Result: []DnsRecord{
					{ID: "rec-main", Name: name, Content: "target1.com", Type: "CNAME"},
				},
			})
			return
		}
		if name == "candidate.example.com" {
			close(candidateProbed)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: true,
				Result: []DnsRecord{
					{ID: "rec-cand", Name: name, Content: "target1.com", Type: "CNAME"},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := &Config{
		SyncCandidateDNS: true,
		CF: CFConfig{
			ZoneID:     "zone-123",
			RecordName: "main.example.com",
			RecordType: "CNAME",
			APIToken:   "token",
		},
		List: []CandidateNode{
			{Detect: "https://candidate.example.com", Value: "target1.com"},
		},
	}

	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	initErrCh := make(chan error, 1)
	go func() {
		initErrCh <- app.Initialize()
	}()

	select {
	case <-primaryProbed:
	case <-time.After(2 * time.Second):
		t.Fatal("超时: primary 未被探测")
	}

	select {
	case <-candidateProbed:
	case <-time.After(2 * time.Second):
		t.Fatal("超时: candidate 未被探测")
	}

	select {
	case err := <-initErrCh:
		if err != nil {
			t.Fatalf("Initialize 期望成功，但返回错误: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("超时: Initialize 未能按时完成")
	}

	if app.dnsRecordID != "rec-main" {
		t.Errorf("dnsRecordID 期望为 rec-main, 实际为 %s", app.dnsRecordID)
	}
	if app.activeIndex != 0 {
		t.Errorf("activeIndex 期望为 0, 实际为 %d", app.activeIndex)
	}
}

func TestParseYAML_JSONFastPath(t *testing.T) {
	jsonContent := `{"cf": {"zone_id": "zone-123", "record_name": "test.com"}, "probe_interval": 10}`
	m, err := parseYAML([]byte(jsonContent))
	if err != nil {
		t.Fatalf("parseYAML 解析 JSON 失败: %v", err)
	}
	cf, ok := m["cf"].(map[string]any)
	if !ok || cf["zone_id"] != "zone-123" {
		t.Fatalf("解析得到的 zone_id 不符合预期: %v", m)
	}
}

func TestParseYAML_TabIndentation(t *testing.T) {
	yamlWithTabs := "cf:\n\tzone_id: zone-tab\n\trecord_name: tab.example.com\nlist:\n\t- detect: http://tab.example.com\n\t  value: 1.1.1.1\n"
	m, err := parseYAML([]byte(yamlWithTabs))
	if err != nil {
		t.Fatalf("parseYAML 解析含 tab 失败: %v", err)
	}
	cf, ok := m["cf"].(map[string]any)
	if !ok || cf["zone_id"] != "zone-tab" {
		t.Fatalf("zone_id 解析不符合预期: %v", m)
	}
}

func TestInitPrimaryRecord_NotFoundExitsImmediately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(CFResponse{
			Success: true,
			Result:  []DnsRecord{},
		})
	}))
	defer server.Close()

	cfg := &Config{
		CF: CFConfig{
			ZoneID:     "zone-123",
			RecordName: "notfound.example.com",
			RecordType: "A",
			APIToken:   "token",
		},
		List: []CandidateNode{
			{Detect: "http://example.com", Value: "1.1.1.1"},
		},
	}
	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	done := make(chan error, 1)
	go func() {
		done <- app.initPrimaryRecord()
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrRecordNotFound) {
			t.Fatalf("期望 ErrRecordNotFound, 实际: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("initPrimaryRecord 在 ErrRecordNotFound 时未立即退出，发生死循环或超时")
	}
}

func TestSyncCandidateDnsRecords_TypeInferenceAndPreserveSettings(t *testing.T) {
	var patchedBody map[string]any
	var queriedType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/dns_records") {
			queriedType = r.URL.Query().Get("type")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: true,
				Result: []DnsRecord{
					{
						ID:      "rec-node-ipv4",
						Name:    "node-ipv4.example.com",
						Type:    "A",
						Content: "1.2.3.4",
						TTL:     300,
						Proxied: false,
					},
				},
			})
			return
		}
		if r.Method == "PATCH" && strings.Contains(r.URL.Path, "/dns_records/rec-node-ipv4") {
			_ = json.NewDecoder(r.Body).Decode(&patchedBody)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{Success: true})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	cfg := &Config{
		SyncCandidateDNS: true,
		CF: CFConfig{
			ZoneID:     "zone-123",
			RecordName: "main.example.com",
			RecordType: "CNAME", // 主域名是 CNAME，Proxied 为 true
			APIToken:   "token",
			TTL:        60,
			Proxied:    true,
		},
		List: []CandidateNode{
			// 候选值是 IPv4，推断类型应为 A；且更新时应保留原记录的 TTL=300 和 Proxied=false，而非主域名的 60 和 true
			{Detect: "http://node-ipv4.example.com", Value: "1.2.3.5"},
		},
	}

	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	err = app.syncCandidateDnsRecords()
	if err != nil {
		t.Fatalf("syncCandidateDnsRecords 失败: %v", err)
	}

	if queriedType != "A" {
		t.Errorf("查询类型推断错误: 期望 A, 实际为 %s", queriedType)
	}
	if patchedBody["content"] != "1.2.3.5" {
		t.Errorf("更新内容错误: %v", patchedBody["content"])
	}
	// 保留候选节点自身的 TTL=300 和 Proxied=false
	if int(patchedBody["ttl"].(float64)) != 300 {
		t.Errorf("TTL 未保留候选记录自身的值: %v", patchedBody["ttl"])
	}
	if patchedBody["proxied"].(bool) != false {
		t.Errorf("Proxied 未保留候选记录自身的值: %v", patchedBody["proxied"])
	}
}

func TestSyncCandidateDnsRecords_IPEqualSkipUpdate(t *testing.T) {
	var patchCalled bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/dns_records") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: true,
				Result: []DnsRecord{
					{
						ID:      "rec-node-ipv6",
						Name:    "node-ipv6.example.com",
						Type:    "AAAA",
						Content: "2001:0db8:0000:0000:0000:ff00:0042:8329",
						TTL:     120,
						Proxied: false,
					},
				},
			})
			return
		}
		if r.Method == "PATCH" {
			patchCalled = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{Success: true})
			return
		}
	}))
	defer server.Close()

	cfg := &Config{
		SyncCandidateDNS: true,
		CF: CFConfig{
			ZoneID:     "zone-123",
			RecordName: "main.example.com",
			RecordType: "AAAA",
			APIToken:   "token",
		},
		List: []CandidateNode{
			// IPv6 缩写形式与服务器返回的全写形式 net.ParseIP.Equal 应判定一致，跳过更新
			{Detect: "http://node-ipv6.example.com", Value: "2001:db8::ff00:42:8329"},
		},
	}

	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	err = app.syncCandidateDnsRecords()
	if err != nil {
		t.Fatalf("syncCandidateDnsRecords 失败: %v", err)
	}

	if patchCalled {
		t.Errorf("等价 IP 不应触发 PATCH 更新")
	}
}

func TestSyncCandidateDnsRecords_PatchAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/dns_records") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: true,
				Result: []DnsRecord{
					{ID: "rec-1", Name: "node1.example.com", Type: "CNAME", Content: "old.com"},
				},
			})
			return
		}
		if r.Method == "PATCH" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(CFResponse{
				Success: false,
				Errors:  []CFError{{Code: 10000, Message: "Authentication error"}},
			})
			return
		}
	}))
	defer server.Close()

	cfg := &Config{
		SyncCandidateDNS: true,
		CF: CFConfig{
			ZoneID:     "zone-123",
			RecordName: "main.example.com",
			APIToken:   "invalid-token",
		},
		List: []CandidateNode{
			{Detect: "http://node1.example.com", Value: "new.com"},
		},
	}

	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = server.URL

	err = app.syncCandidateDnsRecords()
	if err == nil {
		t.Fatalf("期望 PATCH 鉴权错误返回 error，但得到了 nil")
	}
	if !strings.Contains(err.Error(), "10000") && !strings.Contains(err.Error(), "Authentication") {
		t.Fatalf("返回的错误信息不包含鉴权信息: %v", err)
	}
}

func TestParseSwitchMode(t *testing.T) {
	tests := []struct {
		input       string
		expected    []SwitchStrategy
		expectedStr string
		expectErr   bool
	}{
		{"", []SwitchStrategy{StrategyStability, StrategyLatency, StrategyPriority}, "stability,latency,priority", false},
		{"   ", []SwitchStrategy{StrategyStability, StrategyLatency, StrategyPriority}, "stability,latency,priority", false},
		{"priority", []SwitchStrategy{StrategyPriority}, "priority", false},
		{"latency", []SwitchStrategy{StrategyLatency}, "latency", false},
		{"stability", []SwitchStrategy{StrategyStability}, "stability", false},
		{"latency,priority", []SwitchStrategy{StrategyLatency, StrategyPriority}, "latency,priority", false},
		{"latency, priority", []SwitchStrategy{StrategyLatency, StrategyPriority}, "latency,priority", false},
		{"latency，priority", []SwitchStrategy{StrategyLatency, StrategyPriority}, "latency,priority", false},
		{"stability > latency -> priority", []SwitchStrategy{StrategyStability, StrategyLatency, StrategyPriority}, "stability,latency,priority", false},
		{"历史稳定性 > 最低延迟 -> 列表顺序", []SwitchStrategy{StrategyStability, StrategyLatency, StrategyPriority}, "stability,latency,priority", false},
		{"stable,rtt,order", []SwitchStrategy{StrategyStability, StrategyLatency, StrategyPriority}, "stability,latency,priority", false},
		{"history,min_latency,list", []SwitchStrategy{StrategyStability, StrategyLatency, StrategyPriority}, "stability,latency,priority", false},
		{"稳定性,延迟,优先级", []SwitchStrategy{StrategyStability, StrategyLatency, StrategyPriority}, "stability,latency,priority", false},
		{"latency,latency", []SwitchStrategy{StrategyLatency}, "latency", false},
		{"invalid_strategy", nil, "", true},
		{"latency,invalid", nil, "", true},
	}

	for _, tc := range tests {
		strategies, str, err := parseSwitchMode(tc.input)
		if tc.expectErr {
			if err == nil {
				t.Errorf("输入 %q 期望报错，但成功解析为 %v", tc.input, strategies)
			}
			continue
		}
		if err != nil {
			t.Errorf("输入 %q 意外报错: %v", tc.input, err)
			continue
		}
		if str != tc.expectedStr {
			t.Errorf("输入 %q 规范化字符串期望 %q, 实际 %q", tc.input, tc.expectedStr, str)
		}
		if len(strategies) != len(tc.expected) {
			t.Fatalf("输入 %q 策略长度期望 %d, 实际 %d", tc.input, len(tc.expected), len(strategies))
		}
		for i := range strategies {
			if strategies[i] != tc.expected[i] {
				t.Errorf("输入 %q 策略[%d] 期望 %s, 实际 %s", tc.input, i, tc.expected[i], strategies[i])
			}
		}
	}
}

func TestNodeState_RecordProbeAndStabilityRate(t *testing.T) {
	node := &NodeState{}
	if rate := node.StabilityRate(); rate != 0.0 {
		t.Errorf("空历史期望可用率 0.0, 实际 %f", rate)
	}

	window := 5
	// 记录 3 次成功
	node.RecordProbe(true, window)
	node.RecordProbe(true, window)
	node.RecordProbe(true, window)
	if len(node.History) != 3 {
		t.Fatalf("历史长度期望 3, 实际 %d", len(node.History))
	}
	if rate := node.StabilityRate(); rate != 1.0 {
		t.Errorf("期望可用率 1.0, 实际 %f", rate)
	}

	// 记录 2 次失败
	node.RecordProbe(false, window)
	node.RecordProbe(false, window)
	if len(node.History) != 5 {
		t.Fatalf("历史长度期望 5, 实际 %d", len(node.History))
	}
	if rate := node.StabilityRate(); rate != 0.6 {
		t.Errorf("期望可用率 0.6, 实际 %f", rate)
	}

	// 超过窗口，触发滑动窗口淘汰 (新记录 2 次成功，淘汰最早的 2 次成功)
	node.RecordProbe(true, window)
	node.RecordProbe(true, window)
	if len(node.History) != 5 {
		t.Fatalf("超出窗口长度期望维持在 5, 实际 %d", len(node.History))
	}
	// 当前历史: [true, false, false, true, true] => 3/5 = 0.6
	if rate := node.StabilityRate(); rate != 0.6 {
		t.Errorf("滑动后期望可用率 0.6, 实际 %f", rate)
	}
}

func TestComparators(t *testing.T) {
	t.Run("comparePriority", func(t *testing.T) {
		a := &NodeState{Index: 0}
		b := &NodeState{Index: 1}
		if cmp := comparePriority(a, b); cmp >= 0 {
			t.Errorf("期望 a 优于 b, 实际 cmp=%d", cmp)
		}
		if cmp := comparePriority(b, a); cmp <= 0 {
			t.Errorf("期望 b 劣于 a, 实际 cmp=%d", cmp)
		}
		if cmp := comparePriority(a, a); cmp != 0 {
			t.Errorf("期望平局, 实际 cmp=%d", cmp)
		}
	})

	t.Run("compareLatency", func(t *testing.T) {
		a := &NodeState{LastDuration: 20}
		b := &NodeState{LastDuration: 50}
		if cmp := compareLatency(a, b); cmp >= 0 {
			t.Errorf("期望 a 优于 b, 实际 cmp=%d", cmp)
		}
		if cmp := compareLatency(b, a); cmp <= 0 {
			t.Errorf("期望 b 劣于 a, 实际 cmp=%d", cmp)
		}
		if cmp := compareLatency(a, a); cmp != 0 {
			t.Errorf("期望平局, 实际 cmp=%d", cmp)
		}
	})

	t.Run("compareStability", func(t *testing.T) {
		// 1. 可用率不同: 可用率高者胜
		a := &NodeState{History: []bool{true, true, true}}  // 100%
		b := &NodeState{History: []bool{true, false, true}} // 66.7%
		if cmp := compareStability(a, b, 10); cmp >= 0 {
			t.Errorf("期望 a(100%%) 优于 b(66.7%%), 实际 cmp=%d", cmp)
		}

		// 2. 可用率相同 (如均 75%): 历史末尾连续保持正常次数(EventOkStreak)更多者胜
		c := &NodeState{History: []bool{true, true, false, true}} // 3/4=75%, streak=1
		d := &NodeState{History: []bool{false, true, true, true}} // 3/4=75%, streak=3
		if cmp := compareStability(c, d, 10); cmp <= 0 {
			t.Errorf("期望 d(eventStreak=3) 优于 c(eventStreak=1), 实际 cmp=%d", cmp)
		}

		// 3. 可用率与历史末尾连续保持正常次数均相同: 平局
		e := &NodeState{History: []bool{true, true, true}}
		f := &NodeState{History: []bool{true, true, true}}
		if cmp := compareStability(e, f, 30); cmp != 0 {
			t.Errorf("期望历史完全相同表现为平局, 实际 cmp=%d", cmp)
		}
	})

	t.Run("compareNodesWithStrategies_Cascade", func(t *testing.T) {
		strategies := []SwitchStrategy{StrategyLatency, StrategyPriority}
		// 延迟不同时，仅比延迟
		a := &NodeState{Index: 1, LastDuration: 10}
		b := &NodeState{Index: 0, LastDuration: 20}
		if cmp := compareNodesWithStrategies(a, b, strategies, 30); cmp >= 0 {
			t.Errorf("期望 a 胜出 (较低延迟), 实际 cmp=%d", cmp)
		}

		// 延迟相同时，由第二级 priority 决定
		c := &NodeState{Index: 0, LastDuration: 20}
		d := &NodeState{Index: 1, LastDuration: 20}
		if cmp := compareNodesWithStrategies(c, d, strategies, 30); cmp >= 0 {
			t.Errorf("期望 c 胜出 (相同延迟，较小索引), 实际 cmp=%d", cmp)
		}
	})
}

func TestEvaluateTarget_Modes(t *testing.T) {
	t.Run("AllUnhealthy", func(t *testing.T) {
		app := &FailoverApp{
			cfg: &Config{
				SwitchStrategies: DefaultSwitchStrategies,
				StabilityWindow:  30,
			},
			state: []*NodeState{
				{Index: 0, Status: StatusUnhealthy},
				{Index: 1, Status: StatusUnhealthy},
			},
			activeIndex: -1,
		}
		dec := app.evaluateTarget()
		if dec.TargetIndex != -1 {
			t.Errorf("全不可用节点期望 TargetIndex=-1, 实际 %d", dec.TargetIndex)
		}
	})

	t.Run("PriorityPreemption", func(t *testing.T) {
		app := &FailoverApp{
			cfg: &Config{
				SwitchStrategies: []SwitchStrategy{StrategyPriority},
			},
			state: []*NodeState{
				{Index: 0, Status: StatusHealthy},
				{Index: 1, Status: StatusHealthy},
			},
			activeIndex: 1, // 当前活跃是 1
		}
		// 节点 0 优先级更高，回切抢占
		dec := app.evaluateTarget()
		if dec.TargetIndex != 0 {
			t.Errorf("期望回切抢占到节点 0, 实际 %d", dec.TargetIndex)
		}
	})

	t.Run("LatencyEqualTieKeepsActive", func(t *testing.T) {
		app := &FailoverApp{
			cfg: &Config{
				SwitchStrategies: []SwitchStrategy{StrategyLatency},
			},
			state: []*NodeState{
				{Index: 0, Status: StatusHealthy, LastDuration: 50},
				{Index: 1, Status: StatusHealthy, LastDuration: 50},
			},
			activeIndex: 1, // 当前活跃是 1，且两者延迟相同
		}
		// 仅配置 latency 且平局时，应保持当前健康节点 1，防止震荡
		dec := app.evaluateTarget()
		if dec.TargetIndex != 1 {
			t.Errorf("期望平局保持活跃节点 1, 实际 %d", dec.TargetIndex)
		}
	})

	t.Run("LatencyPriorityCascading", func(t *testing.T) {
		app := &FailoverApp{
			cfg: &Config{
				SwitchStrategies: []SwitchStrategy{StrategyLatency, StrategyPriority},
			},
			state: []*NodeState{
				{Index: 0, Status: StatusHealthy, LastDuration: 50},
				{Index: 1, Status: StatusHealthy, LastDuration: 50},
			},
			activeIndex: 1,
		}
		// 延迟相同时，按 priority 决胜负，节点 0 (index 0) 优于节点 1
		dec := app.evaluateTarget()
		if dec.TargetIndex != 0 {
			t.Errorf("期望多级策略决胜负切换到节点 0, 实际 %d", dec.TargetIndex)
		}
	})

	t.Run("DefaultStabilityProtectsActive", func(t *testing.T) {
		app := &FailoverApp{
			cfg: &Config{
				SwitchStrategies: DefaultSwitchStrategies, // stability, latency, priority
				StabilityWindow:  30,
			},
			state: []*NodeState{
				// 节点 0 在过往发生过故障，恢复后当前稳定性为 2/3 (66.7%)
				{Index: 0, Status: StatusHealthy, LastDuration: 10, History: []bool{true, false, true}},
				// 节点 1 经历所有变更均保持正常，稳定性为 3/3 (100%)
				{Index: 1, Status: StatusHealthy, LastDuration: 50, History: []bool{true, true, true}},
			},
			activeIndex: 1,
		}

		// 虽然节点 0 延迟更低且列表靠前，但节点 1 历史稳定性更高，因此不发生切换
		dec := app.evaluateTarget()
		if dec.TargetIndex != 1 {
			t.Errorf("期望历史稳定性保护活跃节点 1，但切换到了 %d", dec.TargetIndex)
		}

		// 当节点 0 与节点 1 历史上均保持 100% 稳定时，进入下一级延迟比较，切换到更快的节点 0
		app.state[0].History = []bool{true, true, true}
		dec2 := app.evaluateTarget()
		if dec2.TargetIndex != 0 {
			t.Errorf("期望两者均稳定后按延迟切换到节点 0, 实际 %d", dec2.TargetIndex)
		}
	})
}

func TestFormatNodeSuffix(t *testing.T) {
	appWithStability := &FailoverApp{
		cfg: &Config{
			SwitchStrategies: []SwitchStrategy{StrategyStability, StrategyLatency, StrategyPriority},
		},
	}
	nodeHealthy := &NodeState{
		Status:       StatusHealthy,
		LastDuration: 45,
		History:      []bool{true, true},
	}
	suffix := appWithStability.formatNodeSuffix(nodeHealthy)
	if suffix != "45ms (稳定性 100%)" {
		t.Errorf("期望 '45ms (稳定性 100%%)', 实际 %q", suffix)
	}

	appWithoutStability := &FailoverApp{
		cfg: &Config{
			SwitchStrategies: []SwitchStrategy{StrategyLatency, StrategyPriority},
		},
	}
	suffixNoStab := appWithoutStability.formatNodeSuffix(nodeHealthy)
	if suffixNoStab != "45ms" {
		t.Errorf("期望 '45ms', 实际 %q", suffixNoStab)
	}

	nodeUnhealthy := &NodeState{
		Status:    StatusUnhealthy,
		LastError: "请求超时",
	}
	suffixErr := appWithStability.formatNodeSuffix(nodeUnhealthy)
	if suffixErr != "请求超时" {
		t.Errorf("期望 '请求超时', 实际 %q", suffixErr)
	}
}

func TestLoadConfig_SwitchModeAndWindow(t *testing.T) {
	content := `
switch_mode: "latency, priority"
stability_window: 50
cf:
  record_name: "test.example.com"
list:
  - detect: "https://node1.example.com"
    value: "target1.com"
`
	path := writeTempConfigFile(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}
	if cfg.SwitchMode != "latency,priority" {
		t.Errorf("期望 SwitchMode 为 latency,priority, 实际 %s", cfg.SwitchMode)
	}
	if len(cfg.SwitchStrategies) != 2 || cfg.SwitchStrategies[0] != StrategyLatency || cfg.SwitchStrategies[1] != StrategyPriority {
		t.Errorf("期望 SwitchStrategies 为 [latency, priority], 实际 %v", cfg.SwitchStrategies)
	}
	if cfg.StabilityWindow != 50 {
		t.Errorf("期望 StabilityWindow 为 50, 实际 %d", cfg.StabilityWindow)
	}
}

func TestLoadConfig_DefaultSwitchModeAndWindow(t *testing.T) {
	content := `
cf:
  record_name: "test.example.com"
list:
  - detect: "https://node1.example.com"
    value: "target1.com"
`
	path := writeTempConfigFile(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}
	if cfg.SwitchMode != "stability,latency,priority" {
		t.Errorf("期望默认 SwitchMode 为 stability,latency,priority, 实际 %s", cfg.SwitchMode)
	}
	if len(cfg.SwitchStrategies) != 3 || cfg.SwitchStrategies[0] != StrategyStability || cfg.SwitchStrategies[1] != StrategyLatency || cfg.SwitchStrategies[2] != StrategyPriority {
		t.Errorf("期望默认 SwitchStrategies 为 [stability, latency, priority], 实际 %v", cfg.SwitchStrategies)
	}
	if cfg.StabilityWindow != DefaultStabilityWindow {
		t.Errorf("期望默认 StabilityWindow 为 %d, 实际 %d", DefaultStabilityWindow, cfg.StabilityWindow)
	}
}

func TestLoadConfig_InvalidSwitchMode(t *testing.T) {
	content := `
switch_mode: "latency,unknown_strategy"
cf:
  record_name: "test.example.com"
`
	path := writeTempConfigFile(t, content)
	_, err := loadConfig(path)
	if err == nil {
		t.Fatalf("期望非法 switch_mode 返回 error")
	}
}

func TestLoadConfig_SwitchModeYAMLList(t *testing.T) {
	content := `
switch_mode:
  - latency
  - priority
cf:
  record_name: "test.example.com"
list:
  - detect: "https://node1.example.com"
    value: "target1.com"
`
	path := writeTempConfigFile(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig 解析 YAML 列表 switch_mode 失败: %v", err)
	}
	if cfg.SwitchMode != "latency,priority" {
		t.Errorf("期望 SwitchMode 为 latency,priority, 实际 %s", cfg.SwitchMode)
	}
	if len(cfg.SwitchStrategies) != 2 || cfg.SwitchStrategies[0] != StrategyLatency || cfg.SwitchStrategies[1] != StrategyPriority {
		t.Errorf("期望 SwitchStrategies 为 [latency, priority], 实际 %v", cfg.SwitchStrategies)
	}
}

func TestFormatNodeSuffix_FloatingPrecision(t *testing.T) {
	app := &FailoverApp{
		cfg: &Config{
			SwitchStrategies: []SwitchStrategy{StrategyStability},
		},
	}

	// 11 次成功，9 次失败 => 11/20 = 55%
	// 在 IEEE 754 浮点下 11/20 * 100 会产生 55.00000000000001
	var history []bool
	for range 11 {
		history = append(history, true)
	}
	for range 9 {
		history = append(history, false)
	}
	node := &NodeState{
		Status:       StatusHealthy,
		LastDuration: 30,
		History:      history,
	}
	suffix := app.formatNodeSuffix(node)
	if suffix != "30ms (稳定性 55%)" {
		t.Errorf("期望 '30ms (稳定性 55%%)', 实际 %q", suffix)
	}
}

func TestHasStabilityStrategy_NilSafe(t *testing.T) {
	var nilApp *FailoverApp
	if nilApp.hasStabilityStrategy() {
		t.Errorf("nil app 期望返回 false")
	}

	appNoCfg := &FailoverApp{}
	if appNoCfg.hasStabilityStrategy() {
		t.Errorf("app with nil cfg 期望返回 false")
	}
}

func TestRunCycle_HistoryOnlyRecordedOnCandidateStatusChange(t *testing.T) {
	var node0Fail atomic.Bool
	node0Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if node0Fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer node0Server.Close()

	node1Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer node1Server.Close()

	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(CFResponse{
			Success: true,
			Result: []DnsRecord{
				{ID: "rec-test", Name: "main.example.com", Content: "target1.com", Type: "CNAME"},
			},
		})
	}))
	defer cfServer.Close()

	cfg := &Config{
		LoopTime:         10,
		ProbeCount:       2,
		ProbeRetry:       1,
		ProbeTimeout:     2,
		StabilityWindow:  10,
		SwitchStrategies: []SwitchStrategy{StrategyStability, StrategyPriority}, // 使用 stability,priority 避免本机回环 0ms/1ms 时钟误差干扰
		SwitchMode:       "stability,priority",
		CF: CFConfig{
			ZoneID:     "zone-test",
			RecordName: "main.example.com",
			RecordType: "CNAME",
			APIToken:   "token",
		},
		List: []CandidateNode{
			{Detect: node0Server.URL, Value: "target0.com"},
			{Detect: node1Server.URL, Value: "target1.com"},
		},
	}

	app, err := NewFailoverApp(cfg)
	if err != nil {
		t.Fatalf("NewFailoverApp 失败: %v", err)
	}
	app.cfBaseURL = cfServer.URL
	app.dnsRecordID = "rec-test"
	app.activeIndex = 0 // 假设初始指向节点 0

	// 1. 第 1 轮探测: 初始探测基线建立 (记录第 1 条测试结果)
	app.RunCycle()
	if len(app.state[0].History) != 1 || len(app.state[1].History) != 1 {
		t.Fatalf("初始探测后各节点期望 History 长度为 1, 实际 [0]=%d, [1]=%d",
			len(app.state[0].History), len(app.state[1].History))
	}
	if !app.state[0].History[0] || !app.state[1].History[0] {
		t.Fatalf("初始探测各节点期望为 true")
	}

	// 2. 第 2~3 轮探测: 正常例行探测，节点健康且无任何候选状态变更
	app.RunCycle()
	app.RunCycle()
	if len(app.state[0].History) != 1 || len(app.state[1].History) != 1 {
		t.Fatalf("无候选状态变更的常规探测中，History 长度应保持为 1 不得递增, 实际 [0]=%d, [1]=%d",
			len(app.state[0].History), len(app.state[1].History))
	}

	// 3. 节点 0 出现故障
	node0Fail.Store(true)

	// 失败第 1 次: probe_count=2，尚未达到阈值，节点 0 状态仍为健康，无变更
	app.RunCycle()
	if len(app.state[0].History) != 1 {
		t.Fatalf("节点 0 失败 1 次尚未翻转状态前，History 长度应保持为 1, 实际 %d", len(app.state[0].History))
	}

	// 失败第 2 次: 达到 probe_count=2，节点 0 翻转为 Unhealthy，触发候选状态变更并切换到节点 1
	app.RunCycle()
	if len(app.state[0].History) != 2 || len(app.state[1].History) != 2 {
		t.Fatalf("节点 0 状态翻转发生候选状态变更后，各节点 History 期望长度为 2, 实际 [0]=%d, [1]=%d",
			len(app.state[0].History), len(app.state[1].History))
	}
	if app.state[0].History[1] != false {
		t.Errorf("节点 0 在故障变更时刻的记录期望为 false")
	}
	if app.state[1].History[1] != true {
		t.Errorf("节点 1 在故障变更时刻的记录期望为 true")
	}
	if app.activeIndex != 1 {
		t.Errorf("期望切换到健康的活跃候选 1, 实际 %d", app.activeIndex)
	}

	// 4. 故障持续期间常规探测，状态保持不变，不递增记录
	app.RunCycle()
	app.RunCycle()
	if len(app.state[0].History) != 2 {
		t.Fatalf("节点 0 持续故障但状态未再度翻转时，History 长度应维持 2, 实际 %d", len(app.state[0].History))
	}

	// 5. 节点 0 恢复正常
	node0Fail.Store(false)

	// 成功第 1 次: probe_count=2，未达就绪阈值，状态仍为 Unhealthy，无变更
	app.RunCycle()
	if len(app.state[0].History) != 2 {
		t.Fatalf("节点 0 成功 1 次尚未恢复健康前，History 长度应维持 2, 实际 %d", len(app.state[0].History))
	}

	// 成功第 2 次: 节点 0 恢复为 StatusHealthy，触发节点状态翻转，写入变更时刻测试结果
	app.RunCycle()
	if len(app.state[0].History) != 3 || len(app.state[1].History) != 3 {
		t.Fatalf("节点 0 恢复健康发生候选状态变更后，History 长度期望为 3, 实际 [0]=%d, [1]=%d",
			len(app.state[0].History), len(app.state[1].History))
	}
	if app.state[0].History[2] != true {
		t.Errorf("节点 0 恢复时刻记录期望为 true")
	}

	// 节点 0 历史记录为 [true, false, true] => 2/3 = 66.7%
	// 节点 1 历史记录为 [true, true, true]   => 3/3 = 100%
	// 在 stability,latency,priority 模式下，节点 1 历史稳定性更高，故保护活跃节点 1，不发生回切抢占
	if app.activeIndex != 1 {
		t.Errorf("刚恢复的节点 0 历史稳定性(66.7%%)劣于持续健康的节点 1(100%%)，期望继续保持活跃节点 1, 实际切到了 %d", app.activeIndex)
	}
}


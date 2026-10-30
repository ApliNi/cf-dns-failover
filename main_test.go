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

package badbotblocker

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var (
	poolKey      = caddy.NewUsagePool()
	refreshState = struct {
		sync.Mutex
		started     bool
		stopChan    chan struct{}
		lastMatcher *BadBotMatcher
	}{}
)

// Max duration for HTTP requests
const httpTimeout = 30 * time.Second

type badBotData struct {
	BadUserAgents map[string]bool
	BadIPs        map[string]bool
	BadReferers   map[string]bool
	BadSubnets    []net.IPNet

	mutex sync.RWMutex
}

func (b *badBotData) Destruct() error {
	return nil
}

func init() {
	caddy.RegisterModule(BadBotMatcher{})
}

// BadBotMatcher implements an HTTP request matcher.
type BadBotMatcher struct {
	ExcludeReferer    []string `json:"exclude_referer,omitempty"`
	ExcludeUserAgents []string `json:"exclude_user_agents,omitempty"`
	ExcludeIPs        []string `json:"exclude_ips,omitempty"`

	UserAgentListURL []string `json:"user_agent_list_url,omitempty"`
	IPListURL        []string `json:"ip_list_url,omitempty"`
	RefererListURL   []string `json:"referer_list_url,omitempty"`
	TrustedIPListURL []string `json:"trusted_ip_list_url,omitempty"`
	RefreshInterval  string   `json:"refresh_interval,omitempty"`

	data   *badBotData
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (BadBotMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.badbotblocker",
		New: func() caddy.Module { return new(BadBotMatcher) },
	}
}

// Provision implements caddy.Provisioner.
func (m *BadBotMatcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	m.logger.Info("=== BAD BOT BLOCKER PROVISION STARTED ===")

	resource, _, err := poolKey.LoadOrNew("badbotblocker_lists", func() (caddy.Destructor, error) {
		m.logger.Info("Creating new shared blocklist data structure")

		data := &badBotData{
			BadUserAgents: make(map[string]bool),
			BadIPs:        make(map[string]bool),
			BadReferers:   make(map[string]bool),
			BadSubnets:    make([]net.IPNet, 0),
		}

		// Check if we have refresh_interval configured
		if m.RefreshInterval != "" {
			m.logger.Info("refresh_interval configured, will start background refresh after initial load",
				zap.String("interval", m.RefreshInterval))
		} else {
			m.logger.Warn("NO refresh_interval configured - blocklists will NOT be automatically updated (only loaded once at startup)")
		}

		// Lock before initial update
		m.logger.Info("Acquiring lock for initial list update...")
		data.mutex.Lock()
		m.logger.Info("Lock acquired, starting list downloads...")

		startTime := time.Now()
		// Pass nil context since we're blocking anyway - the HTTP client will handle timeout
		err := m.updateLists(data)

		data.mutex.Unlock()
		m.logger.Info("Lock released after list update")

		if err != nil {
			m.logger.Error("Failed to download blocklists during initial load",
				zap.Error(err),
				zap.Duration("elapsed", time.Since(startTime)))
			return nil, err
		}

		m.logger.Info(
			"Block lists downloaded successfully",
			zap.Int("ip_loaded", len(data.BadIPs)),
			zap.Int("ua_loaded", len(data.BadUserAgents)),
			zap.Int("referer_loaded", len(data.BadReferers)),
			zap.Duration("elapsed", time.Since(startTime)),
		)

		return data, nil
	})

	if err != nil {
		m.logger.Error("Failed to provision blocklist data", zap.Error(err))
		return err
	}

	m.data = resource.(*badBotData)
	m.logger.Info("=== BAD BOT BLOCKER PROVISION COMPLETED ===")

	// Start refresh loop if refresh_interval is configured (singleton)
	if m.RefreshInterval != "" {
		m.logger.Info("Starting refresh loop from Provision()")
		m.startRefreshLoopOnce()
	}

	return nil
}

// Validate implements caddy.Validator.
func (m *BadBotMatcher) Validate() error {
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *BadBotMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for d.NextBlock(0) {
		switch d.Val() {
		case "exclude_referer":
			m.ExcludeReferer = d.RemainingArgs()
		case "exclude_user_agents":
			m.ExcludeUserAgents = d.RemainingArgs()
		case "exclude_ips":
			m.ExcludeIPs = d.RemainingArgs()
		case "user_agent_list_url":
			m.UserAgentListURL = d.RemainingArgs()
		case "ip_list_url":
			m.IPListURL = d.RemainingArgs()
		case "referer_list_url":
			m.RefererListURL = d.RemainingArgs()
		case "trusted_ip_list_url":
			m.TrustedIPListURL = d.RemainingArgs()
		case "refresh_interval":
			args := d.RemainingArgs()
			if len(args) > 0 {
				m.RefreshInterval = args[0]
			}
		}
	}

	return nil
}

// Match returns true if the request is from a bad bot.
func (m BadBotMatcher) Match(r *http.Request) bool {
	match, err := m.MatchWithError(r)
	if err != nil {
		m.logger.Error("matching request", zap.Error(err))
		return false
	}
	return match
}

// MatchWithError returns true if the request is from a bad bot.
func (m BadBotMatcher) MatchWithError(r *http.Request) (bool, error) {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	userAgent := r.UserAgent()
	referrer := r.Referer()
	if referrer == "" {
		referrer = r.Header.Get("Referrer")
	}

	var reason string
	if m.isBadUserAgent(userAgent) {
		reason = "Bad User-Agent"
	} else if m.isBadReferer(referrer) {
		reason = "Bad Referer"
	} else if m.isBadIP(ip) {
		reason = "Bad IP"
	}

	if reason != "" {
		m.logger.Info(
			"Blocked request",
			zap.String("reason", reason),
			zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: r}),
		)
		return true, nil
	}

	return false, nil
}

// Helper functions to check malicious lists
func (m *BadBotMatcher) isBadIP(ip string) bool {
	host, _, _ := net.SplitHostPort(ip)
	if host == "" {
		host = ip
	}

	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	m.data.mutex.RLock()
	defer m.data.mutex.RUnlock()

	if slices.Contains(m.ExcludeIPs, host) {
		return false
	}

	if m.data.BadIPs[host] {
		return true
	}

	for _, subnet := range m.data.BadSubnets {
		if subnet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func (m *BadBotMatcher) isBadUserAgent(userAgent string) bool {
	m.data.mutex.RLock()
	defer m.data.mutex.RUnlock()

	if slices.Contains(m.ExcludeUserAgents, userAgent) {
		return false
	}

	for badUA := range m.data.BadUserAgents {
		if userAgent != "" && strings.Contains(userAgent, badUA) {
			return true
		}
	}

	return false
}

func (m *BadBotMatcher) isBadReferer(referer string) bool {
	m.data.mutex.RLock()
	defer m.data.mutex.RUnlock()

	if slices.Contains(m.ExcludeReferer, referer) {
		return false
	}

	for badReferer := range m.data.BadReferers {
		if referer != "" && strings.Contains(referer, badReferer) {
			return true
		}
	}

	return false
}

// Function to update the lists
func (m *BadBotMatcher) updateLists(data *badBotData) error {
	// Don't lock here - caller is responsible for locking
	// This function is called by both Provision() and refreshLists()

	m.logger.Info("=== STARTING LIST UPDATE ===")

	// Download the list of malicious User-Agents
	m.logger.Info("STEP 1: Downloading User-Agent list...")
	uaStart := time.Now()
	userAgentList, err := m.fetchList(m.UserAgentListURL, []string{
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list",
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/good-user-agents.list",
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/limited-user-agents.list",
	})
	if err != nil {
		m.logger.Error("Failed to download User-Agent list", zap.Error(err))
		return err
	}
	m.logger.Info("User-Agent list downloaded",
		zap.Int("count", len(userAgentList)),
		zap.Duration("elapsed", time.Since(uaStart)))

	data.BadUserAgents = make(map[string]bool)
	for _, ua := range userAgentList {
		data.BadUserAgents[ua] = true
	}

	goodSubnets := make([]net.IPNet, 0)

	// Download trusted IP ranges (optional)
	m.logger.Info("STEP 2: Downloading Trusted IP list (optional)...")
	trustedStart := time.Now()
	trustedIpRangeList, err := m.fetchList(m.TrustedIPListURL, []string{})
	if err != nil {
		m.logger.Error("Failed to download Trusted IP list", zap.Error(err))
		return err
	}
	m.logger.Info("Trusted IP list downloaded",
		zap.Int("count", len(trustedIpRangeList)),
		zap.Duration("elapsed", time.Since(trustedStart)))

	for _, ip := range trustedIpRangeList {
		if _, subnet, err := net.ParseCIDR(ip); err == nil {
			goodSubnets = append(goodSubnets, *subnet)
		}
	}

	// Download the list of malicious IPs (MAIN LIST - LIKELY WHERE IT HANGS)
	m.logger.Info("STEP 3: Downloading Malicious IP lists (this may take a while)...")
	ipStart := time.Now()
	ipList, err := m.fetchList(m.IPListURL, []string{
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-ip-addresses.list",
		"https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-14d.ipv4",
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/fake-googlebots.list",
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/seo-analysis-tools.list",
		"https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/botscout_30d.ipset",
		"https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/firehol_abusers_30d.netset",
		"https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/firehol_level1.netset",
		"https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/firehol_webserver.netset",
		"https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/greensnow.ipset",
	})
	if err != nil {
		m.logger.Error("Failed to download Malicious IP lists", zap.Error(err))
		return err
	}
	m.logger.Info("Malicious IP lists downloaded",
		zap.Int("count", len(ipList)),
		zap.Duration("elapsed", time.Since(ipStart)))

	data.BadIPs = make(map[string]bool)
	ipParseStart := time.Now()
	parsedCount := 0
	subnetCount := 0
	for _, line := range ipList {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments: split at '#'
		parts := strings.SplitN(line, "#", 2)
		ipStr := strings.TrimSpace(parts[0])

		if strings.Contains(ipStr, "/") {
			_, subnet, err := net.ParseCIDR(ipStr)
			if err == nil {
				data.BadSubnets = append(data.BadSubnets, *subnet)
				subnetCount++
			}
		} else {
			isBad := true
			for _, subnet := range goodSubnets {
				ip := net.ParseIP(ipStr)
				if subnet.Contains(ip) {
					isBad = false
					break
				}
			}
			if isBad {
				data.BadIPs[ipStr] = true
				parsedCount++
			}
		}
	}
	m.logger.Info("Malicious IP lists parsed",
		zap.Int("ips_parsed", parsedCount),
		zap.Int("subnets_parsed", subnetCount),
		zap.Duration("elapsed", time.Since(ipParseStart)))

	// Download the list of malicious Referers
	m.logger.Info("STEP 4: Downloading Referer list...")
	refStart := time.Now()
	refererList, err := m.fetchList(m.RefererListURL, []string{
		"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-referrers.list",
	})
	if err != nil {
		m.logger.Error("Failed to download Referer list", zap.Error(err))
		return err
	}
	m.logger.Info("Referer list downloaded",
		zap.Int("count", len(refererList)),
		zap.Duration("elapsed", time.Since(refStart)))

	data.BadReferers = make(map[string]bool)
	for _, referer := range refererList {
		data.BadReferers[referer] = true
	}

	m.logger.Info("=== LIST UPDATE COMPLETED SUCCESSFULLY ===")

	return nil
}

// startRefreshLoopOnce starts a singleton background goroutine that periodically refreshes the blocklists
func (m *BadBotMatcher) startRefreshLoopOnce() {
	refreshState.Lock()
	defer refreshState.Unlock()

	// Already started by another matcher instance
	if refreshState.started {
		m.logger.Info("Refresh loop already started by another matcher instance, skipping")
		return
	}

	// Parse the refresh interval
	duration, err := time.ParseDuration(m.RefreshInterval)
	if err != nil {
		m.logger.Error("invalid refresh_interval format, refresh disabled",
			zap.String("interval", m.RefreshInterval),
			zap.Error(err),
		)
		return
	}

	if duration < time.Hour {
		m.logger.Warn("refresh_interval is less than 1 hour, consider using a longer interval to avoid excessive requests",
			zap.Duration("interval", duration),
		)
	}

	// Create stop channel and start the goroutine
	refreshState.stopChan = make(chan struct{})
	refreshState.lastMatcher = m
	refreshState.started = true

	// Use the matcher's logger
	logger := m.logger

	logger.Info("Starting blocklist refresh loop (singleton)",
		zap.Duration("interval", duration),
	)

	ticker := time.NewTicker(duration)

	go func() {
		defer ticker.Stop()

		// Wait for first tick
		logger.Info("Refresh goroutine started, waiting for first tick...")

		for {
			select {
			case <-refreshState.stopChan:
				logger.Info("Blocklist refresh loop stopped via stop channel")
				return
			case <-ticker.C:
				logger.Info("=== REFRESH TIMER TICKED - Starting background refresh ===")
				// Use the lastMatcher to call refresh
				refreshState.lastMatcher.refreshLists()
				logger.Info("=== BACKGROUND REFRESH COMPLETE - Waiting for next tick ===")
			}
		}
	}()
}

// stopRefreshLoop stops the running refresh loop (called on Caddy reload)
func stopRefreshLoop() {
	refreshState.Lock()
	defer refreshState.Unlock()

	if refreshState.started && refreshState.stopChan != nil {
		close(refreshState.stopChan)
		refreshState.stopChan = nil
		refreshState.started = false
		refreshState.lastMatcher = nil
	}
}

// refreshLists fetches and updates the blocklists
func (m *BadBotMatcher) refreshLists() {
	m.logger.Info("=== STARTING BACKGROUND REFRESH ===")

	// Create a temporary data structure to hold new lists
	newData := &badBotData{
		BadUserAgents: make(map[string]bool),
		BadIPs:        make(map[string]bool),
		BadReferers:   make(map[string]bool),
		BadSubnets:    make([]net.IPNet, 0),
	}

	// Lock the mutex before updating
	m.logger.Info("Acquiring lock for background refresh...")
	newData.mutex.Lock()
	refreshStart := time.Now()
	err := m.updateLists(newData)
	newData.mutex.Unlock()
	m.logger.Info("Lock released after background refresh")

	if err != nil {
		m.logger.Error("Failed to refresh blocklists, keeping old lists",
			zap.Error(err),
			zap.Duration("elapsed", time.Since(refreshStart)),
		)
		return
	}

	// Atomic pointer swap - readers will see either old or new data, never partial
	m.logger.Info("Performing atomic data pointer swap...")
	m.data = newData

	m.logger.Info("=== BACKGROUND REFRESH COMPLETED SUCCESSFULLY ===",
		zap.Int("ip_loaded", len(newData.BadIPs)),
		zap.Int("ua_loaded", len(newData.BadUserAgents)),
		zap.Int("referer_loaded", len(newData.BadReferers)),
		zap.Duration("total_elapsed", time.Since(refreshStart)),
	)
}

// Destruct implements caddy.Destructor to clean up resources
// This is called when the module is destroyed during Caddy reload
func (m *BadBotMatcher) Destruct() error {
	stopRefreshLoop()
	return nil
}

// Helper function to download the lists
func (m *BadBotMatcher) fetchList(urls []string, defaultUrls []string) ([]string, error) {
	if len(urls) == 0 {
		urls = defaultUrls
	}

	var list []string
	for i, url := range urls {
		m.logger.Info("Downloading list",
			zap.Int("index", i+1),
			zap.Int("total", len(urls)),
			zap.String("url", url))

		downloadStart := time.Now()

		// Create HTTP client with timeout (this is what actually enforces the timeout)
		client := &http.Client{
			Timeout: httpTimeout,
		}

		// Make the HTTP GET request (DO NOT use context here - it conflicts with Caddy's context)
		// The client timeout will handle the timeout
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			m.logger.Error("Failed to create HTTP request",
				zap.String("url", url),
				zap.Error(err))
			return nil, err
		}

		// Execute request
		resp, err := client.Do(req)

		if err != nil {
			m.logger.Error("HTTP request failed",
				zap.String("url", url),
				zap.Error(err),
				zap.Duration("elapsed", time.Since(downloadStart)))
			return nil, err
		}

		// Check HTTP status
		if resp.StatusCode != 200 {
			m.logger.Error("HTTP request returned non-200 status",
				zap.String("url", url),
				zap.Int("status_code", resp.StatusCode),
				zap.Duration("elapsed", time.Since(downloadStart)))
			resp.Body.Close()
			return nil, nil // Return empty list instead of error to allow partial success
		}

		// Read body before closing
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			m.logger.Error("Failed to read response body",
				zap.String("url", url),
				zap.Error(err),
				zap.Duration("elapsed", time.Since(downloadStart)))
			return nil, err
		}

		bodySize := len(body)
		m.logger.Info("Downloaded list body",
			zap.String("url", url),
			zap.Int("bytes", bodySize),
			zap.Duration("elapsed", time.Since(downloadStart)))

		parseStart := time.Now()
		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		lineCount := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if len(line) > 0 && !strings.HasPrefix(line, "#") { // Ignore comments
				list = append(list, line)
				lineCount++
			}
		}

		m.logger.Info("Parsed list",
			zap.String("url", url),
			zap.Int("lines", lineCount),
			zap.Int("total_entries", len(list)),
			zap.Duration("parse_elapsed", time.Since(parseStart)))
	}

	return list, nil
}

// Interface guards
var (
	_ caddy.Provisioner                 = (*BadBotMatcher)(nil)
	_ caddy.Validator                   = (*BadBotMatcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*BadBotMatcher)(nil)
	_ caddyfile.Unmarshaler             = (*BadBotMatcher)(nil)
	_ caddy.Destructor                  = (*BadBotMatcher)(nil)
)

// Package app provides the application bootstrap and initialization logic.
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/cocowh/netproxy/internal/core/admin"
	"github.com/cocowh/netproxy/internal/core/config"
	"github.com/cocowh/netproxy/internal/core/lifecycle"
	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/cocowh/netproxy/internal/feature/acl"
	"github.com/cocowh/netproxy/internal/feature/acme"
	"github.com/cocowh/netproxy/internal/feature/auth"
	"github.com/cocowh/netproxy/internal/feature/dns"
	"github.com/cocowh/netproxy/internal/feature/health"
	"github.com/cocowh/netproxy/internal/feature/loadbalancer"
	"github.com/cocowh/netproxy/internal/feature/metrics"
	"github.com/cocowh/netproxy/internal/feature/ratelimit"
	"github.com/cocowh/netproxy/internal/feature/router"
	"github.com/cocowh/netproxy/internal/feature/stats"
	"github.com/cocowh/netproxy/internal/feature/subscription"
	"github.com/cocowh/netproxy/internal/feature/user"
	"github.com/cocowh/netproxy/internal/protocol/http"
	"github.com/cocowh/netproxy/internal/protocol/socks5"
	"github.com/cocowh/netproxy/internal/protocol/sps"
	"github.com/cocowh/netproxy/internal/protocol/tunnel"
	"github.com/cocowh/netproxy/internal/service/instance"
	"github.com/cocowh/netproxy/internal/service/listener"
	"golang.org/x/time/rate"
)

// App represents the main application instance
type App struct {
	cfgManager        config.Manager
	cfg               *config.Config
	logger            logger.Logger
	lifecycle         lifecycle.Lifecycle
	router            router.Router
	statsCollector    stats.StatsCollector
	authenticator     auth.Authenticator
	userStore         user.Store
	metricsCollector  *metrics.Collector
	healthChecker     *health.Checker
	acmeManager       *acme.Manager
	subscriptionUpdater *subscription.Updater
}

// New creates a new App instance with the given config file path
func New(cfgFile string) (*App, error) {
	app := &App{}

	// 1. Load Config
	if err := app.initConfig(cfgFile); err != nil {
		return nil, fmt.Errorf("failed to init config: %w", err)
	}

	// 2. Init Logger
	if err := app.initLogger(); err != nil {
		return nil, fmt.Errorf("failed to init logger: %w", err)
	}

	// 3. Init Lifecycle
	app.lifecycle = lifecycle.NewLifecycle()

	// 4. Init Router
	app.initRouter()

	// 5. Init Stats Collector
	app.statsCollector = stats.NewSimpleCollector()

	// 6. Init Auth
	app.initAuth()

	// 7. Init User Store (if enabled)
	if err := app.initUserStore(); err != nil {
		return nil, fmt.Errorf("failed to init user store: %w", err)
	}

	// 8. Init Metrics Collector (if enabled)
	app.initMetricsCollector()

	// 9. Init Health Checker (if enabled)
	app.initHealthChecker()

	// 10. Init ACME Manager (if enabled)
	if err := app.initACMEManager(); err != nil {
		return nil, fmt.Errorf("failed to init ACME manager: %w", err)
	}

	// 11. Init Subscription Updater (if enabled)
	app.initSubscriptionUpdater()

	return app, nil
}

// Run starts the application and blocks until shutdown
func (a *App) Run(ctx context.Context) error {
	a.logger.Info("Starting NetProxy...")

	// Start Admin Server
	a.startAdminServer()

	// Register Config Watcher
	a.registerConfigWatcher()

	// Init DNS Server (if enabled)
	a.initDNSServer()

	// Init Listeners
	a.initListeners()

	// Init Tunnel
	a.initTunnel()

	// Init Health Checker lifecycle hook
	a.initHealthCheckerHook()

	// Init ACME Manager lifecycle hook
	a.initACMEManagerHook()

	// Init Subscription Updater lifecycle hook
	a.initSubscriptionUpdaterHook()

	// Run and wait for shutdown
	if err := lifecycle.RunAndWait(ctx, a.lifecycle); err != nil {
		a.logger.Fatal("Application error", logger.Any("error", err))
		return err
	}

	// Cleanup
	a.cleanup()

	a.logger.Info("NetProxy stopped")
	return nil
}

// cleanup performs cleanup operations on shutdown
func (a *App) cleanup() {
	if a.userStore != nil {
		a.userStore.Close()
	}
}

// initConfig loads the configuration
func (a *App) initConfig(cfgFile string) error {
	a.cfgManager = config.NewManager(cfgFile)
	if err := a.cfgManager.Load(); err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
	}
	a.cfg = a.cfgManager.GetConfig()
	return nil
}

// initLogger initializes the logger
func (a *App) initLogger() error {
	logLevel := logger.InfoLevel
	if a.cfg.Log.Level == "debug" {
		logLevel = logger.DebugLevel
	}

	l, err := logger.NewZapLogger(logLevel, a.cfg.Log.Path)
	if err != nil {
		return err
	}
	a.logger = l
	return nil
}

// initRouter initializes the router with rule engine and load balancer
func (a *App) initRouter() {
	ruleEngine := acl.NewSimpleRuleEngine(acl.Direct, nil, nil)
	balancer := loadbalancer.NewRoundRobinBalancer()
	a.router = router.NewSimpleRouter(
		ruleEngine,
		a.cfg.Routing.Upstreams,
		balancer,
		a.cfg.Routing.GeoIP,
		a.cfg.Routing.RemoteDNS,
	)

	if err := config.LoadRules(a.router, a.cfg.Routing.Rules); err != nil {
		a.logger.Warn("Failed to load some rules", logger.Any("error", err))
	}
}

// initAuth initializes the authenticator
func (a *App) initAuth() {
	if a.cfg.Auth.Type == "local" {
		a.authenticator = auth.NewLocalAuthenticator(a.cfg.Auth.Params)
	}
}

// startAdminServer starts the admin HTTP server
func (a *App) startAdminServer() {
	adminAddr := a.cfg.Admin.Addr
	if adminAddr == "" {
		adminAddr = ":9090" // Default
	}

	adminServer := admin.NewServer(adminAddr, a.cfg.Admin.Token, a.statsCollector)
	go func() {
		a.logger.Info("Starting Admin Server", logger.Any("addr", adminAddr))
		if err := adminServer.Start(); err != nil {
			a.logger.Error("Admin server failed", logger.Any("error", err))
		}
	}()
}

// registerConfigWatcher registers the config file watcher for hot reload
func (a *App) registerConfigWatcher() {
	a.cfgManager.Watch(func(newCfg *config.Config) {
		a.logger.Info("Config updated, reloading...")
		if err := config.LoadRules(a.router, newCfg.Routing.Rules); err != nil {
			a.logger.Warn("Failed to reload rules", logger.Any("error", err))
		} else {
			a.logger.Info("Rules reloaded successfully")
		}
	})
}

// initDNSServer initializes the DNS server if enabled
func (a *App) initDNSServer() {
	if !a.cfg.DNS.Enabled {
		return
	}

	dnsServer := dns.NewServer(a.cfg.DNS.Addr, a.cfg.DNS.Upstream)
	for domain, upstream := range a.cfg.DNS.Rules {
		dnsServer.AddRule(domain, upstream)
	}

	if sRouter, ok := a.router.(*router.SimpleRouter); ok {
		dnsServer.SetRouter(sRouter)
	}

	a.lifecycle.Append(lifecycle.Hook{
		Name: "DNSServer",
		OnStart: func(ctx context.Context) error {
			a.logger.Info("Starting DNS Server", logger.Any("addr", a.cfg.DNS.Addr))
			return dnsServer.Start(ctx)
		},
		OnStop: func(ctx context.Context) error {
			return dnsServer.Stop(ctx)
		},
	})
}

// initListeners initializes all protocol listeners
func (a *App) initListeners() {
	for i, lCfg := range a.cfg.Listeners {
		handlerProtocol := lCfg.Protocol
		handlerInstance, err := a.createHandler(handlerProtocol, lCfg.RateLimit, lCfg.Announce)
		if err != nil {
			a.logger.Error("Failed to create handler",
				logger.Any("protocol", handlerProtocol),
				logger.Any("error", err))
			continue
		}

		manager := listener.NewManager(handlerInstance)

		transportProtocol := lCfg.Transport
		if transportProtocol == "" {
			transportProtocol = "tcp"
		}

		configs := a.buildListenerConfigs(lCfg, transportProtocol, handlerProtocol)
		a.registerListenerHook(i, handlerProtocol, lCfg.Addr, manager, configs)
	}
}

// createHandler creates a protocol handler based on the protocol type
func (a *App) createHandler(protocol string, limitConfig config.RateLimitConfig, announceAddr string) (listener.ConnHandler, error) {
	var limiter ratelimit.Limiter
	if limitConfig.Enabled {
		limiter = ratelimit.NewTokenBucketLimiter(rate.Limit(limitConfig.Limit), limitConfig.Burst)
	}

	switch protocol {
	case "socks5":
		return a.createSOCKS5Handler(limiter, announceAddr)
	case "http":
		return a.createHTTPHandler(limiter)
	case "sps", "mixed":
		return a.createSPSHandler(limiter, announceAddr)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", protocol)
	}
}

// createSOCKS5Handler creates a SOCKS5 protocol handler
func (a *App) createSOCKS5Handler(limiter ratelimit.Limiter, announceAddr string) (listener.ConnHandler, error) {
	h, err := socks5.NewSOCKS5Handler(a.authenticator, announceAddr)
	if err != nil {
		return nil, err
	}

	inst := instance.NewServiceInstance(
		instance.Config{Protocol: "socks5"},
		a.logger,
		h,
		a.statsCollector,
		limiter,
	)

	if sInst, ok := inst.(interface{ SetRouter(router.Router) }); ok {
		sInst.SetRouter(a.router)
	}

	return inst, nil
}

// createHTTPHandler creates an HTTP protocol handler
func (a *App) createHTTPHandler(limiter ratelimit.Limiter) (listener.ConnHandler, error) {
	h := http.NewHTTPHandler(a.authenticator)

	inst := instance.NewServiceInstance(
		instance.Config{Protocol: "http"},
		a.logger,
		h,
		a.statsCollector,
		limiter,
	)

	if sInst, ok := inst.(interface{ SetRouter(router.Router) }); ok {
		sInst.SetRouter(a.router)
	}

	return inst, nil
}

// createSPSHandler creates an SPS (mixed SOCKS5/HTTP) protocol handler
func (a *App) createSPSHandler(limiter ratelimit.Limiter, announceAddr string) (listener.ConnHandler, error) {
	socks5Handler, err := socks5.NewSOCKS5Handler(a.authenticator, announceAddr)
	if err != nil {
		return nil, err
	}

	httpHandler := http.NewHTTPHandler(a.authenticator)
	h := sps.NewSPSHandler(socks5Handler, httpHandler, httpHandler)

	inst := instance.NewServiceInstance(
		instance.Config{Protocol: "sps"},
		a.logger,
		h,
		a.statsCollector,
		limiter,
	)

	if sInst, ok := inst.(interface{ SetRouter(router.Router) }); ok {
		sInst.SetRouter(a.router)
	}

	return inst, nil
}

// buildListenerConfigs builds the listener configurations for a given listener config
func (a *App) buildListenerConfigs(lCfg config.ListenerConfig, transportProtocol, handlerProtocol string) []listener.ListenerConfig {
	lcConfig := listener.ListenerConfig{
		Network:  transportProtocol,
		Protocol: handlerProtocol,
		Addr:     lCfg.Addr,
		Announce: lCfg.Announce,
		Options:  lCfg.Options,
	}

	configs := []listener.ListenerConfig{lcConfig}

	// For SPS/Mixed/SOCKS5 over TCP, also enable UDP listener on same port if possible
	if transportProtocol == "tcp" && (handlerProtocol == "sps" || handlerProtocol == "mixed" || handlerProtocol == "socks5") {
		configs = append(configs, listener.ListenerConfig{
			Network:  "udp",
			Protocol: handlerProtocol,
			Addr:     lCfg.Addr,
			Announce: lCfg.Announce,
			Options:  lCfg.Options,
		})
	}

	return configs
}

// registerListenerHook registers a lifecycle hook for a listener
func (a *App) registerListenerHook(index int, protocol, addr string, manager listener.Manager, configs []listener.ListenerConfig) {
	hookName := fmt.Sprintf("Listener-%d-%s", index, protocol)

	a.lifecycle.Append(lifecycle.Hook{
		Name: hookName,
		OnStart: func(ctx context.Context) error {
			a.logger.Info("Starting Listener",
				logger.Any("protocol", protocol),
				logger.Any("addr", addr))
			return manager.Refresh(configs)
		},
		OnStop: func(ctx context.Context) error {
			return manager.Stop(ctx)
		},
	})
}

// initTunnel initializes the tunnel based on configuration
func (a *App) initTunnel() {
	switch a.cfg.Tunnel.Mode {
	case "bridge":
		a.initTunnelBridge()
	case "client":
		a.initTunnelClient()
	}
}

// initTunnelBridge initializes the tunnel bridge mode
func (a *App) initTunnelBridge() {
	bridge := tunnel.NewBridge(
		a.cfg.Tunnel.ControlAddr,
		a.cfg.Tunnel.DataAddr,
		a.cfg.Tunnel.Tunnels,
		a.cfg.Tunnel.Token,
		a.logger,
	)

	a.lifecycle.Append(lifecycle.Hook{
		Name: "TunnelBridge",
		OnStart: func(ctx context.Context) error {
			return bridge.Start(ctx)
		},
		OnStop: func(ctx context.Context) error {
			return nil
		},
	})
}

// initTunnelClient initializes the tunnel client mode
func (a *App) initTunnelClient() {
	client := tunnel.NewClient(
		a.cfg.Tunnel.ServerAddr,
		a.cfg.Tunnel.TargetAddr,
		a.cfg.Tunnel.ClientID,
		a.cfg.Tunnel.Token,
		a.logger,
	)

	a.lifecycle.Append(lifecycle.Hook{
		Name: "TunnelClient",
		OnStart: func(ctx context.Context) error {
			go func() {
				if err := client.Start(ctx); err != nil {
					a.logger.Error("Tunnel client exited with error", logger.Any("error", err))
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return nil
		},
	})
}

// initUserStore initializes the user store if enabled
func (a *App) initUserStore() error {
	if !a.cfg.Users.Enabled {
		return nil
	}

	var store user.Store
	var err error

	switch a.cfg.Users.StoreType {
	case "sqlite":
		store, err = user.NewSQLiteStore(a.cfg.Users.SQLitePath)
		if err != nil {
			return fmt.Errorf("failed to create SQLite store: %w", err)
		}
	default:
		store = user.NewMemoryStore()
	}

	a.userStore = store
	a.logger.Info("User store initialized", logger.Any("type", a.cfg.Users.StoreType))
	return nil
}

// initMetricsCollector initializes the metrics collector if enabled
func (a *App) initMetricsCollector() {
	if !a.cfg.Metrics.Enabled {
		return
	}

	a.metricsCollector = metrics.NewCollector()
	a.logger.Info("Metrics collector initialized")
}

// initHealthChecker initializes the health checker if enabled
func (a *App) initHealthChecker() {
	if !a.cfg.Health.Enabled {
		return
	}

	interval := a.cfg.Health.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}

	defaultTimeout := a.cfg.Health.DefaultTimeout
	if defaultTimeout == 0 {
		defaultTimeout = 5 * time.Second
	}

	a.healthChecker = health.NewChecker(health.Config{
		Interval:       interval,
		DefaultTimeout: defaultTimeout,
	})

	// Register default health checks
	a.healthChecker.Register(&health.Component{
		Name:     "memory",
		Check:    health.MemoryCheck(80),
		Critical: false,
		Timeout:  defaultTimeout,
	})

	a.healthChecker.Register(&health.Component{
		Name:     "goroutines",
		Check:    health.GoroutineCheck(10000),
		Critical: false,
		Timeout:  defaultTimeout,
	})

	a.logger.Info("Health checker initialized")
}

// initHealthCheckerHook registers the health checker lifecycle hook
func (a *App) initHealthCheckerHook() {
	if a.healthChecker == nil {
		return
	}

	a.lifecycle.Append(lifecycle.Hook{
		Name: "HealthChecker",
		OnStart: func(ctx context.Context) error {
			a.logger.Info("Starting Health Checker")
			return a.healthChecker.Start(ctx)
		},
		OnStop: func(ctx context.Context) error {
			return a.healthChecker.Stop()
		},
	})
}

// initACMEManager initializes the ACME certificate manager if enabled
func (a *App) initACMEManager() error {
	if !a.cfg.ACME.Enabled {
		return nil
	}

	cacheDir := a.cfg.ACME.CacheDir
	if cacheDir == "" {
		cacheDir = "./data/acme"
	}

	directoryURL := a.cfg.ACME.DirectoryURL
	if directoryURL == "" {
		directoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	renewBefore := a.cfg.ACME.RenewBefore
	if renewBefore == 0 {
		renewBefore = 30 * 24 * time.Hour
	}

	httpChallengePort := a.cfg.ACME.HTTPChallengePort
	if httpChallengePort == 0 {
		httpChallengePort = 80
	}

	tlsChallengePort := a.cfg.ACME.TLSChallengePort
	if tlsChallengePort == 0 {
		tlsChallengePort = 443
	}

	manager, err := acme.NewManager(acme.Config{
		Email:             a.cfg.ACME.Email,
		Domains:           a.cfg.ACME.Domains,
		CacheDir:          cacheDir,
		DirectoryURL:      directoryURL,
		RenewBefore:       renewBefore,
		HTTPChallenge:     a.cfg.ACME.HTTPChallenge,
		HTTPChallengePort: httpChallengePort,
		TLSChallenge:      a.cfg.ACME.TLSChallenge,
		TLSChallengePort:  tlsChallengePort,
	})
	if err != nil {
		return fmt.Errorf("failed to create ACME manager: %w", err)
	}

	a.acmeManager = manager
	a.logger.Info("ACME manager initialized", logger.Any("domains", a.cfg.ACME.Domains))
	return nil
}

// initACMEManagerHook registers the ACME manager lifecycle hook
func (a *App) initACMEManagerHook() {
	if a.acmeManager == nil {
		return
	}

	a.lifecycle.Append(lifecycle.Hook{
		Name: "ACMEManager",
		OnStart: func(ctx context.Context) error {
			a.logger.Info("Starting ACME Manager")
			return a.acmeManager.Start(ctx)
		},
		OnStop: func(ctx context.Context) error {
			return a.acmeManager.Stop()
		},
	})
}

// initSubscriptionUpdater initializes the subscription updater if enabled
func (a *App) initSubscriptionUpdater() {
	if !a.cfg.Subscription.Enabled || len(a.cfg.Subscription.Sources) == 0 {
		return
	}

	sources := make([]*subscription.RuleSource, 0, len(a.cfg.Subscription.Sources))
	for _, src := range a.cfg.Subscription.Sources {
		if !src.Enabled {
			continue
		}

		ruleType := subscription.RuleTypeCustom
		switch src.Type {
		case "geoip":
			ruleType = subscription.RuleTypeGeoIP
		case "geosite":
			ruleType = subscription.RuleTypeGeoSite
		default:
			ruleType = subscription.RuleTypeCustom
		}

		updateInterval := src.UpdateInterval
		if updateInterval == 0 {
			updateInterval = 24 * time.Hour
		}

		sources = append(sources, &subscription.RuleSource{
			Name:           src.Name,
			Type:           ruleType,
			URL:            src.URL,
			LocalPath:      src.LocalPath,
			UpdateInterval: updateInterval,
			Enabled:        src.Enabled,
		})
	}

	if len(sources) == 0 {
		return
	}

	updater, err := subscription.NewUpdater(subscription.Config{
		DataDir: "./data/rules",
		Sources: sources,
	})
	if err != nil {
		a.logger.Error("Failed to create subscription updater", logger.Any("error", err))
		return
	}

	a.subscriptionUpdater = updater
	a.logger.Info("Subscription updater initialized", logger.Any("sources", len(sources)))
}

// initSubscriptionUpdaterHook registers the subscription updater lifecycle hook
func (a *App) initSubscriptionUpdaterHook() {
	if a.subscriptionUpdater == nil {
		return
	}

	a.lifecycle.Append(lifecycle.Hook{
		Name: "SubscriptionUpdater",
		OnStart: func(ctx context.Context) error {
			a.logger.Info("Starting Subscription Updater")
			return a.subscriptionUpdater.Start(ctx)
		},
		OnStop: func(ctx context.Context) error {
			return a.subscriptionUpdater.Stop()
		},
	})
}

// GetUserStore returns the user store (for API handlers)
func (a *App) GetUserStore() user.Store {
	return a.userStore
}

// GetMetricsCollector returns the metrics collector (for API handlers)
func (a *App) GetMetricsCollector() *metrics.Collector {
	return a.metricsCollector
}

// GetHealthChecker returns the health checker (for API handlers)
func (a *App) GetHealthChecker() *health.Checker {
	return a.healthChecker
}

// GetSubscriptionUpdater returns the subscription updater (for API handlers)
func (a *App) GetSubscriptionUpdater() *subscription.Updater {
	return a.subscriptionUpdater
}

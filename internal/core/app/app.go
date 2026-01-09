// Package app provides the application bootstrap and initialization logic.
package app

import (
	"context"
	"fmt"

	"github.com/cocowh/netproxy/internal/core/admin"
	"github.com/cocowh/netproxy/internal/core/config"
	"github.com/cocowh/netproxy/internal/core/lifecycle"
	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/cocowh/netproxy/internal/feature/acl"
	"github.com/cocowh/netproxy/internal/feature/auth"
	"github.com/cocowh/netproxy/internal/feature/dns"
	"github.com/cocowh/netproxy/internal/feature/loadbalancer"
	"github.com/cocowh/netproxy/internal/feature/ratelimit"
	"github.com/cocowh/netproxy/internal/feature/router"
	"github.com/cocowh/netproxy/internal/feature/stats"
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
	cfgManager     config.Manager
	cfg            *config.Config
	logger         logger.Logger
	lifecycle      lifecycle.Lifecycle
	router         router.Router
	statsCollector stats.StatsCollector
	authenticator  auth.Authenticator
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

	// Run and wait for shutdown
	if err := lifecycle.RunAndWait(ctx, a.lifecycle); err != nil {
		a.logger.Fatal("Application error", logger.Any("error", err))
		return err
	}

	a.logger.Info("NetProxy stopped")
	return nil
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

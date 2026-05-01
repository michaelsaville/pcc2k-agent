//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "pcc2k-agent"
	serviceDisplayName = "PCC2K Agent"
	serviceDescription = "Outbound RMM agent for PCC2K-managed hosts. " +
		"Connects to the WSS gateway, reports inventory, and serves remote operations."
)

// isWindowsService reports whether the current process was started by
// the Service Control Manager. When true, main.go skips flag parsing
// and runs the SCM Execute loop instead of the console foreground.
func isWindowsService() bool {
	in, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return in
}

// runAsService blocks until SCM tells us to stop. Reads config from
// %ProgramData%\PCC2K (saved at install time) — no flags consulted.
func runAsService() {
	// Best-effort event-log writer. If the source isn't registered (we
	// don't currently install one — would need eventlog.InstallAsEventCreate
	// during install with admin rights), elog.Open returns nil and we
	// fall back to stderr/log. The service still runs.
	elog, _ := eventlog.Open(serviceName)
	if elog != nil {
		defer elog.Close()
	}

	logf := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		log.Println(msg)
		if elog != nil {
			_ = elog.Info(1, msg)
		}
	}

	cfg, insecure, err := loadConfig()
	if err != nil {
		if elog != nil {
			_ = elog.Error(1, fmt.Sprintf("config load failed: %v", err))
		}
		log.Printf("config load failed: %v", err)
		os.Exit(2)
	}
	if !insecure && len(cfg.gatewayURL) >= 5 && cfg.gatewayURL[:5] == "ws://" {
		log.Printf("refusing to run service: ws:// requires insecure flag at install time")
		os.Exit(2)
	}

	logf("pcc2k-agent service starting (agentId=%s host=%s)", cfg.agentID, cfg.hostname)

	if err := svc.Run(serviceName, &pcc2kSvc{cfg: cfg}); err != nil {
		log.Printf("svc.Run failed: %v", err)
		if elog != nil {
			_ = elog.Error(1, fmt.Sprintf("svc.Run failed: %v", err))
		}
		os.Exit(1)
	}
}

type pcc2kSvc struct {
	cfg agentConfig
}

// Execute implements svc.Handler. Runs the agent reconnect loop in a
// goroutine and translates SCM Stop/Shutdown into context cancellation.
func (p *pcc2kSvc) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runReconnectLoop(ctx, p.cfg)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				log.Println("service: agent loop didn't exit within 10s; forcing stop")
			}
			return false, 0
		default:
			log.Printf("service: unexpected SCM cmd %v", c.Cmd)
		}
	}
	return false, 0
}

// installService accepts the same flags that console mode does, then
// persists them to %ProgramData%\PCC2K and registers the service with
// SCM. After this completes, `sc start pcc2k-agent` (or our `start`
// subcommand) launches the agent.
func installService(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	gatewayURL := fs.String("gateway", "", "WSS gateway URL (required)")
	token := fs.String("token", "", "enrollment token (required)")
	agentID := fs.String("agent-id", "", "Op_Agent.id (required)")
	clientName := fs.String("client", "PCC2K (Internal)", "TH_Client.name")
	hostname := fs.String("hostname", "", "hostname to report (default = os.Hostname())")
	role := fs.String("role", "workstation", "free-form role tag")
	insecure := fs.Bool("insecure", false, "allow ws:// (dev only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *gatewayURL == "" {
		return fmt.Errorf("install: --gateway is required")
	}
	if *token == "" {
		return fmt.Errorf("install: --token is required")
	}
	if *agentID == "" {
		return fmt.Errorf("install: --agent-id is required")
	}
	hn := *hostname
	if hn == "" {
		h, _ := os.Hostname()
		hn = h
	}

	exepath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate exe: %w", err)
	}
	exepath, _ = filepath.Abs(exepath)

	cfg := agentConfig{
		gatewayURL: *gatewayURL,
		token:      *token,
		agentID:    *agentID,
		clientName: *clientName,
		hostname:   hn,
		role:       *role,
	}
	if err := saveConfig(cfg, *insecure); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("scm connect: %w (run from elevated shell)", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(serviceName); err == nil {
		existing.Close()
		return fmt.Errorf("service %s already installed; uninstall first", serviceName)
	}

	s, err := m.CreateService(serviceName, exepath, mgr.Config{
		DisplayName:    serviceDisplayName,
		Description:    serviceDescription,
		StartType:      mgr.StartAutomatic,
		ErrorControl:   mgr.ErrorNormal,
		ServiceType:    0x10, // SERVICE_WIN32_OWN_PROCESS
		ServiceStartName: "LocalSystem",
	})
	if err != nil {
		return fmt.Errorf("scm create: %w", err)
	}
	defer s.Close()

	// Restart on failure: 5s, 5s, 5s. Reset failure count after 60s clean.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 60); err != nil {
		log.Printf("install: SetRecoveryActions failed (non-fatal): %v", err)
	}

	fmt.Printf("Installed service %q. Start it with: pcc2k-agent.exe start (or `sc start %s`)\n",
		serviceDisplayName, serviceName)
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("scm connect: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("scm open: %w (already uninstalled?)", err)
	}
	defer s.Close()

	// Best-effort stop before delete — SCM will refuse to delete a
	// running service.
	if status, err := s.Query(); err == nil && status.State == svc.Running {
		if _, err := s.Control(svc.Stop); err == nil {
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				st, err := s.Query()
				if err != nil || st.State == svc.Stopped {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("scm delete: %w", err)
	}
	fmt.Printf("Uninstalled service %q. Config files in %s preserved (delete manually if desired).\n",
		serviceDisplayName, configDir())
	return nil
}

func startServiceCmd() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("scm connect: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("scm open: %w (run install first?)", err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return fmt.Errorf("scm start: %w", err)
	}
	fmt.Printf("Started %q.\n", serviceDisplayName)
	return nil
}

func stopServiceCmd() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("scm connect: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("scm open: %w", err)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("scm stop: %w", err)
	}
	fmt.Printf("Stopped %q.\n", serviceDisplayName)
	return nil
}

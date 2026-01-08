//go:build windows
// +build windows

// Package service provides Windows service support using the SCM API.
package service

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sys/windows/svc"
)

const (
	// ServiceName is the Windows service name
	ServiceName = "SlimRMMAgent"
)

// AgentRunner is the interface that the main agent must implement
type AgentRunner interface {
	Run(ctx context.Context) error
	Stop()
}

// agentService implements svc.Handler for Windows Service Control Manager
type agentService struct {
	runner AgentRunner
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
}

// Execute is called by the Windows SCM to start the service
func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// Report that we're starting
	changes <- svc.Status{State: svc.StartPending}

	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Start the agent in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- s.runner.Run(s.ctx)
	}()

	// Report that we're running
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.logger.Info("Windows service started successfully")

	// Main service loop
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s.logger.Info("received stop signal from Windows SCM")
				changes <- svc.Status{State: svc.StopPending}
				s.cancel()
				s.runner.Stop()
				break loop
			default:
				s.logger.Warn("unexpected service control request", "cmd", c.Cmd)
			}
		case err := <-done:
			if err != nil {
				s.logger.Error("agent exited with error", "error", err)
			}
			break loop
		}
	}

	// Wait for agent to finish (with timeout)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		s.logger.Warn("timeout waiting for agent to stop")
	}

	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

// RunAsService runs the agent as a Windows service
func RunAsService(runner AgentRunner, logger *slog.Logger) error {
	return svc.Run(ServiceName, &agentService{
		runner: runner,
		logger: logger,
	})
}

// IsRunningAsService returns true if the current process is running as a Windows service
func IsRunningAsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

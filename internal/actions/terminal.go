// Package actions provides terminal/PTY functionality.
package actions

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

// Terminal represents an interactive terminal session.
type Terminal struct {
	ID       string
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	output   chan string
	done     chan struct{}
	mu       sync.Mutex
	running  bool
}

// TerminalManager manages terminal sessions.
type TerminalManager struct {
	terminals map[string]*Terminal
	mu        sync.RWMutex
}

// NewTerminalManager creates a new terminal manager.
func NewTerminalManager() *TerminalManager {
	return &TerminalManager{
		terminals: make(map[string]*Terminal),
	}
}

// StartTerminal starts a new terminal session.
func (m *TerminalManager) StartTerminal(id string) (*Terminal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.terminals[id]; exists {
		return nil, fmt.Errorf("terminal %s already exists", id)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe")
	} else {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		cmd = exec.Command(shell)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting terminal: %w", err)
	}

	term := &Terminal{
		ID:      id,
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		output:  make(chan string, 100),
		done:    make(chan struct{}),
		running: true,
	}

	// Start output readers
	go term.readOutput(stdout)
	go term.readOutput(stderr)

	// Wait for process to exit
	go func() {
		cmd.Wait()
		term.mu.Lock()
		term.running = false
		term.mu.Unlock()
		close(term.done)
	}()

	m.terminals[id] = term
	return term, nil
}

// readOutput reads from a pipe and sends to output channel.
func (t *Terminal) readOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		select {
		case t.output <- scanner.Text():
		case <-t.done:
			return
		}
	}
}

// SendInput sends input to the terminal.
func (m *TerminalManager) SendInput(id, input string) error {
	m.mu.RLock()
	term, exists := m.terminals[id]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("terminal %s not found", id)
	}

	term.mu.Lock()
	defer term.mu.Unlock()

	if !term.running {
		return fmt.Errorf("terminal %s is not running", id)
	}

	_, err := term.stdin.Write([]byte(input + "\n"))
	return err
}

// GetOutput returns the output channel for a terminal.
func (m *TerminalManager) GetOutput(id string) (<-chan string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	term, exists := m.terminals[id]
	if !exists {
		return nil, fmt.Errorf("terminal %s not found", id)
	}

	return term.output, nil
}

// StopTerminal stops a terminal session.
func (m *TerminalManager) StopTerminal(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	term, exists := m.terminals[id]
	if !exists {
		return fmt.Errorf("terminal %s not found", id)
	}

	term.mu.Lock()
	if term.running {
		term.stdin.Close()
		term.cmd.Process.Kill()
	}
	term.mu.Unlock()

	delete(m.terminals, id)
	return nil
}

// IsRunning checks if a terminal is running.
func (m *TerminalManager) IsRunning(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	term, exists := m.terminals[id]
	if !exists {
		return false
	}

	term.mu.Lock()
	defer term.mu.Unlock()
	return term.running
}

// ReadOutput reads available output from a terminal (non-blocking).
func (m *TerminalManager) ReadOutput(ctx context.Context, id string, maxLines int) ([]string, error) {
	m.mu.RLock()
	term, exists := m.terminals[id]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("terminal %s not found", id)
	}

	var lines []string
	for i := 0; i < maxLines; i++ {
		select {
		case line := <-term.output:
			lines = append(lines, line)
		case <-ctx.Done():
			return lines, ctx.Err()
		default:
			return lines, nil
		}
	}
	return lines, nil
}

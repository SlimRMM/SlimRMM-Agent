// Package actions provides terminal functionality for Windows.
//go:build windows
// +build windows

package actions

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// Terminal represents a terminal session (limited on Windows).
type Terminal struct {
	ID         string
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	stderr     io.ReadCloser
	done       chan struct{}
	mu         sync.RWMutex
	running    bool
	outputChan chan []byte
	rows       uint16
	cols       uint16
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

// StartTerminal starts a new terminal session (cmd.exe on Windows).
func (m *TerminalManager) StartTerminal(id string) (*Terminal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.terminals[id]; exists {
		return nil, fmt.Errorf("terminal %s already exists", id)
	}

	// Use PowerShell or cmd.exe
	shell := os.Getenv("COMSPEC")
	if shell == "" {
		shell = "cmd.exe"
	}

	cmd := exec.Command(shell)
	cmd.Dir = "C:\\" // Start terminal in C:\ on Windows
	cmd.Env = os.Environ()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return nil, fmt.Errorf("starting command: %w", err)
	}

	term := &Terminal{
		ID:         id,
		cmd:        cmd,
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		done:       make(chan struct{}),
		running:    true,
		outputChan: make(chan []byte, 256),
		rows:       24,
		cols:       80,
	}

	// Read output goroutines
	go term.readOutput(stdout)
	go term.readOutput(stderr)

	// Wait for process exit
	go func() {
		cmd.Wait()
		term.mu.Lock()
		term.running = false
		term.mu.Unlock()
		close(term.done)
		close(term.outputChan)
	}()

	m.terminals[id] = term
	return term, nil
}

// readOutput reads from a pipe and sends to output channel.
func (t *Terminal) readOutput(r io.ReadCloser) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-t.done:
			return
		default:
		}

		n, err := r.Read(buf)
		if err != nil {
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			select {
			case t.outputChan <- data:
			case <-t.done:
				return
			default:
				// Channel full, drop oldest
				select {
				case <-t.outputChan:
				default:
				}
				t.outputChan <- data
			}
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

	term.mu.RLock()
	running := term.running
	term.mu.RUnlock()

	if !running {
		return fmt.Errorf("terminal %s is not running", id)
	}

	// Windows cmd.exe with pipes doesn't echo input like a real PTY does.
	// We need to manually echo the input back to the output channel.
	// Convert \r to \r\n for proper line handling in terminal emulator.
	echoData := input
	if input == "\r" {
		echoData = "\r\n"
	}

	// Echo input to output channel (non-blocking)
	select {
	case term.outputChan <- []byte(echoData):
	default:
		// Channel full, skip echo
	}

	// Write to stdin
	_, err := term.stdin.Write([]byte(input))
	if err != nil {
		return fmt.Errorf("stdin.Write failed: %w", err)
	}
	return nil
}

// SendInputRaw sends raw bytes to the terminal.
func (m *TerminalManager) SendInputRaw(id string, data []byte) error {
	m.mu.RLock()
	term, exists := m.terminals[id]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("terminal %s not found", id)
	}

	term.mu.RLock()
	running := term.running
	term.mu.RUnlock()

	if !running {
		return fmt.Errorf("terminal %s is not running", id)
	}

	// Windows cmd.exe with pipes doesn't echo input like a real PTY does.
	// We need to manually echo the input back to the output channel.
	// Handle special cases for proper terminal display.
	echoData := data
	if len(data) == 1 && data[0] == '\r' {
		echoData = []byte("\r\n")
	}

	// Echo input to output channel (non-blocking)
	select {
	case term.outputChan <- echoData:
	default:
		// Channel full, skip echo
	}

	// Write to stdin
	_, err := term.stdin.Write(data)
	if err != nil {
		return fmt.Errorf("stdin.Write failed: %w", err)
	}
	return nil
}

// Resize is a no-op on Windows (no PTY support).
func (t *Terminal) Resize(rows, cols uint16) error {
	t.mu.Lock()
	t.rows = rows
	t.cols = cols
	t.mu.Unlock()
	return nil
}

// ResizeTerminal resizes a terminal session (no-op on Windows).
func (m *TerminalManager) ResizeTerminal(id string, rows, cols uint16) error {
	m.mu.RLock()
	term, exists := m.terminals[id]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("terminal %s not found", id)
	}

	return term.Resize(rows, cols)
}

// GetOutput returns the output channel for a terminal.
func (m *TerminalManager) GetOutput(id string) (<-chan []byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	term, exists := m.terminals[id]
	if !exists {
		return nil, fmt.Errorf("terminal %s not found", id)
	}

	return term.outputChan, nil
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

	term.mu.RLock()
	defer term.mu.RUnlock()
	return term.running
}

// ReadOutput reads available output from a terminal (non-blocking).
// Returns raw bytes for xterm.js compatibility.
func (m *TerminalManager) ReadOutput(ctx context.Context, id string, maxBytes int) ([]byte, error) {
	m.mu.RLock()
	term, exists := m.terminals[id]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("terminal %s not found", id)
	}

	var result []byte
	for len(result) < maxBytes {
		select {
		case data, ok := <-term.outputChan:
			if !ok {
				return result, nil
			}
			result = append(result, data...)
		case <-ctx.Done():
			return result, ctx.Err()
		default:
			return result, nil
		}
	}
	return result, nil
}

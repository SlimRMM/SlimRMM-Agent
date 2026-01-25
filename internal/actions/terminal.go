// Package actions provides terminal/PTY functionality.
//go:build !windows
// +build !windows

package actions

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
)

// Terminal represents an interactive PTY terminal session.
type Terminal struct {
	ID         string
	cmd        *exec.Cmd
	pty        *os.File
	done       chan struct{}
	cancel     context.CancelFunc // For graceful goroutine shutdown
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

// StartTerminal starts a new PTY terminal session.
func (m *TerminalManager) StartTerminal(id string) (*Terminal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.terminals[id]; exists {
		return nil, fmt.Errorf("terminal %s already exists", id)
	}

	// Get user's shell
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	// Create command with login shell
	cmd := exec.Command(shell, "-l")
	cmd.Dir = "/" // Start terminal in root directory
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"HOME=/root", // Ensure HOME is set correctly for root
	)

	// Start with PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("starting PTY: %w", err)
	}

	// Create context for goroutine cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure PTY is closed if we fail after this point
	success := false
	defer func() {
		if !success {
			cancel()
			ptmx.Close()
			cmd.Process.Kill()
		}
	}()

	term := &Terminal{
		ID:         id,
		cmd:        cmd,
		pty:        ptmx,
		done:       make(chan struct{}),
		cancel:     cancel,
		running:    true,
		outputChan: make(chan []byte, 4096), // 4096 * 4KB = 16MB buffer for large file outputs
		rows:       24,
		cols:       80,
	}

	// Set initial size (ignore error - terminal will still work with default size)
	_ = term.Resize(24, 80)

	// Start output reader goroutine with context
	go term.readOutputWithContext(ctx)

	// Wait for process to exit
	go func() {
		cmd.Wait()
		term.mu.Lock()
		term.running = false
		term.mu.Unlock()
		cancel() // Signal goroutines to stop
		close(term.done)
		close(term.outputChan)
	}()

	m.terminals[id] = term
	success = true // Prevent cleanup in defer
	return term, nil
}

// readOutput reads from PTY and sends to output channel.
// Deprecated: Use readOutputWithContext instead.
func (t *Terminal) readOutput() {
	t.readOutputWithContext(context.Background())
}

// readOutputWithContext reads from PTY and sends to output channel with context cancellation.
func (t *Terminal) readOutputWithContext(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		default:
		}

		n, err := t.pty.Read(buf)
		if err != nil {
			if err != io.EOF {
				// Log error but don't crash
			}
			return
		}

		if n > 0 {
			// Make a copy of the data
			data := make([]byte, n)
			copy(data, buf[:n])

			select {
			case t.outputChan <- data:
			case <-ctx.Done():
				return
			case <-t.done:
				return
			default:
				// Channel full, drop oldest data
				select {
				case <-t.outputChan:
				default:
				}
				t.outputChan <- data
			}
		}
	}
}

// SendInput sends raw input to the terminal (character by character).
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

	// Write raw input (no newline added - frontend handles that)
	_, err := term.pty.Write([]byte(input))
	return err
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

	_, err := term.pty.Write(data)
	return err
}

// Resize changes the terminal size.
func (t *Terminal) Resize(rows, cols uint16) error {
	t.mu.Lock()
	t.rows = rows
	t.cols = cols
	t.mu.Unlock()

	ws := struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}{
		Row: rows,
		Col: cols,
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		t.pty.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// ResizeTerminal resizes a terminal session.
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
		// Cancel context to signal goroutines to stop
		if term.cancel != nil {
			term.cancel()
		}
		term.pty.Close()
		term.cmd.Process.Kill()
	}
	term.mu.Unlock()

	delete(m.terminals, id)
	return nil
}

// StopAll stops all terminal sessions (for graceful shutdown).
func (m *TerminalManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, term := range m.terminals {
		term.mu.Lock()
		if term.running {
			if term.cancel != nil {
				term.cancel()
			}
			term.pty.Close()
			term.cmd.Process.Kill()
		}
		term.mu.Unlock()
		delete(m.terminals, id)
	}
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

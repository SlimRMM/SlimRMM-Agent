// Package actions provides terminal functionality for Windows using ConPTY.
//go:build windows
// +build windows

package actions

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"github.com/UserExistsError/conpty"
)

// Terminal represents a ConPTY terminal session on Windows.
type Terminal struct {
	ID         string
	cpty       *conpty.ConPty
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

// StartTerminal starts a new terminal session using Windows ConPTY.
func (m *TerminalManager) StartTerminal(id string) (*Terminal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.terminals[id]; exists {
		return nil, fmt.Errorf("terminal %s already exists", id)
	}

	// Use PowerShell as default shell on Windows
	// Try pwsh (PowerShell 7+) first, fall back to powershell.exe (Windows PowerShell 5.1)
	var shell string
	if _, err := exec.LookPath("pwsh"); err == nil {
		// PowerShell 7+ supports -WorkingDirectory
		// Use forward slash to avoid escaping issues with backslash
		shell = `pwsh -NoLogo -WorkingDirectory C:/`
	} else {
		// Windows PowerShell 5.1 - use -Command to set location
		// Use forward slash to avoid escaping issues with backslash (\" is interpreted as escaped quote)
		shell = `powershell.exe -NoLogo -NoExit -Command "Set-Location C:/"`
	}

	// Start ConPTY with default size
	cpty, err := conpty.Start(shell, conpty.ConPtyDimensions(80, 24))
	if err != nil {
		return nil, fmt.Errorf("starting conpty: %w", err)
	}

	term := &Terminal{
		ID:         id,
		cpty:       cpty,
		done:       make(chan struct{}),
		running:    true,
		outputChan: make(chan []byte, 4096), // 4096 * 4KB = 16MB buffer for large file outputs
		rows:       24,
		cols:       80,
	}

	// Read output goroutine
	go term.readOutput()

	// Wait for process exit
	go func() {
		cpty.Wait(context.Background())
		term.mu.Lock()
		term.running = false
		term.mu.Unlock()
		close(term.done)
		close(term.outputChan)
	}()

	m.terminals[id] = term
	return term, nil
}

// readOutput reads from ConPTY and sends to output channel.
func (t *Terminal) readOutput() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-t.done:
			return
		default:
		}

		n, err := t.cpty.Read(buf)
		if err != nil {
			if err != io.EOF {
				// Log error but don't spam
			}
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

	// Write to ConPTY - it handles all terminal processing
	_, err := term.cpty.Write([]byte(input))
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
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

	// Write to ConPTY - it handles all terminal processing
	_, err := term.cpty.Write(data)
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	return nil
}

// Resize resizes the terminal.
func (t *Terminal) Resize(rows, cols uint16) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.rows = rows
	t.cols = cols

	if t.cpty != nil {
		return t.cpty.Resize(int(cols), int(rows))
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
	if term.running && term.cpty != nil {
		term.cpty.Close()
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

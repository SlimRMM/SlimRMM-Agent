// Package proxmox provides token management for Proxmox API access.
package proxmox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TokenConfig holds API token configuration.
type TokenConfig struct {
	TokenID   string `json:"token_id"`   // e.g., "root@pam!slimrmm"
	Secret    string `json:"secret"`     // The token secret UUID
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

const (
	tokenConfigFile = ".proxmox_token.json"
	tokenName       = "slimrmm"
	tokenUser       = "root@pam"
	tokenComment    = "SlimRMM Agent API Token"
	cmdTimeout      = 30 * time.Second
)

var (
	tokenMu     sync.RWMutex
	cachedToken *TokenConfig
)

// GetOrCreateToken retrieves existing token or creates a new one.
// This requires the agent to run with root privileges on a Proxmox host.
func GetOrCreateToken(ctx context.Context, configDir string) (*TokenConfig, error) {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	// Check cached token first
	if cachedToken != nil {
		return cachedToken, nil
	}

	// Try to load existing token from file
	tokenPath := filepath.Join(configDir, tokenConfigFile)
	if token, err := loadTokenFromFile(tokenPath); err == nil {
		// Verify token still exists in Proxmox
		if verifyToken(ctx, token.TokenID) {
			cachedToken = token
			return token, nil
		}
		// Token invalid, will create new one
	}

	// Check if we can create tokens (requires root)
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("creating API tokens requires root privileges")
	}

	// Create new token
	token, err := createToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create API token: %w", err)
	}

	// Save token to file with restricted permissions
	if err := saveTokenToFile(tokenPath, token); err != nil {
		// Log warning but continue - token is still valid
		fmt.Fprintf(os.Stderr, "warning: failed to save token to file: %v\n", err)
	}

	cachedToken = token
	return token, nil
}

// createToken creates a new API token using pvesh.
func createToken(ctx context.Context) (*TokenConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	tokenID := fmt.Sprintf("%s!%s", tokenUser, tokenName)

	// First, try to delete existing token (ignore errors)
	deleteCmd := exec.CommandContext(ctx, "pvesh", "delete",
		fmt.Sprintf("/access/users/%s/token/%s", tokenUser, tokenName))
	deleteCmd.Run() // Ignore errors - token might not exist

	// Generate a secure random secret
	secret, err := generateSecureSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Create new token with pvesh
	// Using POST to create token with specific value
	createCmd := exec.CommandContext(ctx, "pvesh", "create",
		fmt.Sprintf("/access/users/%s/token/%s", tokenUser, tokenName),
		"--privsep", "0", // No privilege separation - use user's privileges
		"--comment", tokenComment,
		"--output-format", "json",
	)

	output, err := createCmd.Output()
	if err != nil {
		// Try alternative method using pveum
		return createTokenWithPveum(ctx)
	}

	// Parse response to get the generated token value
	var response struct {
		FullTokenID string `json:"full-tokenid"`
		Value       string `json:"value"`
	}

	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if response.Value == "" {
		response.Value = secret
	}

	return &TokenConfig{
		TokenID:   tokenID,
		Secret:    response.Value,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// createTokenWithPveum creates token using pveum command (alternative method).
func createTokenWithPveum(ctx context.Context) (*TokenConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	tokenID := fmt.Sprintf("%s!%s", tokenUser, tokenName)

	// Delete existing token first
	deleteCmd := exec.CommandContext(ctx, "pveum", "user", "token", "remove",
		tokenUser, tokenName)
	deleteCmd.Run() // Ignore errors

	// Create new token
	createCmd := exec.CommandContext(ctx, "pveum", "user", "token", "add",
		tokenUser, tokenName,
		"--privsep", "0",
		"--comment", tokenComment,
		"--output-format", "json",
	)

	output, err := createCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pveum token creation failed: %w", err)
	}

	// Parse the response
	var response struct {
		FullTokenID string `json:"full-tokenid"`
		Value       string `json:"value"`
	}

	if err := json.Unmarshal(output, &response); err != nil {
		// Try to parse as plain text (older Proxmox versions)
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "value:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					response.Value = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	if response.Value == "" {
		return nil, fmt.Errorf("failed to extract token value from response")
	}

	return &TokenConfig{
		TokenID:   tokenID,
		Secret:    response.Value,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// verifyToken checks if a token is still valid in Proxmox.
func verifyToken(ctx context.Context, tokenID string) bool {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	parts := strings.SplitN(tokenID, "!", 2)
	if len(parts) != 2 {
		return false
	}

	user := parts[0]
	token := parts[1]

	cmd := exec.CommandContext(ctx, "pvesh", "get",
		fmt.Sprintf("/access/users/%s/token/%s", user, token),
		"--output-format", "json",
	)

	return cmd.Run() == nil
}

// loadTokenFromFile loads token configuration from a JSON file.
func loadTokenFromFile(path string) (*TokenConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var token TokenConfig
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	if token.TokenID == "" || token.Secret == "" {
		return nil, fmt.Errorf("invalid token configuration")
	}

	return &token, nil
}

// saveTokenToFile saves token configuration to a JSON file with restricted permissions.
func saveTokenToFile(path string, token *TokenConfig) error {
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}

	// Write with restricted permissions (0600 - owner read/write only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}

	// Ensure permissions are correct even if file existed
	return os.Chmod(path, 0600)
}

// generateSecureSecret generates a cryptographically secure random secret.
func generateSecureSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// DeleteToken removes the API token from Proxmox and local storage.
func DeleteToken(ctx context.Context, configDir string) error {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	// Delete from Proxmox
	cmd := exec.CommandContext(ctx, "pvesh", "delete",
		fmt.Sprintf("/access/users/%s/token/%s", tokenUser, tokenName))
	cmd.Run() // Ignore errors

	// Delete local file
	tokenPath := filepath.Join(configDir, tokenConfigFile)
	os.Remove(tokenPath) // Ignore errors

	cachedToken = nil
	return nil
}

// ClearCachedToken clears the in-memory cached token.
func ClearCachedToken() {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	cachedToken = nil
}

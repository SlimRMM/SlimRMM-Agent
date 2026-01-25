package handler

import (
	"testing"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
)

func TestFilterWingetUpdates(t *testing.T) {
	updates := []actions.Update{
		{Name: "App1", Source: "winget", KB: "app1"},
		{Name: "App2", Source: "windows_update", KB: "kb123"},
		{Name: "App3", Source: "winget", KB: "app3"},
	}

	result := filterWingetUpdates(updates)

	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2", len(result))
	}

	for _, u := range result {
		if u.Source != "winget" {
			t.Errorf("unexpected source %s, want winget", u.Source)
		}
	}
}

func TestApplyWingetFilterModeAll(t *testing.T) {
	updates := []actions.Update{
		{Name: "App1", KB: "app1"},
		{Name: "App2", KB: "app2"},
	}

	result := applyWingetFilterMode(updates, "all", nil)
	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2", len(result))
	}
}

func TestApplyWingetFilterModeWhitelist(t *testing.T) {
	updates := []actions.Update{
		{Name: "App1", KB: "app1"},
		{Name: "App2", KB: "app2"},
		{Name: "App3", KB: "app3"},
	}

	result := applyWingetFilterMode(updates, "whitelist", []string{"app1", "app3"})
	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2", len(result))
	}

	// Check correct apps are included
	found := make(map[string]bool)
	for _, u := range result {
		found[u.KB] = true
	}
	if !found["app1"] || !found["app3"] {
		t.Error("expected app1 and app3 to be in result")
	}
}

func TestApplyWingetFilterModeBlacklist(t *testing.T) {
	updates := []actions.Update{
		{Name: "App1", KB: "app1"},
		{Name: "App2", KB: "app2"},
		{Name: "App3", KB: "app3"},
	}

	result := applyWingetFilterMode(updates, "blacklist", []string{"app2"})
	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2", len(result))
	}

	// Check correct apps are included (app2 excluded)
	for _, u := range result {
		if u.KB == "app2" {
			t.Error("app2 should have been filtered out")
		}
	}
}

func TestDetermineWingetPolicyStatus(t *testing.T) {
	tests := []struct {
		name      string
		succeeded int
		failed    int
		want      string
	}{
		{"all succeeded", 5, 0, "completed"},
		{"all failed", 0, 5, "failed"},
		{"partial success", 3, 2, "partial"},
		{"none processed", 0, 0, "completed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineWingetPolicyStatus(tt.succeeded, tt.failed)
			if result != tt.want {
				t.Errorf("determineWingetPolicyStatus(%d, %d) = %s, want %s",
					tt.succeeded, tt.failed, result, tt.want)
			}
		})
	}
}

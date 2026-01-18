//go:build !darwin

package homebrew

import (
	"context"
	"fmt"
)

// ArtifactType represents the type of installable artifact found.
type ArtifactType string

const (
	ArtifactApp     ArtifactType = "app"
	ArtifactPkg     ArtifactType = "pkg"
	ArtifactDmg     ArtifactType = "dmg"
	ArtifactZip     ArtifactType = "zip"
	ArtifactUnknown ArtifactType = "unknown"
)

// ExtractedArtifact represents the result of extracting/finding installable content.
type ExtractedArtifact struct {
	Type    ArtifactType
	Path    string
	AppName string
	Cleanup []string
}

// DetectArtifactType is not available on non-macOS platforms.
func DetectArtifactType(filePath string) ArtifactType {
	return ArtifactUnknown
}

// ExtractAndFindArtifact is not available on non-macOS platforms.
func ExtractAndFindArtifact(ctx context.Context, downloadPath, tempDir string) (*ExtractedArtifact, error) {
	return nil, fmt.Errorf("archive extraction only available on macOS")
}

// CleanupArtifact is a no-op on non-macOS platforms.
func CleanupArtifact(ctx context.Context, artifact *ExtractedArtifact) {}

// InstallArtifact is not available on non-macOS platforms.
func InstallArtifact(ctx context.Context, artifact *ExtractedArtifact) (string, int, error) {
	return "", -1, fmt.Errorf("artifact installation only available on macOS")
}

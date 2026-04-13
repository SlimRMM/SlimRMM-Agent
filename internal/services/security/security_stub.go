//go:build !windows && !linux && !darwin

package security

// CollectSecurityInfo returns a stub result for unsupported platforms.
// All fields default to false with empty details.
func CollectSecurityInfo() *Info {
	return &Info{}
}

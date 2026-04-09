// Package remotedesktop provides remote desktop management services via RustDesk.
package remotedesktop

// ConnectResult contains the result of a remote desktop connect request.
type ConnectResult struct {
	ID       string `json:"id"`
	Password string `json:"password,omitempty"`
	Status   Status `json:"status"`
}

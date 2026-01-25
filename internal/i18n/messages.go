// Package i18n provides internationalization support for user-facing messages.
package i18n

// Message keys for internationalization.
// All user-facing strings should be defined here as constants.

// Connection and Network Messages
const (
	MsgConnecting           = "connecting to server"
	MsgConnectingStatus     = "connecting to server (status %d)"
	MsgNotConnected         = "not connected"
	MsgAgentStarted         = "Agent started successfully"
	MsgConnectionSuccessful = "Connection successful"
	MsgReadingMessage       = "reading message"
	MsgWritingMessage       = "writing message"
	MsgWritingPing          = "writing ping"
)

// Request Validation Messages
const (
	MsgInvalidRequest         = "invalid request"
	MsgRequestValidationFailed = "request validation failed"
	MsgPathValidationFailed   = "path validation failed"
	MsgSourcePathValidation   = "source path validation failed"
	MsgDestPathValidation     = "destination path validation failed"
	MsgURLValidationFailed    = "url validation failed"
	MsgInvalidMode            = "invalid mode"
)

// Encryption and Security Messages
const (
	MsgInvalidEncryptionKey   = "invalid encryption key"
	MsgEncryptionKeyLength    = "encryption key must be 32 bytes for AES-256"
	MsgCreatingCipher         = "creating cipher"
	MsgCreatingGCM            = "creating GCM"
	MsgGeneratingNonce        = "generating nonce"
	MsgCiphertextTooShort     = "ciphertext too short"
	MsgEncryptionFailed       = "encryption failed"
	MsgDecryptionFailed       = "decryption failed"
)

// Backup Operation Messages
const (
	MsgBackupStatusFailed     = "Status: failed"
	MsgBackupStatusSuccess    = "Status: success"
	MsgUnknownBackupType      = "unknown backup type: %s"
	MsgCreatingCompressor     = "failed to create compressor"
	MsgCompressionFailed      = "compression failed"
	MsgUploadFailed           = "upload failed"
	MsgUploadFailedStatus     = "upload failed with status %d: %s"
	MsgDownloadFailed         = "download failed: %v"
	MsgDownloadFailedStatus   = "download failed with status %d: %s"
	MsgCreatingRequest        = "creating request"
	MsgUploading              = "uploading"
	MsgDownloading            = "downloading"
	MsgNoBackupResult         = "no backup result returned"
	MsgBackupFailed           = "backup failed: %s"
	MsgBackupStatusNotImpl    = "Backup status tracking not implemented for synchronous operations"
)

// Certificate Messages
const (
	MsgParsingServerURL    = "parsing server URL"
	MsgRenewalFailed       = "renewal failed with status %d"
	MsgParsingResponse     = "parsing response"
	MsgSavingCertificates  = "saving certificates"
)

// File Operation Messages
const (
	MsgReadingDirectory    = "reading directory"
	MsgCreatingDirectory   = "creating directory"
	MsgCreatingFile        = "creating file"
	MsgWritingFile         = "writing file"
	MsgWritingChunk        = "writing chunk"
	MsgOpeningFile         = "opening file for hash"
	MsgCalculatingHash     = "calculating hash"
	MsgCannotDownloadDir   = "cannot download directory"
	MsgFileTooLarge        = "file too large: %d > %d"
	MsgReadingComposeFile  = "failed to read compose file"
)

// Session Messages
const (
	MsgSessionExists    = "session %s already exists"
	MsgSessionNotFound  = "session %s not found"
	MsgTerminalExists   = "terminal %s already exists"
	MsgTerminalNotFound = "terminal %s not found"
	MsgTerminalNotRunning = "terminal %s is not running"
	MsgStartingPTY      = "starting PTY"
)

// Platform Compatibility Messages
const (
	MsgUnsupportedOS            = "unsupported OS: %s"
	MsgNoPackageManager         = "no supported package manager found"
	MsgHomebrewNotFound         = "homebrew not found"
	MsgDockerNotAvailable       = "docker is not available on this system"
	MsgProxmoxNotHost           = "this system is not a Proxmox host"
	MsgHyperVWindowsOnly        = "hyper-v backups are only supported on Windows"
	MsgWingetWindowsOnly        = "winget is only available on Windows"
	MsgWingetNotAvailable       = "winget is not available on this system"
	MsgServiceNotSupported      = "service management not supported on this platform"
	MsgBashNotOnWindows         = "bash not available on Windows"
	MsgShNotOnWindows           = "sh not available on Windows"
)

// Docker Messages
const (
	MsgDockerInfoFailed        = "failed to get docker info"
	MsgDockerInfoParseFailed   = "failed to parse docker info"
	MsgContainerListFailed     = "failed to list containers"
	MsgContainerNotFound       = "container not found"
	MsgContainerActionFailed   = "failed to %s container: %s"
	MsgContainerRemoveFailed   = "failed to remove container"
	MsgContainerLogsFailed     = "failed to get logs"
	MsgContainerStatsFailed    = "failed to get stats"
	MsgContainerStatsParse     = "failed to parse stats"
	MsgContainerExportFailed   = "failed to export container"
	MsgContainerImportFailed   = "failed to import container"
	MsgContainerInspectFailed  = "failed to inspect container"
	MsgContainerInspectParse   = "failed to parse inspect output"
	MsgImageListFailed         = "failed to list images"
	MsgImageRemoveFailed       = "failed to remove image"
	MsgImagePullFailed         = "failed to pull image"
	MsgImageLoadFailed         = "failed to load image"
	MsgImageSaveFailed         = "failed to save image"
	MsgVolumeListFailed        = "failed to list volumes"
	MsgVolumeRemoveFailed      = "failed to remove volume"
	MsgVolumeArchiveFailed     = "failed to archive volume"
	MsgVolumeRestoreFailed     = "failed to restore volume data"
	MsgNetworkListFailed       = "failed to list networks"
	MsgComposeActionInvalid    = "invalid compose action: %s"
	MsgComposeActionFailed     = "failed to %s compose: %s"
	MsgPruneImagesFailed       = "failed to prune images"
	MsgPruneVolumesFailed      = "failed to prune volumes"
	MsgPruneNetworksFailed     = "failed to prune networks"
	MsgPruneSystemFailed       = "failed to prune system"
	MsgUnhealthyListFailed     = "failed to list unhealthy containers"
	MsgInvalidAction           = "invalid action: %s"
)

// Docker Backup/Restore Messages
const (
	MsgContainerIDRequired   = "container_id is required for docker_container backup"
	MsgVolumeNameRequired    = "volume_name is required for docker_volume backup"
	MsgImageNameRequired     = "image_name is required for docker_image backup"
	MsgComposePathRequired   = "compose_path is required for docker_compose backup"
	MsgNoExportData          = "no export_data found in backup"
	MsgNoVolumeData          = "no volume_data found in backup"
	MsgNoImageData           = "no image_data found in backup"
	MsgParseBackupData       = "failed to parse backup data"
	MsgDecodeExportData      = "failed to decode export data"
	MsgDecodeVolumeData      = "failed to decode volume data"
	MsgDecodeImageData       = "failed to decode image data"
	MsgCreateTempFile        = "failed to create temp file"
	MsgWriteExportData       = "failed to write export data"
)

// Proxmox Messages
const (
	MsgProxmoxVMIDRequired     = "vmid is required for proxmox_vm backup"
	MsgProxmoxLXCIDRequired    = "vmid is required for proxmox_lxc backup"
	MsgProxmoxClientFailed     = "failed to create Proxmox client"
	MsgProxmoxTokenSaved       = "Token saved successfully"
)

// Hyper-V Messages
const (
	MsgHyperVVMNameRequired     = "vm_name is required for hyperv_vm backup"
	MsgHyperVCheckpointRequired = "vm_name is required for hyperv_checkpoint backup"
	MsgHyperVInvalidVMName      = "invalid VM name: contains disallowed characters"
	MsgHyperVInvalidCheckpoint  = "invalid checkpoint name: contains disallowed characters"
	MsgHyperVGetVMInfo          = "failed to get VM info"
	MsgHyperVExportDir          = "failed to create export directory"
	MsgHyperVExportVM           = "failed to export VM"
	MsgHyperVArchiveExport      = "failed to archive export"
	MsgHyperVCheckpointCreate   = "failed to create checkpoint"
)

// Service Management Messages
const (
	MsgServiceNotFound     = "service not found"
	MsgServiceExists       = "service already exists"
	MsgServiceNameRequired = "service name is required"
	MsgParsingTemplate     = "parsing template"
	MsgCreatingUnitFile    = "creating unit file"
	MsgWritingUnitFile     = "writing unit file"
	MsgReloadingSystemd    = "reloading systemd"
	MsgEnablingService     = "enabling service"
	MsgRemovingUnitFile    = "removing unit file"
	MsgStartingService     = "starting service: %s"
	MsgStoppingService     = "stopping service: %s"
	MsgRestartingService   = "restarting service: %s"
	MsgDisablingService    = "disabling service: %s"
	MsgMaskingService      = "masking service: %s"
	MsgInvalidStartType    = "invalid start type: %s (valid: auto, manual, disabled)"
	MsgListingServices     = "listing services"
	MsgCreatingService     = "creating service: %s"
	MsgDeletingService     = "deleting service: %s"
	MsgServiceStartTimeout = "Timeout waiting for service to start"
	MsgSchedulingRestart   = "scheduling restart"
	MsgChangingStartup     = "changing startup type: %s"
	MsgCreatingPlist       = "creating plist file"
	MsgWritingPlist        = "writing plist file"
	MsgSettingPermissions  = "setting permissions"
	MsgRemovingPlist       = "removing plist file"
	MsgPlistNotFound       = "service plist not found: %s"
	MsgLoadingService      = "loading service: %s"
)

// Command Execution Messages
const (
	MsgCommandBlocked      = "command blocked: %s"
	MsgDangerousPattern    = "dangerous pattern detected: %s"
	MsgSensitiveCommand    = "sensitive command requires authorization: %s"
	MsgCommandNotWhitelist = "command not in whitelist: %s"
	MsgEmptyCommand        = "empty command"
	MsgCommandValidation   = "command validation failed"
	MsgScriptDangerous     = "script contains potentially dangerous patterns"
)

// Update Messages
const (
	MsgCheckingUpdate      = "checking for update"
	MsgAlreadyLatest       = "already running the latest version"
	MsgNoUpdateAvailable   = "no update available"
	MsgUpdateStatusFailed  = "Status: failed"
	MsgAgentUpdated        = "agent updated successfully"
	MsgInstallingOsquery   = "installing osquery"
	MsgOsqueryInstalled    = "osquery installed successfully"
	MsgGetUpdatesFailed    = "failed to get updates: %v"
)

// Winget Messages
const (
	MsgWingetAlreadyInstalled = "winget is already installed"
	MsgWingetInstallFailed    = "installation failed: %v"
	MsgWingetNeedsRestart     = "winget installed but not yet available, may require system restart"
	MsgWingetInstalled        = "winget installed successfully"
)

// Registry Messages (Windows)
const (
	MsgRegistryValueNotFound = "registry value not found: %s"
	MsgInvalidRegistryPath   = "invalid registry path: %s"
	MsgUnknownRegistryRoot   = "unknown registry root key: %s"
)

// User/Group Messages
const (
	MsgUnknownUser  = "unknown user: %s"
	MsgUnknownGroup = "unknown group: %s"
)

// Config Messages
const (
	MsgDecodingConfig = "decoding config"
	MsgWritingConfig  = "writing config"
	MsgMarshalingCompliance = "marshaling compliance results"
	MsgWritingComplianceCache = "writing compliance cache"
)

// Status Codes (for response messages)
const (
	StatusSuccess = "success"
	StatusFailed  = "failed"
	StatusError   = "error"
)

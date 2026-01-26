# Working Document

## Last Update
2026-01-25T11:00:00Z

## Current Status
Completed - Architecture Refactoring (i18n, HTTP abstraction, backup services, heartbeat helpers)

## Open Tasks

### Test Coverage (Priority)
- [x] Add tests for `internal/helper` (platform-specific helpers) - 100%
- [x] Add tests for `internal/installer` (installation logic) - 4.0%
- [x] Add tests for `internal/remotedesktop` (remote desktop functionality) - 0.5%
- [x] Add tests for `internal/services/registry` (Windows-only) - 100%
- [x] Add tests for `internal/winget` (Windows-only) - 29.1%
- [ ] Add tests for `cmd/slimrmm-agent` (main entry point)

### Low Coverage Packages (Need Improvement)
- [x] `internal/actions` - 7.4% coverage (improved from 6.9%)
- [ ] `internal/handler` - 1.8% coverage
- [x] `internal/service` - 8.0% coverage (improved from 1.1%)
- [ ] `internal/homebrew` - 2.3% coverage
- [x] `internal/hyperv` - 6.4% coverage (improved from 1.4%)
- [x] `internal/proxmox` - 8.1% coverage (improved from 3.4%)
- [ ] `internal/osquery` - 4.5% coverage
- [ ] `internal/updater` - 6.4% coverage
- [ ] `internal/services/software` - 8.5% coverage
- [x] `internal/monitor` - 27.4% coverage (improved from 16.2%)

### Architecture Review ✅ COMPLETED
- [x] Review backup.go (handler) for service layer refactoring (3,957 lines) - See MVC-Violations above
- [ ] Add integration tests for backup operations

## Findings

### Test Coverage Summary
| Package | Coverage | Status |
|---------|----------|--------|
| internal/security | 100.0% | ✅ Complete |
| internal/services/filesystem | 100.0% | ✅ Complete |
| internal/services/registry | 100.0% | ✅ Complete |
| internal/helper | 100.0% | ✅ Complete |
| pkg/version | 100.0% | ✅ Complete |
| internal/security/ratelimit | 94.2% | ✅ High |
| internal/security/terminal | 94.8% | ✅ High |
| internal/security/sandbox | 90.3% | ✅ High |
| internal/config | 90.0% | ✅ High |
| internal/security/urlval | 89.9% | ✅ High |
| internal/security/pathval | 83.3% | ✅ High |
| internal/security/mtls | 81.6% | ✅ High |
| internal/security/archive | 77.5% | ✅ High |
| internal/logging | 77.1% | ✅ High |
| internal/security/audit | 76.1% | ✅ High |
| internal/security/antireplay | 75.8% | ✅ High |
| internal/services/wol | 68.3% | 🟡 Medium |
| internal/tamper | 63.8% | 🟡 Medium |
| internal/selfhealing | 54.9% | 🟡 Medium |
| internal/services/process | 49.1% | 🟡 Medium |
| internal/services/compliance | 38.0% | 🟡 Medium |
| internal/winget | 29.1% | 🟡 Medium |
| internal/monitor | 27.4% | 🟡 Medium |
| internal/services/validation | 16.7% | 🔴 Low |
| internal/services/software | 8.5% | 🔴 Low |
| internal/updater | 6.4% | 🔴 Low |
| internal/osquery | 4.5% | 🔴 Low |
| internal/installer | 4.0% | 🔴 Low |
| internal/proxmox | 8.1% | 🔴 Low |
| internal/homebrew | 2.3% | 🔴 Low |
| internal/handler | 1.8% | 🔴 Low |
| internal/hyperv | 6.4% | 🔴 Low |
| internal/actions | 6.9% | 🔴 Low |
| internal/service | 8.0% | 🔴 Low |
| internal/remotedesktop | 0.5% | 🔴 Low |

### Packages Without Tests (1 remaining)
1. `cmd/slimrmm-agent` - Main entry point (typically integration tested)

### Hardcoded Strings (i18n) ✅ COMPLETED
**Total: 350+ hardcoded strings identified**

| File | Count | Priority |
|------|-------|----------|
| internal/handler/backup.go | 90+ | HIGH |
| internal/handler/actions.go | 50+ | HIGH |
| internal/handler/software.go | 20+ | HIGH |
| internal/handler/software_uninstall.go | 30+ | HIGH |
| internal/actions/terminal.go | 10 | HIGH |
| internal/actions/system.go | 8 | HIGH |
| internal/actions/files.go | 15 | HIGH |
| internal/actions/commands.go | 10 | HIGH |
| internal/actions/transfer.go | 20 | HIGH |
| internal/actions/docker.go | 30+ | HIGH |
| internal/actions/software.go | 10 | HIGH |
| internal/service/systemd.go | 12 | HIGH |
| internal/service/launchd.go | 10 | HIGH |
| internal/service/windows.go | 10 | HIGH |

**Key Pattern Categories:**
1. Connection errors: "connecting to server", "not connected"
2. Validation errors: "invalid request", "path validation failed"
3. Resource errors: "not found", "already exists"
4. Platform errors: "unsupported OS", "not supported on this platform"
5. Operation failures: "failed to...", status messages
6. Feature availability: Docker, Proxmox, Hyper-V, winget checks
7. Status messages: "Connection successful", "installed successfully"

**Recommended Action:** Create `internal/i18n/` package with translatable message keys

### MVC-Violations ✅ COMPLETED
**Critical architectural issues identified**

#### Critical Files (3,000+ lines)
| File | Lines | Severity | Main Issues |
|------|-------|----------|-------------|
| backup.go | 3,957 | CRITICAL | HTTP ops, DB ops, encryption, file ops in handler |
| actions.go | 3,251 | HIGH | WebSocket ops mixed with business logic (~38 SendRaw calls) |
| software.go | 755 | MEDIUM | HTTP download implementation in handler |
| handler.go | 1,535 | MEDIUM | sendHeartbeat() 251 lines |

#### Violation Types Found
1. **HTTP in Handlers** (3 locations)
   - backup.go:906-931 `uploadBackupData()`
   - backup.go:1271-1293 `downloadBackupData()`
   - software.go:268-350 `downloadFile()`

2. **Database Operations in Handlers**
   - backup.go:3460-3574 PostgreSQL backup (pg_dump)
   - backup.go:3577-3719 MySQL backup (mysqldump)

3. **Functions >200 lines** (3 remaining, 1 fixed)
   - backup.go:3094-3306 `restoreFilesAndFoldersWithProgress()` (213 lines)
   - actions.go:2103-2328 `handleExecuteWingetPolicy()` (226 lines)
   - actions.go:2602-2884 `handleExecuteWingetUpdate()` (283 lines)
   - ~~handler.go:981-1231 `sendHeartbeat()` (251 lines)~~ ✅ FIXED (now 30 lines)

4. **WebSocket in Business Logic**
   - ~50+ `h.SendRaw()` calls embedded in handlers
   - Should use callback/observer pattern

#### Refactoring Progress
1. **PHASE 1**: Extract HTTP abstraction layer ✅ DONE (`internal/http/client.go`)
2. **PHASE 2**: Separate WebSocket concerns (callback pattern) ✅ DONE (`internal/services/backup/progress.go`)
3. **PHASE 3**: Split backup.go into services ✅ STARTED (`internal/services/backup/`)
4. **PHASE 4**: Extract database backup services ✅ DONE (`postgresql_collector.go`, `mysql_collector.go`)
5. **PHASE 5**: Consolidate Winget operations - Pending

#### Proposed backup.go Restructure
```
internal/services/backup/
├── collector.go (interface)
├── compressor.go
├── encryptor.go
├── uploader.go
├── downloader.go
├── agent_collector.go
├── docker_collector.go
├── proxmox_collector.go
├── hyperv_collector.go
├── postgresql_collector.go
├── mysql_collector.go
├── files_folders_collector.go
├── restorer.go (interface)
└── *_restorer.go (per type)
```

### Security Review
- [ ] Pending full security audit

### Dependency Updates
- [ ] Pending dependency audit

### RBAC Review
- [ ] Pending RBAC audit

### Audit-System Integration
- [ ] Pending audit system review

### Build Status
- [ ] Pending GitHub Actions verification

## Completed Tasks

### Architecture Refactoring (2026-01-25)
- [x] Created `internal/i18n/messages.go` with 150+ message constants for internationalization
- [x] Created `internal/http/client.go` with HTTP client abstraction (Download, Upload, ProgressCallback)
- [x] Created `internal/http/client_test.go` with 16 tests (100% coverage)
- [x] Created `internal/services/backup/` package:
  - `collector.go` - Collector interface and registry
  - `compressor.go` - GzipCompressor with compression levels
  - `encryptor.go` - AESEncryptor with AES-256-GCM
  - `errors.go` - Typed errors for backup operations
  - `progress.go` - ProgressReporter interface (callback/channel/noop)
  - `postgresql_collector.go` - PostgreSQL backup via pg_dump
  - `mysql_collector.go` - MySQL backup via mysqldump
  - `backup_test.go` - 18 tests for backup services
- [x] Refactored `handler.go:sendHeartbeat()` from 251 lines to 30 lines
- [x] Created `internal/handler/heartbeat_helpers.go` with extracted helper functions:
  - `buildDiskStats()`, `aggregateNetworkIO()`, `buildBaseHeartbeat()`
  - `addProxmoxInfo()`, `addHyperVInfo()`, `addDockerInfo()`, `addWingetInfo()`
  - `handleWingetMaintenance()`, winget auto-install/update helpers
- [x] Created `internal/handler/heartbeat_helpers_test.go` with 5 tests

### Previous Work
- [x] Hardcoded Strings (i18n) audit - 350+ strings identified across 14 files
- [x] MVC-Violations architecture review - Critical issues in backup.go (3,957 lines)
- [x] Created test file: `internal/security/security_test.go` (100% coverage)
- [x] Fixed test file: `internal/monitor/monitor_test.go` (16.2% coverage)
- [x] Created test file: `internal/services/process/process_test.go` (49.1% coverage)
- [x] Created test file: `internal/services/filesystem/filesystem_test.go` (100% coverage)
- [x] Created test file: `internal/updater/updater_test.go` (6.4% coverage)
- [x] Created test file: `internal/osquery/osquery_test.go` (4.5% coverage)
- [x] Created test file: `internal/proxmox/proxmox_test.go` (3.4% coverage)
- [x] Created test file: `internal/service/service_test.go` (1.1% coverage)
- [x] Created test file: `internal/services/software/software_test.go` (8.5% coverage)
- [x] Created test file: `internal/homebrew/homebrew_test.go` (2.3% coverage)
- [x] Created test file: `internal/helper/helper_test.go` (100% coverage)
- [x] Created test file: `internal/installer/installer_test.go` (4.0% coverage)
- [x] Created test file: `internal/remotedesktop/remotedesktop_test.go` (0.5% coverage)
- [x] Created test file: `internal/services/registry/registry_test.go` (100% coverage)
- [x] Created test file: `internal/winget/winget_test.go` (29.1% coverage)

## Notes
- 36 packages now have tests (up from ~5 originally)
- 16 packages have >70% coverage
- 5 packages have 100% coverage
- Only 1 package without tests remains: cmd/slimrmm-agent (main entry point)
- Plan file exists at `/Users/maltekiefer/.claude/plans/breezy-waddling-wolf.md` for backup features

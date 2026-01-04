# macOS Code Signing & Notarization

This guide explains how to set up Apple code signing for the SlimRMM Agent. Code signing is essential for:
- Preventing permission re-prompts after updates
- Avoiding Gatekeeper warnings
- Professional distribution

## Why Code Signing Matters

Without code signing:
- macOS tracks permissions by binary hash
- Every update = new hash = new app = permissions lost
- Users must re-authorize Screen Recording & Accessibility after each update

With code signing:
- macOS tracks permissions by Team ID + Bundle ID
- Updates maintain the same identity
- Permissions persist across updates

## Prerequisites

1. **Apple Developer Account** ($99/year)
   - Sign up at https://developer.apple.com

2. **Developer ID Application Certificate**
   - Required for distributing apps outside the App Store
   - Created in Xcode or Apple Developer Portal

## Step 1: Create Developer ID Certificate

### Option A: Using Xcode
1. Open Xcode → Settings → Accounts
2. Select your Apple ID
3. Click "Manage Certificates"
4. Click "+" → "Developer ID Application"

### Option B: Using Apple Developer Portal
1. Go to https://developer.apple.com/account/resources/certificates
2. Click "+" to create a new certificate
3. Select "Developer ID Application"
4. Follow the CSR creation instructions
5. Download and install the certificate

## Step 2: Export Certificate as .p12

1. Open **Keychain Access**
2. Find your "Developer ID Application" certificate
3. Right-click → Export
4. Save as .p12 format
5. Set a strong password (you'll need this later)

## Step 3: Create App-Specific Password

Apple requires an app-specific password for notarization:

1. Go to https://appleid.apple.com
2. Sign in → Security → App-Specific Passwords
3. Click "Generate" and name it "SlimRMM Notarization"
4. Save the generated password

## Step 4: Find Your Team ID

1. Go to https://developer.apple.com/account
2. Click "Membership" in the sidebar
3. Your Team ID is listed there (10 characters, e.g., "ABC1234DEF")

## Step 5: Configure GitHub Secrets

Go to your repository: Settings → Secrets and variables → Actions

Add these secrets:

| Secret Name | Description | How to Get |
|-------------|-------------|------------|
| `APPLE_CERTIFICATE_P12_BASE64` | Base64-encoded .p12 file | See below |
| `APPLE_CERTIFICATE_PASSWORD` | Password for the .p12 file | The password you set when exporting |
| `APPLE_ID` | Your Apple ID email | Your Apple Developer account email |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password | From Step 3 |
| `APPLE_TEAM_ID` | Your 10-character Team ID | From Step 4 |

### Encoding the Certificate

```bash
# On macOS, encode your .p12 file to base64:
base64 -i path/to/certificate.p12 | pbcopy

# The base64 string is now in your clipboard
# Paste it as the APPLE_CERTIFICATE_P12_BASE64 secret
```

## Step 6: Verify Setup

After adding all secrets, push a commit to trigger a build. The workflow will:

1. Import the certificate into a temporary keychain
2. Sign the binary with hardened runtime
3. Sign the app bundle
4. Build the PKG installer
5. Submit for notarization (takes 2-10 minutes)
6. Staple the notarization ticket to the PKG

Check the GitHub Actions log for any errors.

## Troubleshooting

### "No identity found"
- Certificate not properly imported
- Check that the .p12 was base64 encoded correctly

### "Notarization failed"
- Check that app-specific password is correct
- Ensure Team ID matches the certificate
- Check Apple's notarization status: https://developer.apple.com/system-status/

### "Could not find signing identity"
- The certificate must be a "Developer ID Application" type
- Make sure you exported the certificate with its private key

## Local Testing

To test signing locally before CI:

```bash
# Find your signing identity
security find-identity -v -p codesigning

# Sign the binary
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: Your Name (TEAM_ID)" \
  --entitlements build/macos/entitlements.plist \
  /path/to/slimrmm-agent

# Verify signature
codesign --verify --deep --strict /path/to/slimrmm-agent
```

## Security Notes

- Never commit certificates or passwords to the repository
- GitHub secrets are encrypted and only exposed during workflow runs
- The temporary keychain is deleted after each build
- Consider using a dedicated Apple ID for CI/CD

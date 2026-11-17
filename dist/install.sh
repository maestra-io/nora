#!/usr/bin/env bash
set -euo pipefail

# NORA Artifact Registry — install script
# Usage: curl -fsSL https://getnora.io/install.sh | bash
# The binary is installed only after its Sigstore bundle verifies against the
# release workflow's identity; NORA_SKIP_VERIFY=1 installs it unverified.

VERSION="${NORA_VERSION:-latest}"
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nora"
DATA_DIR="/var/lib/nora"
LOG_DIR="/var/log/nora"
SIGNER_IDENTITY='^https://github\.com/getnora-io/nora/\.github/workflows/release\.yml@refs/tags/v[^/]+$'

# Asset names as release.yml publishes them: nora-linux-amd64, nora-linux-arm64.
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac
[ "$OS" = "linux" ] || { echo "Unsupported OS: $OS (release binaries are Linux only)"; exit 1; }

# Private staging directory: nothing is written under a guessable /tmp name.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

fetch() { # url, destination
    if command -v curl &>/dev/null; then
        curl -fsSL -o "$2" "$1"
    elif command -v wget &>/dev/null; then
        wget -qO "$2" "$1"
    else
        echo "Error: curl or wget required"; exit 1
    fi
}

echo "Installing NORA ($OS/$ARCH)..."

# Download binary
if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/getnora-io/nora/releases/latest/download/nora-${OS}-${ARCH}"
else
    DOWNLOAD_URL="https://github.com/getnora-io/nora/releases/download/${VERSION}/nora-${OS}-${ARCH}"
fi

echo "Downloading from $DOWNLOAD_URL..."
fetch "$DOWNLOAD_URL" "$STAGE/nora"

if [ "${NORA_SKIP_VERIFY:-}" = "1" ]; then
    echo "WARNING: NORA_SKIP_VERIFY=1 — installing a binary whose signature was NOT verified." >&2
else
    if ! command -v cosign &>/dev/null; then
        echo "Error: cosign is required to verify the binary: https://docs.sigstore.dev/cosign/system_config/installation/" >&2
        echo "       (set NORA_SKIP_VERIFY=1 to install without verification)" >&2
        exit 1
    fi
    echo "Verifying binary signature..."
    fetch "${DOWNLOAD_URL}.bundle" "$STAGE/nora.bundle"
    cosign verify-blob --bundle "$STAGE/nora.bundle" \
        --certificate-identity-regexp "$SIGNER_IDENTITY" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "$STAGE/nora" || { echo "Error: signature verification failed" >&2; exit 1; }
    echo "Signature verified."
fi

sudo install -o root -g root -m 0755 "$STAGE/nora" "$INSTALL_DIR/nora"

# Create system user
if ! id nora &>/dev/null; then
    sudo useradd --system --shell /usr/sbin/nologin --home-dir "$DATA_DIR" --create-home nora
    echo "Created system user: nora"
fi

# Create directories
sudo mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
sudo chown nora:nora "$DATA_DIR" "$LOG_DIR"

# Install default config if not exists
if [ ! -f "$CONFIG_DIR/nora.env" ]; then
    cat > "$STAGE/nora.env" << 'ENVEOF'
NORA_HOST=::
NORA_PORT=4000
# Clients on other hosts need your real address here (e.g. https://registry.example.com)
NORA_PUBLIC_URL=http://localhost:4000
NORA_STORAGE_PATH=/var/lib/nora
# Absolute path inside ReadWritePaths — the relative built-in default (data/tokens)
# resolves outside the ProtectSystem=strict sandbox and breaks token writes (#816).
NORA_AUTH_TOKEN_STORAGE=/var/lib/nora/tokens
ENVEOF
    sudo install -o nora -g nora -m 0600 "$STAGE/nora.env" "$CONFIG_DIR/nora.env"
    echo "Created default config: $CONFIG_DIR/nora.env"
fi

# Install systemd service
if [ -d /etc/systemd/system ]; then
    cat > "$STAGE/nora.service" << 'SVCEOF'
[Unit]
Description=NORA Artifact Registry
Documentation=https://getnora.dev
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nora
Group=nora
ExecStart=/usr/local/bin/nora serve
# `systemctl reload nora`: re-read config.toml in place (curation policy, see the deployment guide)
ExecReload=/bin/kill -HUP $MAINPID
WorkingDirectory=/etc/nora
Restart=on-failure
RestartSec=5
# A configuration error (EX_CONFIG) stops the service instead of restarting into it
RestartPreventExitStatus=78
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nora /var/log/nora
PrivateTmp=true
EnvironmentFile=-/etc/nora/nora.env

[Install]
WantedBy=multi-user.target
SVCEOF
    sudo install -o root -g root -m 0644 "$STAGE/nora.service" /etc/systemd/system/nora.service
    sudo systemctl daemon-reload
    sudo systemctl enable nora
    echo "Installed systemd service: nora"
fi

echo ""
echo "NORA installed successfully!"
echo ""
echo "  Binary:  $INSTALL_DIR/nora"
echo "  Config:  $CONFIG_DIR/nora.env"
echo "  Data:    $DATA_DIR"
echo "  Version: $(nora --version 2>/dev/null || echo 'unknown')"
echo ""
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/nora.env"
echo "  2. sudo systemctl start nora"
echo "  3. curl http://localhost:4000/health"
echo ""

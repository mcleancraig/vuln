#!/bin/bash

# Setup script for node-vuln systemd service
# Run as root: sudo ./setup-service.sh

set -e

APP_NAME="node-vuln"
APP_USER="node-vuln"
APP_GROUP="node-vuln"
APP_DIR="/opt/node-vuln"
SERVICE_FILE="/etc/systemd/system/node-vuln.service"
ENV_DIR="/etc/node-vuln"
LOG_DIR="/var/log/node-vuln"
[ $(basename $(pwd)) = "setup" ] && cd ..
RUNDIR=$(pwd)
echo "Setting up $APP_NAME systemd service..."

# Create user and group
if ! getent group "$APP_GROUP" > /dev/null 2>&1; then
    echo "Creating group: $APP_GROUP"
    groupadd --system "$APP_GROUP"
fi

if ! getent passwd "$APP_USER" > /dev/null 2>&1; then
    echo "Creating user: $APP_USER"
    useradd --system --gid "$APP_GROUP" --home-dir "$APP_DIR" --shell /bin/false "$APP_USER"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$APP_DIR"
mkdir -p "$APP_DIR/logs"
mkdir -p "$ENV_DIR"
mkdir -p "$LOG_DIR"

# Set permissions
chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
chown -R "$APP_USER:$APP_GROUP" "$LOG_DIR"
chown -R root:root "$ENV_DIR"
chmod 755 "$APP_DIR"
chmod 755 "$LOG_DIR"
chmod 750 "$ENV_DIR"

# Copy application files (assuming they're in current directory)
if [ -f "node-vuln.js" ]; then
    echo "Copying application files..."
    cp node-vuln.js "$APP_DIR/"
    cp package.json "$APP_DIR/"
    cp package-lock.json "$APP_DIR/" 2>/dev/null || true
    chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"

    # Install dependencies
    echo "Installing Node.js dependencies..."
    cd "$APP_DIR"
    sudo -u "$APP_USER" npm install --production
    
    # Set file permissions
    chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
    chmod 644 "$APP_DIR/node-vuln.js"
    chmod 644 "$APP_DIR/package.json"
else
    echo "Warning: node-vuln.js not found in current directory"
    echo "You'll need to manually copy your application files to $APP_DIR"
fi

# Create environment file template
cat > "$ENV_DIR/environment" << 'EOF'
# Environment variables for node-vuln
# Copy this file and customize with your actual values

# Database configuration
DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=your_db_name
ROOT_PASSWORD=<database root password>

# Azure AD configuration
TENANT_ID=your_tenant_id
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret

# Application configuration
SESSION_SECRET=your_session_secret_here
BASE_URL=https://your-domain.com
NODE_ENV=production
PORT=3000

EOF

chmod 640 "$ENV_DIR/environment"
chown root:root "$ENV_DIR/environment"

echo "Created environment template at $ENV_DIR/environment"
echo "IMPORTANT: Edit this file with your actual configuration values!"

# Install systemd service
echo "Installing systemd service..."
echo $(pwd)
cp ${RUNDIR}/setup/node-vuln.service "$SERVICE_FILE"
systemctl daemon-reload

# Create logrotate configuration
cat > /etc/logrotate.d/node-vuln << 'EOF'
/var/log/node-vuln/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 node-vuln node-vuln
    postrotate
        systemctl reload node-vuln > /dev/null 2>&1 || true
    endscript
}
EOF

if [ $(systemctl status rsyslog) -eq 0 ]
then
# Create rsyslog configuration for better logging
cat > /etc/rsyslog.d/30-node-vuln.conf << 'EOF'
# node-vuln logging configuration
:programname, isequal, "node-vuln" /var/log/node-vuln/node-vuln.log
& stop
EOF

systemctl restart rsyslog
fi

echo ""
echo "Setup complete! Next steps:"
echo "1. Edit $ENV_DIR/environment with your actual configuration"
echo "2. Test the configuration:"
echo "   sudo systemctl start node-vuln"
echo "   sudo systemctl status node-vuln"
echo "3. Enable auto-start:"
echo "   sudo systemctl enable node-vuln"
echo "4. View logs:"
echo "   sudo journalctl -u node-vuln -f"
echo "   sudo tail -f /var/log/node-vuln/node-vuln.log"
echo ""
echo "Service commands:"
echo "  sudo systemctl start node-vuln"
echo "  sudo systemctl stop node-vuln"
echo "  sudo systemctl restart node-vuln"
echo "  sudo systemctl reload node-vuln"
echo "  sudo systemctl status node-vuln"

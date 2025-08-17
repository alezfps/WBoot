# Spigot Plugin Bootstrapper System

A comprehensive solution to protect Spigot plugins from reverse engineering while providing seamless updates. This system splits your plugin into a heavily obfuscated bootstrapper and a secure server-side distribution mechanism.

## Overview

This system protects Spigot plugins through a multi-layered approach:

1. **Obfuscated Bootstrapper** - Users download a minimal, heavily obfuscated JAR file
2. **Secure Distribution** - The actual plugin is hosted securely on your VPS
3. **Dynamic Loading** - The real plugin is downloaded and loaded at runtime
4. **Automatic Updates** - Seamless version management without requiring user intervention

### Benefits

- **Anti-Reverse Engineering**: ProGuard obfuscation makes code analysis extremely difficult
- **Automatic Updates**: Deploy updates instantly without requiring user downloads
- **Secure Distribution**: Authentication and rate limiting prevent unauthorized access
- **Usage Analytics**: Track downloads and monitor usage patterns
- **Revenue Protection**: Protect premium plugins from unauthorized distribution

## Features

### Client-Side (Bootstrapper)
- Heavy ProGuard obfuscation with custom dictionaries
- Dynamic plugin loading and initialization
- Version checking and automatic updates
- SSL/TLS encrypted communication
- Bearer token authentication
- Minimal footprint to reduce attack surface

### Server-Side (Distribution)
- **Multiple backends**: Python Flask, Node.js Express, or PHP
- Rate limiting and DDoS protection
- Redis-based caching and session management
- Comprehensive logging and monitoring
- File integrity verification
- IP-based access control
- Automatic SSL certificate management

### Security Features
- Bearer token authentication
- Request signing and validation
- Rate limiting (per IP, per endpoint)
- File type and size validation
- Access logging and monitoring
- fail2ban integration
- Security headers (HSTS, CSP, etc.)

## Architecture

```
┌─────────────────┐    HTTPS/Auth     ┌─────────────────┐
│   Minecraft     │◄─────────────────►│   Your Host     │
│   Server        │                   │                 │
│                 │                   │  ┌─────────────┐│
│ ┌─────────────┐ │   Download        │  │   Web       ││
│ │Bootstrapper │ │   Plugin          │  │  Server     ││
│ │   (3KB)     │ │                   │  │(Nginx/etc.) ││
│ └─────────────┘ │                   │  └─────────────┘│
│                 │                   │  ┌─────────────┐│
│ ┌─────────────┐ │                   │  │ App Server  ││
│ │ Real Plugin │◄┼───────────────────┼──┤   Python    |│
│ │ (Loaded in  │ │                   │  │  Node.js    ││
│ │  Memory)    │ │                   │  └─────────────┘│
│ └─────────────┘ │                   │  ┌─────────────┐│
└─────────────────┘                   │  │   Redis     ││
                                      │  │  (Cache)    ││
                                      │  └─────────────┘│
                                      └─────────────────┘
```

## Quick Start

### Prerequisites
- Java 11+ and Gradle
- VPS with Ubuntu/Debian
- Domain name with DNS pointing to VPS

### 1. Clone 

```bash
git clone https://github.com/alezfps/wboot
cd wboot
```

### 2. Deploy to VPS

Choose your preferred backend:

#### Python Flask
```bash
# On your VPS
curl -O https://raw.githubusercontent.com/yourusername/spigot-bootstrapper/main/deploy_python.sh
chmod +x deploy_python.sh
sudo ./deploy_python.sh yourdomain.com
```

#### Node.js Express
```bash
# On your VPS
curl -O https://raw.githubusercontent.com/yourusername/spigot-bootstrapper/main/deploy_nodejs.sh
chmod +x deploy_nodejs.sh
sudo ./deploy_nodejs.sh yourdomain.com
```

### 3. Upload Your Plugin

```bash
# On your VPS
/var/www/plugins/upload_plugin.sh plugin.jar 1.0.0
```

### 4. Test

```bash
# Test endpoints
curl -H "Authorization: Bearer your-token" https://yourdomain.com/version.txt
curl -H "Authorization: Bearer your-token" https://yourdomain.com/download.jar -o test.jar
```

## Configuration

### Environment Variables

Create a `.env` file in your server directory:

```bash
# Authentication
AUTH_TOKEN=your-super-secure-random-token-minimum-32-characters
SECRET_KEY=another-super-secure-key-for-sessions

# Paths
PLUGIN_DIR=/var/www/plugins
LOG_DIR=/var/www/plugins/logs

# Limits
MAX_DOWNLOAD_SIZE=52428800  # 50MB in bytes
RATE_LIMIT_WINDOW=300       # 5 minutes
RATE_LIMIT_MAX=20          # Max requests per window

# Redis
REDIS_URL=redis://localhost:6379/0

# Server
NODE_ENV=production
PORT=3000
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
    
    location / {
        limit_req zone=api burst=5 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Deployment

### Automated Deployment Scripts

#### Deploy Python Server
```bash
#!/bin/bash
# deploy_python.sh

DOMAIN=$1
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

# Install dependencies
apt update && apt upgrade -y
apt install -y python3.11 python3.11-venv python3-pip redis-server nginx certbot python3-certbot-nginx ufw fail2ban

# Set up application
mkdir -p /var/www/plugin-server /var/www/plugins
cd /var/www/plugin-server

# Create virtual environment
python3.11 -m venv venv
./venv/bin/pip install flask redis flask-limiter gunicorn

# Copy files and set permissions
cp app.py .env gunicorn.conf.py ./
chown -R www-data:www-data /var/www/plugin-server /var/www/plugins

# Configure services
systemctl enable redis-server nginx
systemctl start redis-server

# Set up SSL
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN

# Configure firewall
ufw enable
ufw allow 'Nginx Full'
ufw allow ssh

echo "Python server deployed successfully!"
echo "Update your AUTH_TOKEN in /var/www/plugin-server/.env"
```

#### Deploy Node.js Server
```bash
#!/bin/bash
# deploy_nodejs.sh

DOMAIN=$1
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

# Install Node.js and dependencies
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs redis-server nginx certbot python3-certbot-nginx ufw fail2ban

# Set up application
mkdir -p /var/www/plugin-server /var/www/plugins
cd /var/www/plugin-server

# Install Node.js dependencies
npm init -y
npm install express express-rate-limit helmet redis mime-types

# Copy files
cp server.js package.json .env ./
chown -R www-data:www-data /var/www/plugin-server /var/www/plugins

# Set up PM2
npm install -g pm2
pm2 start server.js --name plugin-server
pm2 startup
pm2 save

# Configure services
systemctl enable redis-server nginx
systemctl start redis-server

# Set up SSL
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN

# Configure firewall
ufw enable
ufw allow 'Nginx Full'
ufw allow ssh

echo "Node.js server deployed successfully!"
echo "Update your AUTH_TOKEN in /var/www/plugin-server/.env"
```

### Manual Deployment Checklist

- [ ] VPS with public IP and domain name
- [ ] SSL certificate installed and configured
- [ ] Application server running (Python/Node.js/PHP)
- [ ] Redis server running
- [ ] Nginx configured as reverse proxy
- [ ] Firewall configured (UFW/iptables)
- [ ] fail2ban configured for intrusion prevention
- [ ] Log rotation configured
- [ ] Monitoring scripts installed
- [ ] AUTH_TOKEN configured and secure
- [ ] Initial plugin uploaded and tested

## Usage

### Building the Bootstrapper

1. **Configure Your Settings**
   ```java
   // In PluginBootstrapper.java
   private static final String SERVER_URL = "https://example.com/";
   private static final String AUTH_TOKEN = "your-secure-auth-token";
   private static final String PLUGIN_NAME = "Example";
   ```

2. **Verify Obfuscation**
   ```bash
   # Check that sensitive strings are obfuscated
   strings build/libs/*-obfuscated.jar | grep -i "yourdomain\|token\|plugin"
   # Should return minimal or no results
   ```

### Managing Plugins on Server

#### Upload New Plugin
```bash
# Using the upload script
./upload_plugin.sh /path/to/new-plugin.jar 1.2.0

# Manual upload
cp new-plugin.jar /var/www/plugins/plugin.jar
echo "1.2.0" > /var/www/plugins/version.txt
chown www-data:www-data /var/www/plugins/plugin.jar /var/www/plugins/version.txt
```

#### Check Server Status
```bash
# Python Flask
sudo systemctl status plugin-server

# Node.js
pm2 status plugin-server

# Check logs
tail -f /var/www/plugins/logs/access.log
tail -f /var/log/nginx/access.log
```

### Client-Side Usage

The bootstrapper automatically:
1. Checks for updates on server startup
2. Downloads the real plugin if needed
3. Loads and initializes the plugin
4. Handles errors gracefully

Users simply install the obfuscated bootstrapper JAR like any normal plugin.

## Security

### Authentication Security

**Bearer Token Requirements:**
- Minimum 32 characters
- Cryptographically random
- Rotated periodically
- Never logged in plain text

```bash
# Generate secure token
openssl rand -base64 32

# Or using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Network Security

**TLS/SSL Configuration:**
```nginx
# Strong SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
```

**Rate Limiting:**
- Global: 100 requests per hour per IP
- Version checks: 10 per minute per IP  
- Downloads: 5 per minute per IP
- Custom Redis-based limiting for advanced cases

### Server Hardening

**fail2ban Configuration:**
```ini
[plugin-server]
enabled = true
port = http,https
logpath = /var/www/plugins/access.log
maxretry = 5
bantime = 3600
findtime = 600
filter = plugin-server

# Filter: /etc/fail2ban/filter.d/plugin-server.conf
[Definition]
failregex = .* \| <HOST> \| AUTH_FAILED \| FAILED \|.*
            .* \| <HOST> \| RATE_LIMITED \| FAILED \|.*
ignoreregex =
```

**File Permissions:**
```bash
# Secure file permissions
chmod 755 /var/www/plugins
chmod 644 /var/www/plugins/*.jar
chmod 644 /var/www/plugins/*.txt
chmod 700 /var/www/plugins/logs
chown -R www-data:www-data /var/www/plugins
```

### Code Obfuscation

**ProGuard Settings:**
- Class name obfuscation with custom dictionary
- Method and field renaming
- Control flow obfuscation
- String encryption (with additional tools)
- Dead code elimination
- Aggressive optimization

**Additional Protection:**
```java
// Anti-debugging measures
private static boolean isDebugging() {
    return java.lang.management.ManagementFactory.getRuntimeMXBean()
        .getInputArguments().toString().contains("jdwp");
}

// Environment checks
private static boolean isValidEnvironment() {
    // Check for common reverse engineering tools
    String[] badProcesses = {"ida", "ollydbg", "x64dbg", "ghidra"};
    // Implementation details...
}
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures
**Symptoms:** HTTP 401 errors, "AUTH_FAILED" in logs
**Solutions:**
```bash
# Check token configuration
grep AUTH_TOKEN /var/www/plugin-server/.env

# Verify token in bootstrapper code
strings bootstrapper.jar | grep -A5 -B5 "Bearer"

# Test manually
curl -H "Authorization: Bearer your-token" https://yourdomain.com/version.txt
```

#### 2. Download Failures
**Symptoms:** HTTP 404/403 errors, plugin not loading
**Solutions:**
```bash
# Check file existence and permissions
ls -la /var/www/plugins/plugin.jar
file /var/www/plugins/plugin.jar

# Verify file integrity
unzip -t /var/www/plugins/plugin.jar

# Check server logs
tail -f /var/log/nginx/error.log
tail -f /var/www/plugins/logs/server.log
```

#### 3. SSL Certificate Issues
**Symptoms:** SSL handshake failures, certificate errors
**Solutions:**
```bash
# Check certificate status
sudo certbot certificates

# Test SSL configuration
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Renew certificate
sudo certbot renew --force-renewal
```

#### 4. Rate Limiting Problems
**Symptoms:** HTTP 429 errors, legitimate users blocked
**Solutions:**
```bash
# Check current rate limits
redis-cli keys "rate_limit:*"

# Clear rate limit for specific IP
redis-cli del "rate_limit:IP_ADDRESS"

# Adjust rate limits in configuration
nano /var/www/plugin-server/.env
```

#### 5. Plugin Loading Errors
**Symptoms:** ClassNotFoundException, plugin not enabling
**Solutions:**
```java
// Add debug logging to bootstrapper
if (DEBUG_MODE) {
    getLogger().info("Downloaded plugin size: " + pluginFile.length());
    getLogger().info("Plugin file exists: " + pluginFile.exists());
    getLogger().info("Main class: " + getMainClassFromJar());
}
```

### Debug Mode

Enable debug mode in your bootstrapper for troubleshooting:

```java
private static final boolean DEBUG_MODE = true; // Set to false in production

private void debugLog(String message) {
    if (DEBUG_MODE) {
        getLogger().info("[DEBUG] " + message);
    }
}
```

### Health Checks

**Automated Health Check Script:**
```bash
#!/bin/bash
# health_check.sh

DOMAIN="yourdomain.com"
AUTH_TOKEN="your-auth-token"

# Test version endpoint
echo "Testing version endpoint..."
VERSION_RESPONSE=$(curl -s -H "Authorization: Bearer $AUTH_TOKEN" https://$DOMAIN/version.txt)
if [ $? -eq 0 ]; then
    echo "Version check successful: $VERSION_RESPONSE"
else
    echo "Version check failed"
    exit 1
fi

# Test download endpoint (head request only)
echo "Testing download endpoint..."
DOWNLOAD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $AUTH_TOKEN" -I https://$DOMAIN/download.jar)
if [ "$DOWNLOAD_STATUS" = "200" ]; then
    echo "Download endpoint accessible"
else
    echo "Download endpoint failed with status: $DOWNLOAD_STATUS"
    exit 1
fi

echo "All health checks passed!"
```

### Log Rotation

**Configure logrotate:**
```bash
# /etc/logrotate.d/plugin-server
/var/www/plugins/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload plugin-server
    endscript
}

/var/www/plugins/access.log {
    daily
    rotate 60
    compress
    delaycompress
    missingok
    notifempty
    create 644 www-data www-data
}
```

## Contributing

We welcome contributions to improve this project. Please follow these guidelines:

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/alezfps/wboot
   cd wboot
   ```

2. **Set Up Development Environment**
   ```bash 
   # Set up pre-commit hooks
   pip install pre-commit
   pre-commit install
   ```

3. **Run Tests**
   ```bash
   # Python tests
   cd server-python && python -m pytest
   
   # Node.js tests
   cd server-nodejs && npm test
   ```

### Reporting Issues

Please include:
- Operating system and version
- Java version
- Server backend (Python/Node.js/PHP)
- Complete error messages and logs
- Steps to reproduce

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

- **Spigot API**: LGPL v3
- **Flask**: BSD 3-Clause License
- **Express.js**: MIT License
- **Redis**: BSD 3-Clause License

---

## Support

- **Documentation**: [Wiki](https://github.com/alezfps/wboot/wiki)
- **Issues**: [GitHub Issues](https://github.com/alezfps/wboot/issues)

---

**Disclaimer**: This tool is designed for legitimate plugin protection. Ensure compliance with Minecraft's EULA and relevant laws in your jurisdiction. The authors are not responsible for misuse of this software.

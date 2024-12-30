
# Protect - Docker Container Abuse Detection System

A robust security monitoring system designed to detect and prevent abuse in Docker containers managed by Pterodactyl Panel. The system implements various detection strategies and automated response mechanisms to protect your infrastructure.

## Features

- Real-time monitoring of Docker containers
- Multiple detection strategies:
  - File system monitoring
  - Dependency scanning
  - Log analysis
  - Process monitoring
  - Network usage tracking
- Automated response system:
  - Server suspension via Pterodactyl API
  - Discord webhook notifications (public and private channels)
  - Persistent flagging system

# Installation Guide

## Step 1: Prerequisites
```bash
# Navigate to etc directory
cd /etc

# Clone the repository
git clone https://github.com/Epic-Group12345/protect.git

# Enter the project directory
cd /etc/protect

# Install required Python packages
pip install -r requirements.txt
```

## Step 2: Configuration

Create a `config.json` file with the following structure:
```json
{
    "public_whook": "your_public_webhook_url",
    "private_whook": "your_private_webhook_url",
    "panel": "your_pterodactyl_panel_url",
    "key": "your_pterodactyl_api_key"
}
```
if your are using custom wings volumes directory please setup
```json
"volumes_dir": "/var/lib/pterodactyl/volumes"
```

## Step 3: Testing
```bash
python3 main.py
```

## Step 4: Daemonize the Service

1. Create the service file:
```bash
nano /etc/systemd/system/protect.service
```

2. Add the following content:
```ini
[Unit]
Description=Ameprotect Daemon Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/etc/protect
ExecStart=/usr/bin/python3 main.py
Restart=on-failure
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

3. Enable and start the service:
```bash
# Reload systemd
systemctl daemon-reload

# Enable the service to start on boot
systemctl enable protect

# Start the service
systemctl start protect

# Check service status
systemctl status protect
```

## Creating detection strategies
Create detection strategies in the `strategies` directory using `.protect` files:
```json
{
    "name": "strategy_name",
    "type": "detection_type",
    "checks": [
        {
            "type": "check_type",
            "path": "path_to_check",
            "patterns": ["pattern1", "pattern2"],
            "message": "Custom alert message"
        }
    ]
}
```

## Available Check Types

- `file_existence`: Check for specific files
- `file_content`: Scan file contents for patterns
- `file_size`: Monitor file sizes
- `dependency`: Scan for suspicious dependencies
- `log_content`: Analyze container logs
- `process_check`: Monitor CPU usage of processes
- `network_usage`: Track network traffic

The system will:
1. Load detection strategies
2. Continuously scan containers every 3 minutes
3. Apply detection strategies
4. Automatically respond to detected threats
5. Send notifications via Discord webhooks

## Alert System

The system provides two types of alerts:
- Public alerts: Basic notification of detected suspicious activity
- Private alerts: Detailed incident reports including:
  - Docker UUID
  - Server ID
  - Detected flags
  - Timestamp

## Security Measures

- SHA256 hash calculation for file integrity
- Persistent tracking of flagged containers
- Automatic server suspension upon threat detection
- Error handling and logging

## Error Handling

The system includes comprehensive error handling for:
- File operations
- API communications
- Container interactions
- Strategy execution
- Network operations

## Maintenance

- Flagged containers are stored in `flagged.json`
- Detection strategies can be updated by modifying `.protect` files
- Logs provide detailed information about system operation

## Note

This system is designed to work with Pterodactyl Panel and requires appropriate permissions and API access. Ensure all paths and configurations are correctly set before deployment.

# Open V2Ray Key Tester

Advanced V2Ray key testing tool with full protocol support

Created by @nlhatn
Open Source Project

## Overview

Open V2Ray Key Tester is a comprehensive testing and monitoring tool for V2Ray proxy keys. It supports all major V2Ray protocols and provides detailed statistics, subscription management, QR code generation, and advanced filtering capabilities.

## Supported Protocols

- VMess - Classic V2Ray protocol
- VLESS - Modern lightweight protocol  
- VLESS + Reality - Latest stealth protocol
- Trojan - HTTPS traffic imitation
- Shadowsocks / SS2022 - Fast and simple protocol
- Hysteria2 - QUIC-based high-speed protocol
- TUIC - QUIC-based protocol
- SSH - SSH tunneling

## Features

### Core Functionality
- Key testing and monitoring
- Latency measurement
- Server availability checking
- Success rate tracking
- Uptime monitoring

### Subscription Management
- Add unlimited subscriptions
- Automatic subscription updates
- Subscription statistics
- Server grouping by subscription

### QR Code Support
- Generate QR codes for any key
- Save QR codes as images
- Scan QR codes from screen
- Scan QR codes from files

### Advanced Filtering
- Filter by protocol
- Filter by group
- Filter by status (working/not working)
- Live search across all fields
- Multiple simultaneous filters

### Server Management
- Copy selected keys to clipboard
- Remove duplicates
- Remove non-working servers
- Remove worst performing servers
- Mark favorites
- Edit server names
- Export to various formats
- Batch operations

### User Interface
- Context menu (right-click)
- Keyboard shortcuts
- Color-coded performance indicators
- Multiple tabs (Keys, Statistics, Best Keys, Charts, Logs)
- Detailed server information
- Auto-select best server

## Installation

### System Requirements

Linux Mint / Ubuntu / Debian

### Step 1: Install System Dependencies

```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk -y
```

### Step 2: Install Python Libraries

```bash
pip3 install --break-system-packages -r requirements_advanced.txt
```

Alternative method using virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements_advanced.txt
```

### Step 3: Run the Program

```bash
chmod +x v2ray_tester_advanced.py
python3 v2ray_tester_advanced.py
```

Or use the installation script:

```bash
chmod +x install_advanced.sh
./install_advanced.sh
```

## Quick Start Guide

### Adding Keys

Method 1: From Clipboard
1. Copy V2Ray keys (vmess://, vless://, trojan://, ss://, etc.)
2. In program: Ctrl+V or click "Add" button

Method 2: From File
1. Create .txt file with keys (one per line)
2. In program: Ctrl+O or click "Load" button

Method 3: Via Subscriptions
1. Menu > Subscriptions > Manage Subscriptions
2. Add subscription URL
3. Click "Update Selected"

Method 4: QR Code Scanning
1. Menu > Tools > Scan QR Code
2. Select file with QR code or scan from screen

### Testing Keys

Quick test all keys:
- Press Ctrl+T or click "Test All" button

Test selected keys:
- Select keys > Right-click > "Test Server"

Automatic monitoring:
- Set interval in toolbar
- Click "Start Monitoring"

Stop testing:
- Click "Stop" button during testing

### Working with Keys

Copying:
- Select keys > Ctrl+C or Right-click > "Copy Key"

Generate QR:
- Right-click on key > "Generate QR"
- Or use "QR Codes" button for batch generation

Export:
- Menu > File > Export Selected/All
- Save to .txt file

Delete:
- Select keys > Delete or Right-click > "Delete"
- Menu > Edit > Remove Duplicates/Non-working/Worst

### Filtering and Search

Filters:
- Protocol: select desired protocol
- Group: filter by groups/subscriptions
- Status: working/not working/not tested

Search:
- Enter text in "Search" field
- Searches by name, server, country

Reset filters:
- Click "Reset Filters" button

### Viewing Results

Tab "All Keys":
- Complete list with sorting
- Double-click for detailed information
- Right-click for context menu

Tab "Statistics":
- Overall statistics for all keys
- Distribution by protocols and countries
- Average performance metrics

Tab "Best Keys":
- TOP-10 fastest servers
- TOP-10 most stable servers
- TOP-10 by uptime
- "Auto-select Best" button
- Copy TOP-5 buttons

Tab "Logs":
- All program operations
- Test results
- Import/export operations
- Save logs to file

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Ctrl+V | Import from clipboard |
| Ctrl+O | Open file |
| Ctrl+C | Copy selected keys |
| Ctrl+A | Select all |
| Ctrl+T | Test all keys |
| Delete | Delete selected |
| Double-click | Detailed information |
| Right-click | Context menu |

## Performance Indicators

Latency:
- Green: Excellent (< 100ms)
- Yellow: Good (100-300ms)
- Red: Slow (> 300ms)

Success Rate:
- Above 90% - Very stable
- 70-90% - Stable
- Below 70% - Unstable

Status:
- Working - Server available
- Not available - Server down
- Not tested - Not checked yet

## Subscription Management

Adding subscription:
1. Menu > Subscriptions > Manage Subscriptions
2. Click "Add Subscription"
3. Enter name and URL
4. Click "Add"

Updating subscriptions:
- Single: Select subscription > "Update Selected"
- All: Menu > Subscriptions > Update All Subscriptions

## QR Code Generation

For single key:
1. Right-click on key > "Generate QR"
2. QR code window opens automatically
3. Save image: "Save QR" button

For multiple keys:
1. Menu > Tools > QR Code Generator
2. Select desired keys
3. Click "Generate QR"
4. Windows open for each key

## Export and Import

Export keys:
File format:
```
vmess://...
vless://...
trojan://...
ss://...
```

Export statistics:
- Statistics tab > "Export Statistics"
- Saves to text file

Save configuration:
- Menu > File > Save Configuration
- Saves to JSON with keys and settings

## Troubleshooting

Problem: Program does not start
```bash
# Check Python version (needs 3.6+)
python3 --version

# Check tkinter
python3 -c "import tkinter"

# If error:
sudo apt install python3-tk
```

Problem: QR codes not working
```bash
pip3 install --break-system-packages qrcode pillow
```

Problem: Cannot scan QR codes
```bash
# Additional library required
sudo apt install libzbar0
pip3 install --break-system-packages pyzbar
```

Problem: Subscriptions not updating
- Check internet connection
- Verify subscription URL (must start with http:// or https://)
- Some subscriptions may be blocked

Problem: Country shows N/A
- Requires internet connection for IP geolocation
- May take a few tests to get country information
- Some servers may not provide location data

## File Formats

Keys file (keys.txt):
```
vmess://base64_encoded_config
vless://uuid@server:port?params#name
trojan://password@server:port?params#name
ss://method:password@server:port#name
```

Configuration file (v2ray_config.json):
```json
{
  "keys": [
    "vmess://...",
    "vless://..."
  ],
  "subscriptions": [
    {
      "name": "My Subscription",
      "url": "https://...",
      "enabled": true
    }
  ],
  "settings": {
    "monitor_interval": 3600,
    "test_timeout": 10
  }
}
```

## Tips and Best Practices

1. Regular testing
   - Enable auto-monitoring every 30-60 minutes
   - Remove non-working servers daily

2. Using subscriptions
   - Add multiple subscriptions for variety
   - Update subscriptions daily

3. Selecting best server
   - Use "Auto-select Best" for optimal choice
   - Consider both low latency and high success rate

4. Organizing keys
   - Use groups for organization
   - Mark best servers as Favorites

5. Backup
   - Regularly save configuration
   - Export keys to files

## Project Information

This is an open source project distributed free of charge.
The project should remain free and accessible to all users.

Created by: @nlhatn

Links:
- GitHub: https://github.com/NLHATN/Open-V2Ray-Checker
- Telegram Channel: https://t.me/Open_v2ray_key_tester
- Keys Channel: https://t.me/V2ray_key
- Author: https://t.me/Nlhatn

## Support the Project

If you find this project useful, you can support it by:
- Starring the repository on GitHub
- Sharing with friends
- Subscribing to the Telegram channel
- Reporting bugs or suggesting improvements

## License

Open Source - Free for personal use

## Contributing

Contributions are welcome. Please submit issues and pull requests on GitHub.

---

Created with dedication to the community
Author: @nlhatn

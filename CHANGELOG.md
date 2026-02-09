# Changelog - Open V2Ray Key Tester v2.0

## What's New

### Project Information
- Project renamed to "Open V2Ray Key Tester"
- Added author information: @nlhatn
- Added social links:
  - Telegram: https://t.me/Nlhatn
  - GitHub: https://github.com/NLHATN/Open-V2Ray-Checker
  - Project Channel: https://t.me/Open_v2ray_key_tester
  - Keys Channel: https://t.me/V2ray_key
- Added "About Project" section with open source information
- Added "Support Project" option in Help menu

### Bug Fixes
- Fixed country detection (N/A issue)
  - Implemented multiple fallback IP geolocation services
  - Added support for ip-api.com, ipapi.co, and ipify
  - Improved error handling for location detection
  - Now tests with full geolocation data

### New Features

#### 1. Logging System
- New "Logs" tab added
- Real-time logging of all operations:
  - Key imports
  - Test results
  - Errors
  - User actions
- Save logs to file functionality
- Clear logs option
- Timestamped entries

#### 2. Stop Testing
- Added "Stop" button to halt ongoing tests
- Graceful shutdown of test threads
- Progress saved for completed tests
- Logged when testing is stopped

#### 3. Remove Worst Keys
- Intelligent algorithm to identify worst performing keys:
  - Non-working servers (0% success rate)
  - Very slow servers (>500ms latency with <50% success)
  - Unstable servers (<30% success rate)
- Shows detailed criteria before deletion
- Confirmation dialog
- Logged in system logs

#### 4. Full Statistics View
- New "Full Statistics" option in context menu
- Comprehensive per-key statistics:
  - Basic information
  - Geography data
  - Test statistics
  - Performance metrics
  - Latency history (last 10 measurements)
  - Uptime information
  - Speed test results (if available)
  - Notes field
- Copy key from statistics window

#### 5. Copy Best Keys
- Two new buttons in "Best Keys" tab:
  - "Copy TOP-5 Fastest"
  - "Copy TOP-5 Most Stable"
- Quick access to best performing keys
- Copies directly to clipboard
- Logged in system

### User Interface Improvements
- Updated window title to include author
- Reorganized menus with better structure
- Added social links to Help menu
- Professional "About Project" dialog
- Improved button labels
- Better status messages
- Enhanced context menu

### Code Quality
- Better error handling
- Improved logging throughout
- Thread-safe operations
- More robust IP detection
- Better state management for testing

### Documentation
- Updated README without AI hints and emojis
- Professional tone throughout
- Clear installation instructions
- Comprehensive feature descriptions
- Troubleshooting section expanded
- Added Tips and Best Practices

### Performance
- Optimized IP geolocation with fallback services
- Better thread management
- Improved memory usage
- Faster filter application

## Technical Changes

### IP Geolocation
- Multiple service support:
  1. ipapi.co (primary)
  2. ip-api.com (fallback)
  3. ipify.org (IP only fallback)
- Automatic retry on failure
- Better error handling

### Testing System
- Added stop_testing flag
- Thread-safe stopping mechanism
- Better progress tracking
- Enhanced result reporting

### Logging Infrastructure
- Centralized logging system
- Timestamped entries
- File export capability
- Real-time display in UI
- Persistent log storage

### Key Management
- Improved duplicate detection
- Smart worst key identification
- Better statistics tracking
- Enhanced metadata storage

## Breaking Changes

None - Fully backward compatible with v1.0

## Migration Guide

If upgrading from v1.0:
1. Configuration files are compatible
2. No changes needed to key formats
3. New features available immediately
4. Previous functionality unchanged

## Known Issues

- QR scanning requires additional pyzbar library
- Speed test feature not yet implemented
- Charts tab placeholder (planned for future)

## Future Plans

- Real V2Ray Core integration for proxy testing
- Speed test implementation
- Advanced charting and graphs
- Dark theme option
- More export formats

## Contributors

Created by: @nlhatn

## Links

- GitHub: https://github.com/NLHATN/Open-V2Ray-Checker
- Telegram: https://t.me/Open_v2ray_key_tester
- Keys Channel: https://t.me/V2ray_key

---

Version 2.0 - Released 2024
Open Source - Free for all users

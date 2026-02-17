# NetSentinel - LAN Security & Traffic Intelligence Analyzer

A production-ready Windows desktop application for LAN monitoring and cybersecurity analysis.

## Features

### 🔍 Network Monitoring
- Real-time bandwidth monitoring with upload/download speeds
- Active network interface detection (WiFi SSID, IP, Gateway)
- Daily traffic usage tracking
- Historical bandwidth data with charts

### 🖥️ Device Discovery
- ARP-based LAN device scanning
- MAC address vendor identification (OUI lookup)
- Hostname resolution
- Online/offline device status tracking
- Gateway device identification

### 🔗 Connection Monitoring
- Active TCP/UDP connections tracking
- Process name and PID identification
- Real-time connection statistics
- Connection filtering by protocol and search

### 🛡️ Security Analysis
- Rule-based security detection engine
- Gateway MAC address change detection (ARP spoofing)
- Unknown device detection
- Traffic spike alerts
- Excessive connection warnings
- Real-time security alerts with severity levels

### 📦 Packet Capture (Requires Admin)
- Live packet capture using Npcap/WinPcap
- Protocol breakdown (TCP/UDP/ICMP/ARP)
- DNS query monitoring
- ARP packet analysis
- Packet statistics collection

### 🎨 Modern UI
- Dark theme with cybersecurity aesthetics
- Real-time updating charts (LiveCharts2)
- Responsive material design
- Professional dashboard layout

### 💾 Data Management
- SQLite database for persistent storage
- CSV export for devices and alerts
- Automatic data cleanup
- Settings persistence

### 📊 Reporting
- Device list export (CSV)
- Security alerts export (CSV)
- Traffic summary reports

## Technology Stack

- **Language:** C# (.NET 8)
- **UI Framework:** WPF with MVVM pattern
- **Database:** SQLite with Dapper
- **Packet Capture:** Npcap + SharpPcap + PacketDotNet
- **Charts:** LiveCharts2
- **Logging:** Serilog
- **MVVM:** CommunityToolkit.Mvvm
- **DI:** Microsoft.Extensions.DependencyInjection

## Requirements

### System Requirements
- Windows 10/11 (64-bit)
- .NET 8 Runtime
- **Administrator privileges** (for packet capture features)
- Npcap or WinPcap installed (download from https://npcap.com/)

### NuGet Dependencies
```xml
<PackageReference Include="Microsoft.Data.Sqlite" Version="8.0.0" />
<PackageReference Include="Dapper" Version="2.1.28" />
<PackageReference Include="SharpPcap" Version="6.2.5" />
<PackageReference Include="PacketDotNet" Version="1.4.7" />
<PackageReference Include="LiveChartsCore.SkiaSharpView.WPF" Version="2.0.0-rc2" />
<PackageReference Include="Serilog" Version="3.1.1" />
<PackageReference Include="Serilog.Sinks.File" Version="5.0.0" />
<PackageReference Include="Serilog.Sinks.Console" Version="5.0.1" />
<PackageReference Include="CommunityToolkit.Mvvm" Version="8.2.2" />
<PackageReference Include="Microsoft.Extensions.DependencyInjection" Version="8.0.0" />
<PackageReference Include="Microsoft.Extensions.Hosting" Version="8.0.0" />
<PackageReference Include="System.Management" Version="8.0.0" />
```

## Installation

1. **Install Npcap**
   - Download from https://npcap.com/
   - Install with "WinPcap compatibility mode" enabled
   - Restart your computer

2. **Build the Application**
   ```bash
   dotnet restore
   dotnet build --configuration Release
   ```

3. **Run as Administrator**
   - Right-click on NetSentinel.exe
   - Select "Run as administrator"
   - Accept the ethical usage agreement on first launch

## Architecture

### Project Structure
```
NetSentinel/
├── Capture/
│   └── PacketCaptureService.cs    # Packet capture using Npcap/SharpPcap
├── Core/
│   ├── NetworkManager.cs          # Network interface management
│   ├── BandwidthMonitor.cs        # Real-time bandwidth tracking
│   ├── DeviceScanner.cs           # LAN device discovery
│   ├── ConnectionMonitor.cs       # TCP/UDP connection monitoring
│   └── SecurityEngine.cs          # Security detection rules
├── Data/
│   ├── Models.cs                  # Data models
│   └── DatabaseService.cs         # SQLite database operations
├── Services/
│   ├── AlertService.cs            # Security alert management
│   └── BackgroundScheduler.cs     # Scheduled tasks
├── ViewModels/
│   ├── MainViewModel.cs           # Main window VM
│   ├── DashboardViewModel.cs      # Dashboard VM
│   ├── DevicesViewModel.cs        # Devices VM
│   ├── ConnectionsViewModel.cs    # Connections VM
│   ├── AlertsViewModel.cs         # Alerts VM
│   └── SettingsViewModel.cs       # Settings VM
├── UI/
│   ├── DashboardView.xaml         # Dashboard view
│   ├── DevicesView.xaml           # Devices list view
│   ├── ConnectionsView.xaml       # Connections view
│   ├── AlertsView.xaml            # Security alerts view
│   └── SettingsView.xaml          # Settings view
├── Utils/
│   ├── AdminChecker.cs            # Admin privilege detection
│   └── OUILookup.cs               # MAC vendor lookup
├── Converters/
│   └── ValueConverters.cs         # WPF value converters
├── Resources/
│   └── Styles.xaml                # UI styling
├── App.xaml                       # Application entry
└── MainWindow.xaml                # Main window shell
```

### MVVM Pattern
- **Models:** Data entities in `Data/Models.cs`
- **ViewModels:** Business logic and state management
- **Views:** WPF UserControls with XAML
- **Services:** Background tasks and data access
- **Dependency Injection:** Microsoft.Extensions.DependencyInjection

## Security Features

### Detection Rules
1. **Gateway MAC Change Detection**
   - Monitors gateway MAC address
   - Alerts on changes (potential ARP spoofing)
   - Critical severity

2. **Unknown Device Detection**
   - Tracks known devices
   - Alerts when new devices join
   - Warning severity

3. **Traffic Spike Detection**
   - Monitors upload/download speeds
   - Configurable threshold
   - Warning severity

4. **Excessive Connections**
   - Monitors connection count
   - Configurable threshold
   - Warning severity

### Alert Severity Levels
- **Critical:** Red - Immediate attention required
- **Warning:** Orange - Potential security concern
- **Info:** Blue - Informational notices

## Configuration

### Settings (Configurable in UI)
- Auto-scan devices: Enable/disable automatic scanning
- Scan interval: Minutes between scans (default: 5)
- Enable packet capture: Enable/disable packet capture
- Show notifications: Enable/disable alert popups
- Minimize to tray: Minimize to system tray
- Auto-start with Windows: Launch on system startup
- Traffic spike threshold: KB/s threshold (default: 10000)
- Connection count threshold: Max connections (default: 100)

### Database Location
```
%AppData%\NetSentinel\netsentinel.db
```

### Log Files
```
%AppData%\NetSentinel\logs\netsentinel-YYYYMMDD.log
```

## Usage

### Dashboard
- View real-time network statistics
- Monitor bandwidth usage with live charts
- See recent security alerts
- Check system status

### Devices
- View all discovered LAN devices
- Filter by IP, MAC, vendor, or hostname
- Export device list to CSV
- Manually trigger network scan

### Connections
- Monitor active TCP/UDP connections
- Filter by protocol or search
- View process information
- Track connection statistics

### Alerts
- Review security alerts
- Filter by severity or unread status
- Mark alerts as read
- Export alerts to CSV

### Settings
- Configure monitoring preferences
- Adjust security thresholds
- Test network scanning
- Enable/disable features

## Ethical Usage

⚠️ **IMPORTANT:** This tool is designed for network security monitoring and analysis.

**You MUST only use this tool on:**
- Networks that you own
- Networks where you have explicit written authorization

**Unauthorized network monitoring may:**
- Violate computer fraud and abuse laws
- Breach privacy regulations
- Result in legal consequences

By using this software, you agree to use it responsibly and ethically.

## Known Limitations

1. **Requires Administrator Privileges**
   - Packet capture requires admin rights
   - Some features limited without admin access

2. **Windows Only**
   - Designed specifically for Windows 10/11
   - Uses Windows-specific APIs (WLAN, Registry)

3. **Npcap Dependency**
   - Requires Npcap installation
   - Must be installed before first run

4. **Network Interface**
   - Monitors primary active network interface
   - May not work correctly with multiple active adapters

## Troubleshooting

### "Administrator privileges required" warning
- Right-click the executable and select "Run as administrator"
- Or modify the app.manifest to require admin elevation

### Packet capture not working
- Verify Npcap is installed: https://npcap.com/
- Ensure WinPcap compatibility mode is enabled
- Run application as administrator
- Check firewall/antivirus settings

### No devices found during scan
- Verify network connectivity
- Check firewall rules allow ARP packets
- Try manual scan from Devices view
- Ensure not on isolated network (guest WiFi)

### Application won't start
- Check .NET 8 runtime is installed
- Review log files in %AppData%\NetSentinel\logs\
- Verify database file isn't corrupted

## Performance

- **Bandwidth Monitoring:** Updates every 1 second
- **Connection Monitoring:** Updates every 2 seconds
- **Device Scanning:** Manual or every 5 minutes (configurable)
- **Security Evaluation:** Every 5-30 seconds (rule-dependent)
- **Database Cleanup:** Daily (keeps 30 days of history)

## License

This is a demonstration/educational project. Ensure compliance with local laws and regulations before use.

## Support

For issues, feature requests, or questions:
1. Check the log files for error details
2. Verify system requirements are met
3. Ensure Npcap is properly installed
4. Run as administrator

## Version History

### Version 1.0.0 (2026-02-17)
- Initial release
- Core monitoring features
- Security detection engine
- Modern WPF UI
- SQLite database
- Packet capture support

## Acknowledgments

- **SharpPcap:** Packet capture library
- **PacketDotNet:** Packet parsing library
- **LiveCharts2:** Real-time charting
- **Serilog:** Logging framework
- **SQLite:** Embedded database
- **Npcap:** Windows packet capture driver

---

**NetSentinel** - Professional LAN Security & Traffic Intelligence Analyzer

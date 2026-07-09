# NetSentinel - LAN Security & Traffic Intelligence Analyzer
## Complete Technical Project Report & Architectural Specification

---

**Project Title:** NetSentinel - LAN Security & Traffic Intelligence Analyzer  
**Document Version:** 1.2  
**Framework:** .NET 8.0 with WPF (Windows) | Android SDK (Min API 26, Target API 34)  
**Database System:** SQLite (Microsoft.Data.Sqlite) with Dapper Micro-ORM  
**Packet Parsing Engine:** SharpPcap & PacketDotNet  
**Target Environments:** Windows 10/11 (Administrator execution required for packet capture features) & Android 8.0+  

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Desktop Application Page-by-Page Technical Breakdown](#2-desktop-application-page-by-page-technical-breakdown)
   - [2.1 Dashboard View](#21-dashboard-view)
   - [2.2 Devices View](#22-devices-view)
   - [2.3 Connections View (Deep Dive Connection Retrieval)](#23-connections-view-deep-dive-connection-retrieval)
   - [2.4 Alerts View](#24-alerts-view)
   - [2.5 Settings View](#25-settings-view)
3. [Android Companion App Architecture](#3-android-companion-app-architecture)
   - [3.1 Loopback VPN DNS Interception](#31-loopback-vpn-dns-interception)
   - [3.2 Background Sniffing & Accessibility Service](#32-background-sniffing--accessibility-service)
   - [3.3 Mobile Ingestion API REST Interface](#33-mobile-ingestion-api-rest-interface)
4. [Key Development Challenges & Implemented Solutions](#4-key-development-challenges--implemented-solutions)
   - [4.1 Remote Connection Metadata Harvesting: ARP Spoofing vs. Loopback VPN](#41-remote-connection-metadata-harvesting-arp-spoofing-vs-loopback-vpn)
   - [4.2 Accessibility Node Traversal Aborts on Input Elements](#42-accessibility-node-traversal-aborts-on-input-elements)
   - [4.3 Static UI State Alert Storms](#43-static-ui-state-alert-storms)
   - [4.4 Raw Socket Constraints on Windows (Admin & Npcap dependency)](#44-raw-socket-constraints-on-windows-admin--npcap-dependency)
5. [Future Roadmap & Improvements](#5-future-roadmap--improvements)

---

## 1. Executive Summary

NetSentinel is a hybrid desktop-mobile LAN security platform that bridges passive network monitoring with active endpoint heuristics. The desktop application (developed in C# using WPF and .NET 8) acts as a centralized security console, receiving live packet data from the local PC interface and streaming telemetry from an Android companion app. 

### Core Capabilities:
- **Device Discovery**: ARP-based subnet scanning and Address Resolution Protocol mapping.
- **Connection Diagnostics**: Process-level auditing of socket state changes (TCP/UDP).
- **Intrusion Prevention System (IPS)**: Real-time checks against Abuse.ch URLHaus threat intelligence databases.
- **Credential Sniffing Safeguard**: Foreground mobile login failure monitoring via accessibility sniffing.
- **Local Persistence & Privacy**: Single-host local execution with SQLite storage and zero cloud dependencies.

---

## 2. Desktop Application Page-by-Page Technical Breakdown

The desktop software is structured under a clean MVVM pattern, using `Microsoft.Extensions.DependencyInjection` for dependency injection and `CommunityToolkit.Mvvm` for observable properties and command relaying.

```
                  ┌──────────────────────────────────────────────┐
                  │                 App.xaml.cs                  │
                  │  (Dependency Injection Container Framework)  │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼ (Injected Singletons)
    ┌───────────────────────┬────────────┴──────────┬────────────────────────┐
    ▼                       ▼                       ▼                        ▼
┌──────────────┐     ┌──────────────┐       ┌──────────────┐         ┌──────────────┐
│DatabaseServ. │     │PacketCapture │       │ThreatIntelS. │         │ AlertService │
└──────┬───────┘     └──────┬───────┘       └──────┬───────┘         └──────┬───────┘
       │                    │                      │                        │
       └────────────────────┼───────────┬──────────┘                        │
                            ▼           ▼                                   ▼
                    ┌──────────────┐┌──────────────┐                 ┌──────────────┐
                    │SecurityEngine││AgentReceiver│                 │   ViewModels │
                    └──────────────┘└──────────────┘                 └──────────────┘
```

---

### 2.1 Dashboard View

#### A. Purpose
To serve as the primary visual status board, providing real-time data on active network interfaces, network bandwidth utilization, device counts, and unread security alert volumes.

#### B. Features & UI Layout
- **Active Interface Details Card**: Renders the active network connection details (SSID for WiFi, adapter name, local IPv4 address, subnet mask, default gateway, and DNS servers).
- **Throughput Speed Cards**: Real-time visual gauges reporting live upload and download speeds in Kilobits per second (Kbps) or Megabits per second (Mbps).
- **Accumulated Bandwidth Card**: Shows total accumulated megabytes or gigabytes sent and received since midnight, with automatic daily resets.
- **Bandwidth Timeline Chart**: Dual-line graph displaying traffic trends over a rolling 60-second window. Upload speed is represented in Cyan (`#3B82F6`) and Download speed in Green (`#10B981`).
- **Security Health Indicator**: A colored badge indicating the threat status of the network (Secure, Warning, Critical) based on unread alert counts.

#### C. Implementation Details & Technologies
The view binds to `DashboardViewModel.cs`. Bandwidth monitoring is driven by `BandwidthMonitor.cs`:
1. **Metrics Collection**: The monitor uses `NetworkInterface.GetIPv4Statistics()` on the active network adapter at a strict 1-second interval.
2. **Speed Calculation**: Speed is calculated as the byte delta from the previous measurement:
   $$\text{Download Speed (bps)} = (\text{BytesReceived}_{t} - \text{BytesReceived}_{t-1}) \times 8$$
   The speed value is formatted to Kbps or Mbps in the ViewModel.
3. **Chart Rendering**: Visualized using `LiveCharts2` (SkiaSharp-based vector engine) bound to an `ObservableValue` series for smooth micro-animations.
4. **SQL Metrics Archiving**: At 10-second intervals, the average speeds are saved to the `BandwidthHistory` SQLite table:
   ```sql
   INSERT INTO BandwidthHistory (Timestamp, BytesSent, BytesReceived, UploadSpeedKbps, DownloadSpeedKbps)
   VALUES (@Timestamp, @BytesSent, @BytesReceived, @UploadSpeed, @DownloadSpeed);
   ```

#### D. Associated Settings Controls
- **Traffic Spike Threshold**: Located in Settings. If the current throughput exceeds this limit (default 10,000 KB/s), the `SecurityEngine` triggers a `Warning` alert.
- **Enable Packet Capture**: Disabling packet capture in Settings stops the `PacketCaptureService` thread, which stops DNS query auditing and updates to the dashboard’s packet stats card.

---

### 2.2 Devices View

#### A. Purpose
To maintain a real-time list of all network devices connected to the local network segment.

#### B. Features & UI Layout
- **Connected Hosts Table**: Renders device details: Online Status (indicated by a green or grey dot), IPv4 Address, MAC Address, resolved Hostname, Manufacturer/Vendor, Device Type icon, and timestamps for First Seen and Last Seen.
- **Subnet Scanner Button**: Allows users to manually trigger a subnet scan.
- **Asset Export**: Exports the network device database to a CSV file.

#### C. Implementation Details & Technologies
Driven by `DeviceScanner.cs` and resolved through `OUILookup.cs` and `DeviceTypeDetector.cs`:
1. **Subnet Determination**: Reads the local IP and subnet mask to calculate the IPv4 address range (e.g., `192.168.1.1` to `192.168.1.254`).
2. **Ping Sweep**: Fires concurrent asynchronous Ping packets to all addresses in the subnet range to populate the system's local ARP table:
   ```csharp
   var pings = subnetIps.Select(ip => pingSender.SendPingAsync(ip, timeoutMs));
   await Task.WhenAll(pings);
   ```
3. **ARP Table Extraction**: Reads the system's ARP cache.
4. **OUI Manufacturer Mapping**: Extracts the first 3 bytes (the Organizationally Unique Identifier) of the MAC address and matches it against `oui.txt` (stored in AppData/NetSentinel) to identify device manufacturers (e.g., `Samsung`, `Apple`, `Intel`).
5. **Type Classification**: Checks the resolved hostname and vendor name to classify the device (e.g., hostnames containing `android`, `iphone`, or `pixel` are classified as `DeviceType.Mobile`).
6. **Data Storage**: Saves the discovered hosts to the `NetworkDevices` table:
   ```sql
   INSERT INTO NetworkDevices (IpAddress, MacAddress, Vendor, Hostname, FirstSeen, LastSeen, IsOnline, IsGateway)
   VALUES (@Ip, @Mac, @Vendor, @Hostname, @First, @Last, 1, @IsGateway)
   ON CONFLICT(MacAddress) DO UPDATE SET
     IpAddress = excluded.IpAddress, Hostname = excluded.Hostname, LastSeen = excluded.LastSeen, IsOnline = 1;
   ```

#### D. Associated Settings Controls
- **Auto Scan Devices (Toggle)**: Turns automatic background scanning on or off.
- **Scan Interval Minutes**: Controls how often the system triggers an automatic network scan (configured from 1 to 60 minutes).

---

### 2.3 Connections View (Deep Dive Connection Retrieval)

#### A. Purpose
Provides a process-level view of active connections to audit network traffic. It shows which specific applications on the local machine and which remote companion devices are generating traffic, helping administrators identify data exfiltration or unauthorized background connections.

```
                                [ Connections View Grid ]
                                            │
                    ┌───────────────────────┴───────────────────────┐
                    ▼                                               ▼
     [ Local Laptop Socket Table ]                     [ Mobile Telemetry Stream ]
     - Get socket list via .NET IPGlobalProps          - Incoming POST to Port 5095 API
     - Exec "netstat -ano" in background               - Telemetry carries recent domains
     - Match address/port to find target PID           - Parsed from loopback VPN Service
     - Query Process.GetProcessById                    - App attribution via PackageManager
     - Resolve executable name (e.g. Chrome)           - Flags Foreground vs Background status
```

#### B. Connection Extraction Mechanics

##### Local Laptop Connection Extraction
To retrieve active socket endpoints and map them to their owning applications on Windows, the `ConnectionMonitor.cs` service performs the following operations:
1. **Extract Sockets**: Queries the .NET CLR networking API to retrieve active sockets:
   - `IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()` returns active TCP connections.
   - `IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()` returns TCP listening sockets.
   - `IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners()` returns UDP listener sockets.
2. **Process Mappings**: Standard .NET APIs do not expose which Process ID (PID) owns a socket. To resolve this, NetSentinel runs the Windows utility `netstat` in a background process:
   - **Command Line**: `netstat -ano` (reports active TCP/UDP ports with their owning PIDs).
   - **Execution Settings**:
     ```csharp
     var process = new Process {
         StartInfo = new ProcessStartInfo {
             FileName = "netstat",
             Arguments = "-ano",
             UseShellExecute = false,
             RedirectStandardOutput = true,
             CreateNoWindow = true
         }
     };
     ```
3. **Parse Process Outputs**: Standard output is read and parsed line by line. NetSentinel extracts connection entries using space delimiters:
   ```text
   Active Connections
     Proto  Local Address          Foreign Address        State           PID
     TCP    192.168.1.100:54321    142.250.190.46:443     ESTABLISHED     12440
   ```
   - Matches the IP and Port from the `Local Address` column against the active connection list.
   - Reads the last column on the line as the PID.
4. **Resolve Process Name**: Resolves the PID to a process name:
   ```csharp
   var proc = Process.GetProcessById(pid);
   string processName = proc.ProcessName; // e.g. "chrome", "spotify"
   ```
   - Wraps the resolution in try-catch blocks. If a process terminates during execution or is a system-protected process, it falls back to `"Unknown"` or `"System"`.
5. **Connection Attributes Mapping**:
   - **Protocol**: Maps connection type to `TCP` or `UDP`.
   - **Local Address / Port**: Represents the local network binding interface.
   - **Remote Address / Port**: Shows the destination IP and port. If the socket is a listener (state `LISTENING`), the remote IP defaults to `0.0.0.0` or `*` and remote port is set to `0`.
   - **Connection State**: Maps socket states (`ESTABLISHED`, `LISTENING`, `CLOSE_WAIT`, `TIME_WAIT`, `SYN_SENT`).

##### Android Companion App Connection/Domain Extraction
Android’s application sandbox restricts apps from reading system-wide socket tables (`/proc/net/tcp`) or querying the PIDs of other running processes. NetSentinel bypasses this restriction through a **Local Loopback VPN Service** on the mobile device:
1. **Loopback VPN Interception**: The companion app sets up a local virtual network interface via `VpnService`, routing only outbound DNS queries (UDP, port 53) through the VPN. All other traffic bypasses the VPN, preventing network latency.
2. **DNS Packet Parsing**: The local VPN captures outbound UDP packets on port 53. It parses the DNS query structure to extract:
   - The destination domain (e.g., `github.com`).
   - The UID (User ID) of the application that sent the packet.
3. **Process Attribution**: Uses Android's `PackageManager` to map the UID to package labels:
   ```kotlin
   val packageNames = packageManager.getPackagesForUid(uid)
   val appLabel = packageManager.getApplicationLabel(packageManager.getApplicationInfo(packageNames[0], 0))
   ```
4. **HTTP Telemetry Delivery**: Every 3 seconds, the companion app sends these domain visits to the desktop application's REST API (`http://[PC_IP]:5095/api/agent/telemetry`):
   ```json
   {
     "deviceInfo": {
       "deviceName": "Galaxy S23",
       "ipAddress": "192.168.1.105",
       "macAddress": "9C:02:98:8A:2B:11"
     },
     "recentDomains": [
       {
         "domain": "github.com",
         "timestamp": 1782341586000,
         "appLabel": "Chrome",
         "isBackground": false
       }
     ]
   }
   ```
5. **Ingestion Processing**: `AgentReceiver.cs` processes this payload on the PC. It maps incoming domains to the device's IP and updates the active connection list.

#### C. Separation of Background vs. Active (Foreground) Connections
To help administrators identify suspicious activity, NetSentinel classifies connections into two distinct types:
* **Active Connections (Foreground)**: User-initiated network activity, such as typing a URL or visiting a web page in a web browser (with `IsBackground = false`).
* **Background Connections**: Autonomous network activity generated by system services or applications running in the background, such as email synchronizations, push notifications, telemetry, and background ad trackers (with `IsBackground = true`).

##### Why Separated / Purpose
1. **Noise Reduction**: A typical user browsing a single webpage generates 50+ background requests for analytics, ads, and CDNs. Separating background from active traffic allows analysts to focus on what the user is actively visiting.
2. **Identification of Spyware/Adware**: Shows background data transfers from inactive applications, making background communication, spyware activity, or C&C beacons visible.
3. **Alert Debouncing**: Prevents the security alert engine from raising duplicate warnings for the same background domains during a single browsing session.

#### D. Associated Settings Controls
- **Connection Count Threshold**: Located in Settings. If a device exceeds this limit (default 100 connections), `SecurityEngine` triggers an alert.

---

### 2.4 Alerts View

#### A. Purpose
To serve as the primary security operations console, displaying security events and threat alerts detected across the network.

#### B. Features & UI Layout
- **Alert History Grid**: Lists alerts with columns for Severity Level, Timestamp, Alert Title, Description, Source IP, and Source MAC Address.
- **Unread Badge Indicator**: Shows the count of unread alerts on the sidebar.
- **Incident Response Tools**: Buttons to mark selected alerts as read, clear the alert database, or export the history to a CSV file.

#### C. Implementation Details & Technologies
Driven by the `AlertService.cs` manager and the `SecurityEngine`:
1. **Alert Injection**: When a security threat is detected, `AlertService.RaiseAlertAsync` is called:
   ```csharp
   public async Task RaiseAlertAsync(SecurityAlert alert) {
       await _database.SaveAlertAsync(alert);
       AlertRaised?.Invoke(this, alert);
   }
   ```
2. **Real-time Notifications**: Uses WPF's `NotificationManager` toast alerts to display high-severity events to the user.
3. **Badge Synchronization**: Displays the unread count on the navigation sidebar using a reactive SQL query:
   ```sql
   SELECT COUNT(*) FROM SecurityAlerts WHERE IsRead = 0;
   ```

#### D. Security Detection Heuristics & Rules
NetSentinel's `SecurityEngine.cs` continuously evaluates network traffic and endpoints against the following threat patterns:
- **Gateway MAC Change**: Monitors the active gateway IP address and checks its associated MAC address in the ARP tables. If a MAC change is detected, it flags a potential ARP poisoning threat.
  - *Severity*: `Critical`
  - *Evaluation*: Swept every 30 seconds.
- **Unknown Device Alerts**: Matches discovered device MAC addresses against verified historical records in the SQLite database. If a new MAC is identified, it generates a new device alert.
  - *Severity*: `Warning`
  - *Evaluation*: Triggered immediately post-scan.
- **Traffic Spike Detection**: Tracks physical interface data transfer rates. If upload or download bandwidth speeds exceed the user-defined `TrafficSpikeThreshold`, an anomaly alert is raised.
  - *Severity*: `Warning`
  - *Evaluation*: Evaluated every 1 second.
- **Excessive Connections**: Analyzes the count of active TCP sockets and UDP listeners. If a device exceeds the `ConnectionCountThreshold` (e.g., 100 connections), it flags potential malware beaconing or DDoS participation.
  - *Severity*: `Critical`
  - *Evaluation*: Checked on 5-second loops.
- **Port Scan Reconnaissance**: Detects rapid consecutive TCP SYN packets originating from a single host targeting multiple distinct destination ports.
  - *Severity*: `Warning`
  - *Evaluation*: Handled in packet capture streams, configurable via the user-defined `PortScanThreshold` setting.
- **Threat Intelligence Blocklist Alert**: Intercepts local and mobile DNS lookup queries and checks them against the Abuse.ch URLHaus list. Any match triggers a critical malware/phishing warning.
  - *Severity*: `Critical`
  - *Evaluation*: Checked instantly on DNS query capture.

#### E. Associated Settings Controls
- **Failed Login Thresholds**: User-defined sliders that control when a failed login attempt triggers an alert:
  - `FailedLoginThresholdInfo` (Default 1 attempt)
  - `FailedLoginThresholdWarning` (Default 5 attempts)
  - `FailedLoginThresholdCritical` (Default 50 attempts)

---

### 2.5 Settings View

#### A. Purpose
Provides a centralized settings panel to configure network interface targets, modify security thresholds, and manage the threat intelligence database.

#### B. Features & UI Layout
- **Preferences Section**: Toggles for automatic device scanning, packet capture, notifications, system tray behavior, and Windows startup options.
- **Security Thresholds Section**: Numerical inputs for Traffic Spike Limits, Connection Count thresholds, and Port Scan trigger thresholds.
- **Failed Login Threshold Sliders**: Adjusts alert escalation limits.
- **Threat Intelligence Section**: Displays database status, the last updated timestamp, and an **"Update Threat Intel Database"** action button.

#### C. Implementation Details & Technologies
The settings view binds to `SettingsViewModel.cs` and updates parameters in `DatabaseService.cs`:
1. **Setting Synchronization**: Mapped to the `Settings` SQLite database table using Dapper.
   ```sql
   -- SQLite Settings DDL Table Configuration
   CREATE TABLE IF NOT EXISTS Settings (
       Id INTEGER PRIMARY KEY CHECK (Id = 1),
       AutoScanDevices INTEGER NOT NULL DEFAULT 1,
       ScanIntervalMinutes INTEGER NOT NULL DEFAULT 5,
       EnablePacketCapture INTEGER NOT NULL DEFAULT 1,
       ShowNotifications INTEGER NOT NULL DEFAULT 1,
       MinimizeToTray INTEGER NOT NULL DEFAULT 1,
       AutoStartWithWindows INTEGER NOT NULL DEFAULT 0,
       TrafficSpikeThreshold INTEGER NOT NULL DEFAULT 10000,
       ConnectionCountThreshold INTEGER NOT NULL DEFAULT 100,
       DarkMode INTEGER NOT NULL DEFAULT 1,
       FailedLoginThresholdInfo INTEGER NOT NULL DEFAULT 1,
       FailedLoginThresholdWarning INTEGER NOT NULL DEFAULT 5,
       FailedLoginThresholdCritical INTEGER NOT NULL DEFAULT 50,
       PortScanThreshold INTEGER NOT NULL DEFAULT 8
   );
   ```
2. **Windows Startup Registration**:
   - Setting **Start with Windows** writes the application path to the Windows registry run key:
     ```csharp
     using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
     key.SetValue("NetSentinel", $"\"{exePath}\"");
     ```
3. **Threat Intelligence Integration**:
   - `ThreatIntelService.cs` loads threat intelligence domains into an in-memory `HashSet<string>`.
   - On clicking the update button, it downloads the live hosts file from Abuse.ch URLHaus (`https://urlhaus.abuse.ch/downloads/hostfile/`).
   - The parser ignores comment lines starting with `#` and splits lines by whitespace. It extracts the target domain and appends it to the in-memory `HashSet<string>`.
   - The updated blocklist is saved to `AppData/NetSentinel/blocklist.txt`, and the `LastUpdated` timestamp is updated in the database.

---

## 3. Android Companion App Architecture

The Android companion application acts as a mobile security agent, reporting system telemetry, network domain connections, and credential security events to the NetSentinel console.

```
                      ┌────────────────────────────────────────┐
                      │      NetSentinel Android Agent         │
                      └───────────────────┬────────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
     ┌─────────────────────────┐                     ┌─────────────────────────┐
     │   LocalVpnService.kt    │                     │AccessibilityService.kt  │
     │                         │                     │                         │
     │ - Intercepts UDP Port 53│                     │ - Sniffs URL address bar│
     │ - Resolves Package UIDs │                     │ - Detects login errors  │
     │ - Maps active domains   │                     │ - Tracks input focus    │
     └────────────┬────────────┘                     └────────────┬────────────┘
                  │                                               │
                  └───────────────────────┬───────────────────────┘
                                          ▼
                             ┌─────────────────────────┐
                             │    Telemetry Ingest     │
                             │   (POST via Port 5095)  │
                             └─────────────────────────┘
```

---

### 3.1 Loopback VPN DNS Interception
The companion app uses a local loopback VPN to capture DNS requests without requiring administrative root privileges on the device:
1. **Virtual Interface Configuration**: Configures a virtual network interface using Android's `VpnService.Builder`:
   ```kotlin
   val vpnInterface = Builder()
       .addAddress("10.0.0.2", 24)
       .addRoute("0.0.0.0", 0)
       .addDnsServer("10.0.0.1")
       .establish()
   ```
2. **DNS Packet Parsing**: Reads outbound IP packets from the virtual interface descriptor. It filters for UDP packets on port 53 and parses the DNS question section to extract the requested domain name.
3. **App Attribution**: Queries the `/proc/net/udp` system socket table or uses the active connection mapping API to locate the UID of the socket that sent the DNS query. It then translates the UID into the application package name (e.g. `com.android.chrome`).

---

### 3.2 Background Sniffing & Accessibility Service
To monitor web browsing behavior and detect credential compromise attempts, the companion app runs an accessibility service (`NetSentinelAccessibilityService.kt`):
1. **Address Bar Monitoring**: Listens to UI events (`TYPE_WINDOW_CONTENT_CHANGED`). It traverses the browser's view hierarchy node tree to locate address bar input fields. It extracts the active URL or domain name, marking the visit as an active foreground connection.
2. **Login Error Detection**: Listens to layout text updates. If a common login error phrase (e.g., `"Incorrect username or password"`, `"invalid credentials"`, `"login failed"`) appears on screen, it triggers a failed login telemetry event.
3. **State Debouncer**: The service tracks user interactions. Once a failure is logged, it sets a lock state. It only raises another failure alert if the user interacts with the UI (keyboard input, button clicks) and generates a new failure, preventing duplicate notifications.

---

### 3.3 Mobile Ingestion API REST Interface
The collected metrics are transmitted via a lightweight HTTP client to the desktop:
- **Transport**: Standard HTTP POST requests sent over the local network (WiFi).
- **Authentication**: Includes a matching API key in the headers (`X-Api-Key`).
- **Reporting Interval**: Runs on a background loop reporting every 3 seconds for active connection telemetry, and 15 seconds for general system updates (battery temperature, running applications, OS version).

#### Telemetry Serialization Models (Kotlin)
The companion app serializes its telemetry models using `kotlinx.serialization` before transmission. The core models are defined as follows:
```kotlin
@Serializable
data class AgentTelemetry(
    val timestamp: String = "",
    val agentVersion: String = "",
    val deviceInfo: AgentDeviceInfo,
    val wifiInfo: AgentWifiInfo? = null,
    val networkStats: AgentNetworkStats? = null,
    val runningApps: List<AgentAppInfo>? = null,
    val batteryInfo: AgentBatteryInfo? = null,
    val activeWebsite: String? = null,
    val recentDomains: List<DomainVisit>? = null,
    val failedLogins: List<FailedLoginAttempt>? = null
)

@Serializable
data class AgentDeviceInfo(
    val deviceName: String = "",
    val model: String = "",
    val manufacturer: String = "",
    val androidVersion: String = "",
    val sdkVersion: Int = 0,
    val macAddress: String = "",
    val ipAddress: String = "",
    val deviceId: String = ""
)

@Serializable
data class DomainVisit(
    val domain: String = "",
    val timestamp: Long = 0L,
    val appLabel: String = "Unknown",
    val isBackground: Boolean = false
)

@Serializable
data class FailedLoginAttempt(
    val target: String = "",
    val timestamp: Long = 0L
)
```

---

## 4. Key Development Challenges & Implemented Solutions

### 4.1 Remote Connection Metadata Harvesting: ARP Spoofing vs. Loopback VPN

#### A. Problem Scenario
To map the active TCP/UDP connections of remote hosts on a LAN, a security monitor must intercept their network traffic. Modern operating systems isolate devices, drop unsolicited incoming connections, and encrypt standard network frames.
Initially, the team evaluated **ARP Spoofing (Poisoning)** as a method to intercept remote device traffic.

#### B. The Threat & Ethical Implications of ARP Spoofing
ARP Spoofing is a technique where an attacker sends spoofed ARP messages onto a local area network. This associates the attacker's MAC address with the IP address of another host (such as the default gateway), causing all traffic from target devices to route through the attacker's machine (Man-in-the-Middle attack).
```
[ Normal LAN Traffic Path ]
Android Device ───────────────────────────────► Default Gateway (Router)

[ ARP Spoofing / Poisoning MITM (Rejected) ]
Android Device ───(Poisoned Cache)───► Laptop ───(Forwarded)───► Router
```
Why this approach was rejected:
1. **Intrusive and Disruptive**: ARP poisoning degrades network performance and can drop packets, leading to denial-of-service conditions.
2. **Unethical**: Intercepting traffic from other users on a shared network without their consent is intrusive and potentially illegal.
3. **Security Defenses**: Modern OS firewalls, smart switches, and endpoint detection software actively block and flag ARP spoofing attempts.

#### C. The Solution: Companion App with Loopback VPN Architecture
Instead of using intrusive network attacks to intercept traffic, the team developed an **Android Companion App** that acts as a local loopback VPN.
- The companion app runs a local `VpnService` that captures DNS requests locally on the device itself.
- It parses the DNS request headers to extract the target domain and maps it to the calling application package name.
- It packages this metadata and transmits it as structured JSON telemetry to the desktop application over a standard, authenticated HTTP REST API.
This design respects user privacy, requires no root privileges, does not disrupt network traffic, and provides clean metadata attribution.

---

### 4.2 Accessibility Node Traversal Aborts on Input Elements

#### A. Problem Scenario
While implementing browser address bar tracking inside the companion app's `NetSentinelAccessibilityService.kt`, the service traversed the UI tree recursively to find active URL nodes.
However, we discovered that if the user entered an email address in a login form or if a node contained an `@` character, the traversal routine aborted the search entirely, returning `null`. This broke failed login detection and browser sniffing on major websites.

#### B. The Cause
The validation check for valid domains/URLs in `isValidUrlOrDomain()` flagged any string containing `@` as an email address (invalid URL). During recursive layout traversal, if an input field matched this rule, the search code returned an early exit condition, aborting parent-node traversal for the entire UI subtree.

#### C. The Solution
We separated the validation checks:
- The `@` check was removed from the general fallback branch of the traversal code, preventing it from aborting the search for sibling and child nodes.
- Inside `isAddressBar()`, if a node matches an input box containing an `@` character, it returns `null` *only for that specific node*, allowing the recursive search to continue traversing the rest of the layout tree.

---

### 4.3 Static UI State Alert Storms

#### A. Problem Scenario
When a user entered incorrect credentials on a login screen (e.g. GitHub), the site displayed an error message like `"Incorrect username or password."`. Because accessibility events are triggered continuously by minor layout refreshes (such as blinking cursor states or keyboard shifts), the service generated duplicate alerts every 2 seconds, flooding the desktop UI.

#### B. The Solution
We implemented an **interaction-driven state tracking** mechanism:
- Introduced a state flag: `userInteractedSinceLastFailure`.
- Listens to active user events: `TYPE_VIEW_CLICKED`, `TYPE_VIEW_TEXT_CHANGED`, `TYPE_VIEW_FOCUSED`, `TYPE_VIEW_TEXT_SELECTION_CHANGED`. Any such event sets the interaction flag to `true`.
- When a failed login attempt is detected and reported, the flag is set to `false`.
- The service will not log another failure until the user interacts with the UI again, the text contents change, or a 10-second safety fallback window elapsed.

---

### 4.4 Raw Socket Constraints on Windows (Admin & Npcap dependency)

#### A. Problem Scenario
The low-level packet capture features in `PacketCaptureService.cs` rely on the **Npcap** raw packet driver to bind to physical network cards. Standard Windows security policies restrict raw socket access to administrative accounts. If a user ran NetSentinel as a standard user or without Npcap installed, the application crashed.

#### B. The Solution
We implemented an **automatic fallback state**:
- Created `AdminChecker.cs` to detect administrative execution rights.
- Added Npcap checking code to verify the raw driver availability.
- If Npcap or administrator rights are missing, NetSentinel disables raw packet capturing, writes a warning to the logs, and falls back to **Passive Socket Monitoring** (using `IPGlobalProperties` and process mapping loops) alongside active **Mobile Ingestion Telemetry**.
- This ensures the application remains functional and stable on any standard Windows PC.

---

## 5. Future Roadmap & Improvements

To further enhance the capabilities of NetSentinel, several intelligent features and machine learning technologies can be integrated:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Future Intelligence Roadmap                          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [ Machine Learning Anomaly ]          [ Threat Prevention ]           │
│  - Microsoft ML.NET                    - Active ARP GARP healing       │
│  - Time-Series Outlier analysis        - Network block triggers        │
│                                                                        │
│  [ Heuristic Detectors ]               [ Application Profiling ]       │
│  - Shannon Entropy DNS tunnels         - Behavioral mobile scoring     │
│  - Port Scan detection heuristics      - Outbound endpoint validation  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 1. ML.NET Anomaly Predictor
- **Tech Stack**: Integration of `Microsoft.ML` libraries.
- **Concept**: Train a local unsupervised anomaly detection model (e.g., K-Means clustering or Random Forest) on local device traffic metrics.
- **Outcome**: The engine will automatically learn the typical traffic baseline of each device, flag outlier patterns (e.g. unexpected high-frequency uploads or off-hours connections) with confidence intervals, and reduce static threshold false positives.

### 2. Shannon Entropy DNS Tunneling Analyzer
- **Tech Stack**: Custom string entropy calculations.
- **Concept**: Calculate the mathematical randomness of DNS queries passing through the packet capture engine:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- **Outcome**: Detects data exfiltration attempts over DNS. If the query string has high entropy, it suggests encrypted payload exfiltration, triggering a Critical Alert.

### 3. Active ARP Healing
- **Tech Stack**: Raw packet injection, ARP frame construction.
- **Concept**: Convert the alert engine into an active defense mechanism.
- **Outcome**: When an ARP spoofing threat is detected, NetSentinel will automatically construct and transmit a series of **Gratuitous ARP (GARP)** frames to overwrite poisoned ARP caches on the local subnet, restoring correct gateway routing.

### 4. Heuristic Port Scan Detector
- **Tech Stack**: Packet state counters.
- **Concept**: Track connection attempts to administrative ports (22, 445, 3389) across local IPs.
- **Outcome**: Detects lateral movement and reconnaissance scans. If an IP triggers multiple connection failures to adjacent network hosts, it is flagged as a scanning threat.

### 5. Application Vulnerability Risk Scorer
- **Tech Stack**: Threat intel lookup APIs, permissions correlation.
- **Concept**: Map Android companion app permissions and destinations against known malicious profiles.
- **Outcome**: Assigns a risk score to installed apps based on their background traffic destinations and access privileges, helping users identify potential spyware or data harvesting programs.

---

## 6. Project Directory & Source File Specification

Below is the architectural file structure of the NetSentinel platform. It describes each file's task, technical role, and internal mechanism.

### 6.1 Windows WPF Desktop Project File Structure

```
NetSentinel/
├── App.xaml / App.xaml.cs
├── MainWindow.xaml / MainWindow.xaml.cs
├── NetSentinel.csproj
├── app.manifest
│
├── Capture/
│   └── PacketCaptureService.cs
│
├── Core/
│   ├── BandwidthMonitor.cs
│   ├── ConnectionMonitor.cs
│   ├── DeviceScanner.cs
│   ├── NetworkManager.cs
│   └── SecurityEngine.cs
│
├── Data/
│   ├── DatabaseService.cs
│   └── Models.cs
│
├── Services/
│   ├── AgentReceiver.cs
│   ├── AlertService.cs
│   ├── BackgroundScheduler.cs
│   └── ThreatIntelService.cs
│
├── UI/
│   ├── DashboardView.xaml / .cs
│   ├── DevicesView.xaml / .cs
│   ├── ConnectionsView.xaml / .cs
│   ├── AlertsView.xaml / .cs
│   └── SettingsView.xaml / .cs
│
├── ViewModels/
│   ├── MainViewModel.cs
│   ├── DashboardViewModel.cs
│   ├── DevicesViewModel.cs
│   ├── ConnectionsViewModel.cs
│   ├── AlertsViewModel.cs
│   └── SettingsViewModel.cs
│
├── Converters/
│   └── ValueConverters.cs
│
└── Utils/
    ├── AdminChecker.cs
    ├── DeviceTypeDetector.cs
    └── OUILookup.cs
```

#### Detailed File Descriptions:

##### 1. Root & Shell Controllers
* **`App.xaml` / `App.xaml.cs`**:
  - **Task**: The application bootstrapper and ethical terms verification entry point.
  - **How it works**: Initializes the Generic Host builder (`Host.CreateDefaultBuilder`), configures the Dependency Injection (DI) service registrations, registers Serilog logger, and handles the `Application_Startup` event. Importantly, it invokes `ShowEthicalUsageNotice()` to ensure a consent banner has been accepted by verification of the `accepted_terms` file in AppData; if declined or first-run, it forces terms agreement before initiating background services.
* **`MainWindow.xaml` / `MainWindow.xaml.cs`**:
  - **Task**: The visual shell window.
  - **How it works**: Provides the main shell containing the navigation sidebar and content presenters. It binds navigation buttons to `MainViewModel` commands to transition views dynamically.
* **`app.manifest`**:
  - **Task**: Declares system authorization policies.
  - **How it works**: Instructs the Windows operating system that the application requires administrator execution level privileges (via `requireAdministrator` tag) to unlock raw socket capturing via Npcap.

##### 2. Capture Layer
* **`Capture/PacketCaptureService.cs`**:
  - **Task**: Sniffs and parses physical network frames with ethical metadata isolation.
  - **How it works**: Uses `SharpPcap` to bind to the active network interface card. It captures raw ethernet packets in promiscuous mode, filters for DNS (UDP Port 53) and HTTP login traffic using BPF (Berkeley Packet Filter) syntax, parses headers via `PacketDotNet`, and raises events like `DnsQueryDetected` or `HttpLoginFailureDetected`.
  - **Ethical Scope Limitation**: Crucially, it only captures and parses header metadata fields (source/destination IP, ports, protocol types, DNS queries) and *deliberately avoids* reading, logging, or disk-storing packet payload bodies (such as raw HTML data, images, or payload text), ensuring total user data confidentiality and compliance with privacy rights.

##### 3. Core Network Logic
* **`Core/NetworkManager.cs`**:
  - **Task**: Network adapter target discovery.
  - **How it works**: Queries network adapters on the system. It detects local IP addresses, DNS server lists, gateway MAC addresses, and WiFi SSID details using WMI (`System.Management`) and standard `System.Net.NetworkInformation` APIs.
* **`Core/DeviceScanner.cs`**:
  - **Task**: Subnet scanner and asset discovery.
  - **How it works**: Calculates subnet IP ranges and fires parallel, asynchronous Ping requests to populate the local Windows ARP cache table. It then queries the cache table to resolve active MAC-to-IP pairings.
* **`Core/BandwidthMonitor.cs`**:
  - **Task**: Real-time traffic throughput tracker.
  - **How it works**: Uses a 1-second system timer loop to read the physical interface’s `IPv4InterfaceStatistics` byte metrics. It calculates speed differences and updates the database logs.
* **`Core/ConnectionMonitor.cs`**:
  - **Task**: Local host socket auditor.
  - **How it works**: Retrieves active UDP and TCP socket endpoints using `IPGlobalProperties`. It runs a background `netstat -ano` shell process to match local ports to Process IDs (PIDs), resolving them to binary names using `Process.GetProcessById()`.
* **`Core/SecurityEngine.cs`**:
  - **Task**: Threat detection heuristics evaluator.
  - **How it works**: Evaluates active security rules at 5-second intervals. It compares gateway MAC states for ARP Spoofing anomalies, scans connection counts against settings limits, tracks Facebook lookup frequency, and matches DNS lookups against the blocklist service.

##### 4. Data Layer
* **`Data/DatabaseService.cs`**:
  - **Task**: Manages the local SQLite database.
  - **How it works**: Creates tables, indices, and schema migrations. It executes CRUD operations asynchronously using `Microsoft.Data.Sqlite` and `Dapper` micro-ORM mapping.
* **`Data/Models.cs`**:
  - **Task**: Core entity definitions.
  - **How it works**: Holds class models representing network devices, security alerts, database configuration preferences (`AppSettings`), telemetry types, and database statistics.

##### 5. Services Layer
* **`Services/AgentReceiver.cs`**:
  - **Task**: REST API server for mobile agents.
  - **How it works**: Uses an `HttpListener` on port `5095` to listen for telemetry POST requests. It authenticates requests via a shared API key, parses JSON payloads containing running apps, battery temperature, and domain visits, and routes them to the alert engine.
* **`Services/AlertService.cs`**:
  - **Task**: Incident dispatcher and notification center.
  - **How it works**: Saves alerts to the database and dispatches events to the UI. It throws system tray notification popups to alert users to security events.
* **`Services/BackgroundScheduler.cs`**:
  - **Task**: Scheduled task manager.
  - **How it works**: Runs on a background thread to trigger automatic device scanner sweeps at user-configured intervals.
* **`Services/ThreatIntelService.cs`**:
  - **Task**: Threat intelligence blocklist database.
  - **How it works**: Maintains an in-memory `HashSet<string>` of blocked domains. It loads local fallback seed domains, downloads Abuse.ch hosts lists, and checks lookups against the blocklist (including wildcard parent-level matching).

##### 6. UI Views & ViewModels
* **`UI/` (Views)**:
  - **DashboardView / DevicesView / ConnectionsView / AlertsView / SettingsView**: WPF UserControls defined in XAML that bind properties and event commands to their corresponding ViewModels to render graphs, tables, and buttons.
* **`ViewModels/`**:
  - **MainViewModel / DashboardViewModel / DevicesViewModel / ConnectionsViewModel / AlertsViewModel / SettingsViewModel**: CommunityToolkit.Mvvm classes that manage view states, trigger background sweeps, run manual saves, and notify UI controls when metrics update.

##### 7. Utilities & Converters
* **`Converters/ValueConverters.cs`**: Converts data types (such as formatting UTC times to local strings, converting booleans to layout visibility values, and mapping device categories to icons) for UI controls.
* **`Utils/AdminChecker.cs`**: Verifies if NetSentinel has been launched with administrative privileges.
* **`Utils/DeviceTypeDetector.cs`**: Uses hostnames, SSDP query records, and manufacturer prefixes to categorize devices.
* **`Utils/OUILookup.cs`**: Parses the `oui.txt` file to resolve MAC addresses to manufacturers.

---

### 6.2 Android Companion Project File Structure

```
AndroidApp/
├── app/src/main/java/com/netsentinel/agent/
│   ├── MainActivity.kt
│   ├── model/
│   │   └── TelemetryModels.kt
│   ├── service/
│   │   └── NetSentinelAccessibilityService.kt
│   └── vpn/
│       ├── LocalVpnService.kt
│       └── PacketParser.kt
```

#### Detailed File Descriptions:

* **`MainActivity.kt`**:
  - **Task**: The mobile user interface.
  - **How it works**: Provides buttons to pair the companion app with the desktop server, toggle the local VPN service, review the connection status, and request necessary system accessibility permissions.
* **`model/TelemetryModels.kt`**:
  - **Task**: Holds telemetry payload schemas.
  - **How it works**: Declares Kotlin serialization models matching the JSON structures of the desktop's REST API.
* **`service/NetSentinelAccessibilityService.kt`**:
  - **Task**: Monitors active browser sites and failed logins.
  - **How it works**: Uses Android's accessibility APIs to inspect active layout node trees. It extracts the address bar URL and looks for error strings containing credential failure keywords.
* **`vpn/LocalVpnService.kt`**:
  - **Task**: Runs the local loopback DNS VPN tunnel.
  - **How it works**: Configures a virtual VPN interface, intercepts outbound UDP port 53 packets, and maps socket UIDs to application packages via the system `PackageManager`.
* **`vpn/PacketParser.kt`**:
  - **Task**: Network packet header decoder.
  - **How it works**: Parses captured raw bytes from the virtual interface descriptor, decoding IP and UDP headers to extract the raw DNS queries.


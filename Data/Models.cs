using System;
using System.Collections.Generic;

namespace NetSentinel.Data;

/// <summary>
/// Represents a network device discovered on the LAN
/// </summary>
public class NetworkDevice
{
    public int Id { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public string? Hostname { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public bool IsOnline { get; set; }
    public bool IsGateway { get; set; }
    private DeviceType _deviceType = DeviceType.Unknown;
    public DeviceType DeviceType
    {
        get
        {
            if (_deviceType == DeviceType.Unknown)
            {
                return Utils.DeviceTypeDetector.DetectDeviceType(Vendor, Hostname, MacAddress);
            }
            return _deviceType;
        }
        set => _deviceType = value;
    }
}

/// <summary>
/// Device type categories
/// </summary>
public enum DeviceType
{
    Unknown,
    Desktop,
    Laptop,
    Mobile,
    Tablet,
    Router,
    SmartTV,
    IoT,
    Printer,
    Console
}

/// <summary>
/// Represents a security alert
/// </summary>
public class SecurityAlert
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public AlertSeverity Severity { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? SourceIp { get; set; }
    public string? SourceMac { get; set; }
    public bool IsRead { get; set; }
    public int Count { get; set; } = 1;
}

/// <summary>
/// Alert severity levels
/// </summary>
public enum AlertSeverity
{
    Info,
    Warning,
    Critical
}

/// <summary>
/// Represents bandwidth usage data
/// </summary>
public class BandwidthEntry
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public double UploadSpeedKbps { get; set; }
    public double DownloadSpeedKbps { get; set; }
}

/// <summary>
/// Represents an active network connection
/// </summary>
public class NetworkConnection
{
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public bool IsBackground { get; set; }
}

/// <summary>
/// Represents packet capture statistics
/// </summary>
public class PacketStats
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public long TotalPackets { get; set; }
    public long TcpPackets { get; set; }
    public long UdpPackets { get; set; }
    public long IcmpPackets { get; set; }
    public long ArpPackets { get; set; }
    public long DnsQueries { get; set; }
}

/// <summary>
/// Represents network interface information
/// </summary>
public class NetworkInterfaceInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string SubnetMask { get; set; } = string.Empty;
    public string Gateway { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string? Ssid { get; set; }
    public string[] DnsServers { get; set; } = Array.Empty<string>();
    public bool IsWireless { get; set; }
}

/// <summary>
/// Represents a security detection rule
/// </summary>
public class SecurityRule
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public RuleType Type { get; set; }
    public AlertSeverity Severity { get; set; }
    public bool IsEnabled { get; set; }
    public int ThresholdValue { get; set; }
    public TimeSpan EvaluationInterval { get; set; }
}

/// <summary>
/// Types of security rules
/// </summary>
public enum RuleType
{
    GatewayMacChange,
    UnknownDevice,
    TrafficSpike,
    ExcessiveConnections,
    PortScan,
    ArpSpoof
}

/// <summary>
/// Application settings
/// </summary>
public class AppSettings
{
    public int Id { get; set; }
    public bool AutoScanDevices { get; set; } = true;
    public int ScanIntervalMinutes { get; set; } = 5;
    public bool EnablePacketCapture { get; set; } = true;
    public bool ShowNotifications { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public bool AutoStartWithWindows { get; set; } = false;
    public int TrafficSpikeThreshold { get; set; } = 10000; // KB/s
    public int ConnectionCountThreshold { get; set; } = 100;
    public bool DarkMode { get; set; } = true;
    public int FailedLoginThresholdInfo { get; set; } = 1;
    public int FailedLoginThresholdWarning { get; set; } = 5;
    public int FailedLoginThresholdCritical { get; set; } = 50;
}

/// <summary>
/// Top-level telemetry payload received from a mobile agent
/// </summary>
public class AgentTelemetry
{
    public string Timestamp { get; set; } = string.Empty;
    public string AgentVersion { get; set; } = string.Empty;
    public AgentDeviceInfo DeviceInfo { get; set; } = null!;
    public AgentWifiInfo? WifiInfo { get; set; }
    public AgentNetworkStats? NetworkStats { get; set; }
    public List<AgentAppInfo>? RunningApps { get; set; }
    public AgentBatteryInfo? BatteryInfo { get; set; }
    public string? ActiveWebsite { get; set; }
    public List<DomainVisit>? RecentDomains { get; set; }
    public List<FailedLoginAttempt>? FailedLogins { get; set; }
}

/// <summary>
/// Represents a failed login attempt captured by the accessibility service on the mobile agent.
/// </summary>
public class FailedLoginAttempt
{
    public string Target { get; set; } = string.Empty;
    public long Timestamp { get; set; }
}

/// <summary>
/// Represents a single domain visit captured by the VPN DNS interceptor on the mobile agent.
/// </summary>
public class DomainVisit
{
    public string Domain { get; set; } = string.Empty;
    public long Timestamp { get; set; }
    public string AppLabel { get; set; } = "Unknown";
    public bool IsBackground { get; set; }
}

/// <summary>
/// Device identification from a mobile agent
/// </summary>
public class AgentDeviceInfo
{
    public string DeviceName { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public string AndroidVersion { get; set; } = string.Empty;
    public int SdkVersion { get; set; }
    public string MacAddress { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
}

/// <summary>
/// WiFi connection details from a mobile agent
/// </summary>
public class AgentWifiInfo
{
    public string Ssid { get; set; } = string.Empty;
    public string Bssid { get; set; } = string.Empty;
    public int Rssi { get; set; }
    public int LinkSpeedMbps { get; set; }
    public int FrequencyMhz { get; set; }
    public int NetworkId { get; set; }
    public bool IsConnected { get; set; }
}

/// <summary>
/// Network traffic statistics from a mobile agent
/// </summary>
public class AgentNetworkStats
{
    public long WifiBytesSent { get; set; }
    public long WifiBytesReceived { get; set; }
    public long MobileBytesSent { get; set; }
    public long MobileBytesReceived { get; set; }
    public long TotalBytesSent { get; set; }
    public long TotalBytesReceived { get; set; }
    public int ActiveConnectionsCount { get; set; }
}

/// <summary>
/// Running app information from a mobile agent
/// </summary>
public class AgentAppInfo
{
    public string PackageName { get; set; } = string.Empty;
    public string AppName { get; set; } = string.Empty;
    public bool IsSystemApp { get; set; }
    public string Category { get; set; } = "unknown";
}

/// <summary>
/// Battery status from a mobile agent
/// </summary>
public class AgentBatteryInfo
{
    public int Level { get; set; }
    public bool IsCharging { get; set; }
    public string ChargingType { get; set; } = string.Empty;
    public float Temperature { get; set; }
    public int Voltage { get; set; }
    public string Health { get; set; } = string.Empty;
}

/// <summary>
/// Agent registration request from a mobile device
/// </summary>
public class AgentRegistration
{
    public AgentDeviceInfo DeviceInfo { get; set; } = null!;
    public string AgentVersion { get; set; } = string.Empty;
    public string Timestamp { get; set; } = string.Empty;
}

using System;

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
    public DeviceType DeviceType { get; set; } = DeviceType.Unknown;
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
}

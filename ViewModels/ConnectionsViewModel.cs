using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Messages;
using NetSentinel.Services;
using NetSentinel.Capture;
using Serilog;

namespace NetSentinel.ViewModels;

/// <summary>
/// ViewModel representing network connections for a specific device
/// </summary>
public partial class DeviceConnections : ObservableObject
{
    [ObservableProperty]
    private string _deviceName = string.Empty;

    [ObservableProperty]
    private string _ipAddress = string.Empty;

    [ObservableProperty]
    private string _deviceType = string.Empty; // "Laptop" or "Mobile"

    [ObservableProperty]
    private string _status = "Connected";

    [ObservableProperty]
    private bool _isExpanded;

    public List<NetworkConnection> RawConnections { get; set; } = new();

    public ObservableCollection<NetworkConnection> Connections { get; set; } = new();
    
    public ObservableCollection<NetworkConnection> ActiveConnections { get; set; } = new();
    public ObservableCollection<NetworkConnection> BackgroundConnections { get; set; } = new();

    public int TotalConnections => RawConnections.Count;
    public int TcpConnections => RawConnections.Count(c => c.Protocol == "TCP");
    public int UdpListeners => RawConnections.Count(c => c.Protocol == "UDP");
}

/// <summary>
/// ViewModel for the connections view, displaying grouped connections per device
/// </summary>
public partial class ConnectionsViewModel : ObservableObject
{
    private readonly ILogger _logger;
    private readonly ConnectionMonitor _connectionMonitor;
    private readonly AgentReceiver _agentReceiver;
    private readonly PacketCaptureService _packetCapture;

    [ObservableProperty]
    private int _totalConnections;

    [ObservableProperty]
    private int _tcpConnections;

    [ObservableProperty]
    private int _udpListeners;

    [ObservableProperty]
    private int _establishedConnections;

    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private string _selectedProtocol = "All";

    public ObservableCollection<DeviceConnections> Devices { get; set; }

    public string[] ProtocolFilters { get; } = { "All", "TCP", "UDP" };

    private readonly List<NetworkConnection> _localConnectionsCache = new();

    public ConnectionsViewModel(ILogger logger, ConnectionMonitor connectionMonitor, AgentReceiver agentReceiver, PacketCaptureService packetCapture)
    {
        _logger = logger;
        _connectionMonitor = connectionMonitor;
        _agentReceiver = agentReceiver;
        _packetCapture = packetCapture;

        Devices = new ObservableCollection<DeviceConnections>();

        _connectionMonitor.ConnectionsUpdated += OnConnectionsUpdated;
        _agentReceiver.TelemetryReceived += OnTelemetryReceived;

        // Register for global refresh messages
        WeakReferenceMessenger.Default.Register<RefreshConnectionsMessage>(this, (r, m) => HandleRefreshMessage());

        // Initial refresh
        Refresh();
    }

    private void HandleRefreshMessage()
    {
        _logger.Information("ConnectionsViewModel received refresh message");
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Refresh();
        });
    }

    private void OnTelemetryReceived(object? sender, AgentTelemetryReceivedEventArgs e)
    {
        Refresh();
    }

    private void OnConnectionsUpdated(object? sender, ConnectionsUpdatedEventArgs e)
    {
        lock (_localConnectionsCache)
        {
            _localConnectionsCache.Clear();
            _localConnectionsCache.AddRange(e.Connections);
        }
        Refresh();
    }

    [RelayCommand]
    private void Refresh()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            // Gather local connections
            var localConnections = new List<NetworkConnection>();
            lock (_localConnectionsCache)
            {
                localConnections.AddRange(_localConnectionsCache);
            }
            if (localConnections.Count == 0 && _connectionMonitor.ActiveConnections != null)
            {
                localConnections.AddRange(_connectionMonitor.ActiveConnections);
            }

            // Find or create local laptop entry
            var localDevice = Devices.FirstOrDefault(d => d.DeviceType == "Laptop");
            if (localDevice == null)
            {
                localDevice = new DeviceConnections
                {
                    DeviceName = "Local Laptop (This PC)",
                    IpAddress = GetLocalIPAddress(),
                    DeviceType = "Laptop",
                    IsExpanded = true
                };
                Devices.Add(localDevice);
            }

            localDevice.RawConnections = localConnections.OrderBy(c => c.ProcessName).ToList();

            // Track active mobile agents
            var activeMobileIps = new HashSet<string>();
            foreach (var kvp in _agentReceiver.LatestTelemetry)
            {
                var ip = kvp.Key;
                var telemetry = kvp.Value;
                activeMobileIps.Add(ip);

                var mobileDevice = Devices.FirstOrDefault(d => d.DeviceType == "Mobile" && d.IpAddress == ip);
                if (mobileDevice == null)
                {
                    mobileDevice = new DeviceConnections
                    {
                        DeviceName = $"{telemetry.DeviceInfo.Manufacturer} {telemetry.DeviceInfo.Model}",
                        IpAddress = ip,
                        DeviceType = "Mobile",
                        IsExpanded = false
                    };
                    Devices.Add(mobileDevice);
                }
                else
                {
                    mobileDevice.DeviceName = $"{telemetry.DeviceInfo.Manufacturer} {telemetry.DeviceInfo.Model}";
                }

                mobileDevice.RawConnections = GenerateMobileConnections(telemetry);
            }

            // Remove mobile devices that have gone offline
            var toRemove = Devices.Where(d => d.DeviceType == "Mobile" && !activeMobileIps.Contains(d.IpAddress)).ToList();
            foreach (var dev in toRemove)
            {
                Devices.Remove(dev);
            }

            ApplyFilters();
        });
    }

    partial void OnFilterTextChanged(string value)
    {
        ApplyFilters();
    }

    partial void OnSelectedProtocolChanged(string value)
    {
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            int total = 0;
            int tcp = 0;
            int udp = 0;
            int established = 0;

            foreach (var device in Devices)
            {
                 device.Connections.Clear();
                device.ActiveConnections.Clear();
                device.BackgroundConnections.Clear();

                var filtered = device.RawConnections.AsEnumerable();

                // Protocol filter
                if (SelectedProtocol != "All")
                {
                    filtered = filtered.Where(c => c.Protocol == SelectedProtocol);
                }

                // Text filter
                if (!string.IsNullOrWhiteSpace(FilterText))
                {
                    filtered = filtered.Where(c =>
                        c.LocalAddress.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                        c.RemoteAddress.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                        c.ProcessName.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                        c.LocalPort.ToString().Contains(FilterText) ||
                        c.RemotePort.ToString().Contains(FilterText)
                    );
                }

                foreach (var conn in filtered.OrderBy(c => c.ProcessName))
                {
                    if (device.DeviceType == "Laptop")
                    {
                        conn.IsBackground = IsBackgroundProcess(conn.ProcessName);
                    }

                    device.Connections.Add(conn);

                    if (conn.IsBackground)
                    {
                        device.BackgroundConnections.Add(conn);
                    }
                    else
                    {
                        device.ActiveConnections.Add(conn);
                    }
                }

                // Update counts per device
                total += device.RawConnections.Count;
                tcp += device.RawConnections.Count(c => c.Protocol == "TCP");
                udp += device.RawConnections.Count(c => c.Protocol == "UDP");
                established += device.RawConnections.Count(c => c.State == "ESTABLISHED");
            }

            TotalConnections = total;
            TcpConnections = tcp;
            UdpListeners = udp;
            EstablishedConnections = established;
        });
    }

    private List<NetworkConnection> GenerateMobileConnections(AgentTelemetry telemetry)
    {
        var list = new List<NetworkConnection>();
        var mobileIp = telemetry.DeviceInfo.IpAddress;

        // 1. Connection from mobile agent to desktop host (NetSentinel)
        list.Add(new NetworkConnection
        {
            ProcessName = "NetSentinel Agent",
            ProcessId = 2050,
            Protocol = "TCP",
            LocalAddress = mobileIp,
            LocalPort = 49152,
            RemoteAddress = GetLocalIPAddress(),
            RemotePort = _agentReceiver.Port,
            State = "ESTABLISHED",
            IsBackground = true
        });

        // 2. Domain visits from VPN DNS interception (primary source)
        var activeDomains = _agentReceiver.GetActiveDomainsForDevice(mobileIp);
        if (activeDomains != null && activeDomains.Count > 0)
        {
            // De-duplicate by domain, keep the most recent visit, sorted by timestamp desc
            var uniqueDomains = activeDomains
                .GroupBy(d => d.Domain)
                .Select(g => g.OrderByDescending(d => d.Timestamp).First())
                .OrderByDescending(d => d.Timestamp)
                .ToList();

            int pid = 3000;
            foreach (var visit in uniqueDomains)
            {
                var appLabel = !string.IsNullOrEmpty(visit.AppLabel) && visit.AppLabel != "Unknown"
                    ? visit.AppLabel
                    : ResolveFriendlyName(visit.Domain);

                list.Add(new NetworkConnection
                {
                    ProcessName = $"{appLabel} — {visit.Domain}",
                    ProcessId = pid++,
                    Protocol = "TCP",
                    LocalAddress = mobileIp,
                    LocalPort = 0,
                    RemoteAddress = visit.Domain,
                    RemotePort = 443,
                    State = "ESTABLISHED",
                    IsBackground = visit.IsBackground
                });
            }
        }
        else if (!string.IsNullOrEmpty(telemetry.ActiveWebsite))
        {
            // Fallback: single active website (backward compat)
            list.Add(new NetworkConnection
            {
                ProcessName = $"Active Browsing: {telemetry.ActiveWebsite}",
                ProcessId = 2051,
                Protocol = "TCP",
                LocalAddress = mobileIp,
                LocalPort = 0,
                RemoteAddress = telemetry.ActiveWebsite,
                RemotePort = 443,
                State = "ESTABLISHED",
                IsBackground = false
            });
        }

        // 3. Real sniffed active connections for this mobile IP (from packet capture)
        var flows = _packetCapture.ActiveFlows.Where(f => f.SourceIp == mobileIp).ToList();
        foreach (var flow in flows)
        {
            var domain = _packetCapture.ResolveDomainName(flow.DestinationIp);
            var processName = ResolveFriendlyName(domain);

            list.Add(new NetworkConnection
            {
                ProcessName = processName,
                ProcessId = 0,
                Protocol = flow.Protocol,
                LocalAddress = flow.SourceIp,
                LocalPort = flow.SourcePort,
                RemoteAddress = domain,
                RemotePort = flow.DestinationPort,
                State = "ESTABLISHED",
                IsBackground = true
            });
        }

        return list;
    }

    /// <summary>
    /// Maps a domain to a friendly app/service name for display.
    /// </summary>
    private static string ResolveFriendlyName(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return "Unknown";

        var d = domain.ToLowerInvariant();

        // Social Media
        if (d.Contains("facebook.com") || d.Contains("fbcdn.net") || d.Contains("fb.com"))
            return "Facebook";
        if (d.Contains("instagram.com") || d.Contains("cdninstagram.com"))
            return "Instagram";
        if (d.Contains("twitter.com") || d.Contains("x.com") || d.Contains("twimg.com"))
            return "Twitter/X";
        if (d.Contains("tiktok.com") || d.Contains("tiktokcdn.com") || d.Contains("musical.ly") || 
            d.Contains("byteoversea.com") || d.Contains("byteimg.com") || d.Contains("ibytedtos.com"))
            return "TikTok";
        if (d.Contains("snapchat.com") || d.Contains("sc-cdn.net"))
            return "Snapchat";
        if (d.Contains("linkedin.com") || d.Contains("licdn.com"))
            return "LinkedIn";
        if (d.Contains("reddit.com") || d.Contains("redd.it") || d.Contains("redditstatic.com"))
            return "Reddit";
        if (d.Contains("pinterest.com") || d.Contains("pinimg.com"))
            return "Pinterest";

        // Messaging
        if (d.Contains("whatsapp.net") || d.Contains("whatsapp.com"))
            return "WhatsApp";
        if (d.Contains("telegram.org") || d.Contains("t.me"))
            return "Telegram";
        if (d.Contains("discord.com") || d.Contains("discordapp.com"))
            return "Discord";

        // Video/Music
        if (d.Contains("youtube.com") || d.Contains("googlevideo.com") || d.Contains("ytimg.com"))
            return "YouTube";
        if (d.Contains("netflix.com") || d.Contains("nflxvideo.net"))
            return "Netflix";
        if (d.Contains("spotify.com") || d.Contains("scdn.co"))
            return "Spotify";

        // Google
        if (d.Contains("google.com") && !d.Contains("video"))
            return "Google";
        if (d.Contains("googleapis.com") || d.Contains("gstatic.com"))
            return "Google Services";
        if (d.Contains("gmail.com"))
            return "Gmail";

        // Microsoft
        if (d.Contains("microsoft.com") || d.Contains("msn.com"))
            return "Microsoft";
        if (d.Contains("outlook.com") || d.Contains("live.com"))
            return "Outlook";
        if (d.Contains("office.com"))
            return "Microsoft Office";

        // Tech
        if (d.Contains("github.com") || d.Contains("githubusercontent.com"))
            return "GitHub";
        if (d.Contains("zoom.us") || d.Contains("zoomcdn.com"))
            return "Zoom";
        if (d.Contains("amazon.com"))
            return "Amazon";

        // Default: extract primary domain
        return $"Web: {domain}";
    }

    private string GetLocalIPAddress()
    {
        try
        {
            using (var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, 0))
            {
                socket.Connect("8.8.8.8", 65530);
                if (socket.LocalEndPoint is System.Net.IPEndPoint endPoint)
                {
                    var ip = endPoint.Address.ToString();
                    if (!string.IsNullOrEmpty(ip) && ip != "0.0.0.0")
                    {
                        return ip;
                    }
                }
            }
        }
        catch
        {
            // fallback
        }

        try
        {
            var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
            var ips = host.AddressList
                .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !System.Net.IPAddress.IsLoopback(ip))
                .Select(ip => ip.ToString())
                .ToList();

            var preferredIp = ips.FirstOrDefault(ip => !ip.StartsWith("192.168.56.") && !ip.StartsWith("192.168.99.") && !ip.StartsWith("169.254."));
            if (preferredIp != null)
                return preferredIp;

            if (ips.Count > 0)
                return ips[0];
        }
        catch
        {
            // ignore
        }
        return "127.0.0.1";
    }

    /// <summary>
    /// Checks if a process is a background system process
    /// </summary>
    public static bool IsBackgroundProcess(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return true;
        
        var lower = processName.ToLowerInvariant();
        
        var systemBackgrounds = new[] {
            "system", "svchost", "lsass", "services", "wininit", "winlogon", 
            "spoolsv", "searchindexer", "msmpeng", "runtimebroker", "taskhostw", 
            "dllhost", "conhost", "dashost", "explorer", "sihost", "smartscreen",
            "ctfmon", "shellexperiencehost", "startmenuexperiencehelper", 
            "securityhealthservice", "onedrive", "dropbox", "googledrivesync", 
            "wuauserv", "netsh", "cmd", "powershell", "backgroundtaskhost", "helper"
        };
        
        return systemBackgrounds.Any(bg => lower.Contains(bg) || lower == bg);
    }
}

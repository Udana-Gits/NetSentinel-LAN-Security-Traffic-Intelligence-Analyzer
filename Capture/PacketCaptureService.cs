using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSentinel.Data;
using NetSentinel.Utils;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Serilog;

namespace NetSentinel.Capture;

/// <summary>
/// Packet capture service using Npcap/WinPcap and SharpPcap
/// </summary>
public class PacketCaptureService
{
    private readonly ILogger _logger;
    private readonly DatabaseService _database;
    private ILiveDevice? _captureDevice;
    private bool _isCapturing;
    private CancellationTokenSource? _cts;

    private readonly List<SniffedConnection> _activeFlows = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _resolvedDomains = new();

    public List<SniffedConnection> ActiveFlows
    {
        get
        {
            lock (_activeFlows)
            {
                return new List<SniffedConnection>(_activeFlows);
            }
        }
    }

    public event EventHandler<HttpLoginEventArgs>? HttpLoginAttemptDetected;
    public event EventHandler<HttpLoginFailureEventArgs>? HttpLoginFailureDetected;

    private long _totalPackets;
    private long _tcpPackets;
    private long _udpPackets;
    private long _icmpPackets;
    private long _arpPackets;
    private long _dnsQueries;

    private readonly List<string> _recentDnsQueries;
    private readonly object _statsLock = new();

    public long TotalPackets => _totalPackets;
    public long TcpPackets => _tcpPackets;
    public long UdpPackets => _udpPackets;
    public long IcmpPackets => _icmpPackets;
    public long ArpPackets => _arpPackets;
    public long DnsQueries => _dnsQueries;

    public event EventHandler<PacketCapturedEventArgs>? PacketCaptured;
    public event EventHandler<DnsQueryEventArgs>? DnsQueryDetected;
    public event EventHandler<ArpEventArgs>? ArpPacketDetected;

    public PacketCaptureService(ILogger logger, DatabaseService database)
    {
        _logger = logger;
        _database = database;
        _recentDnsQueries = new List<string>();
    }

    /// <summary>
    /// Checks if Npcap is available
    /// </summary>
    public bool IsNpcapAvailable()
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            return devices.Count > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Starts packet capture on the specified interface
    /// </summary>
    public async Task<bool> StartCaptureAsync(string interfaceName)
    {
        if (_isCapturing)
        {
            _logger.Warning("Packet capture already running");
            return false;
        }

        if (!AdminChecker.IsRunningAsAdministrator())
        {
            _logger.Warning("Administrator privileges required for packet capture");
            return false;
        }

        try
        {
            var devices = CaptureDeviceList.Instance;
            _captureDevice = devices.FirstOrDefault(d => d.Name.Contains(interfaceName) || d.Description.Contains(interfaceName));

            if (_captureDevice == null)
            {
                // Try to get any active device
                _captureDevice = devices.FirstOrDefault();
            }

            if (_captureDevice == null)
            {
                _logger.Error("No capture device found");
                return false;
            }

            _captureDevice.OnPacketArrival += OnPacketArrival;
            _captureDevice.Open(DeviceModes.Promiscuous, 1000);
            _captureDevice.StartCapture();

            _isCapturing = true;
            _cts = new CancellationTokenSource();

            // Start statistics collection task
            _ = Task.Run(() => StatisticsLoopAsync(_cts.Token), _cts.Token);

            _logger.Information("Packet capture started on device: {Device}", _captureDevice.Description);
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to start packet capture");
            return false;
        }
    }

    /// <summary>
    /// Stops packet capture
    /// </summary>
    public void StopCapture()
    {
        if (!_isCapturing)
            return;

        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;

            if (_captureDevice != null)
            {
                _captureDevice.StopCapture();
                _captureDevice.Close();
                _captureDevice.OnPacketArrival -= OnPacketArrival;
                _captureDevice = null;
            }

            _isCapturing = false;
            _logger.Information("Packet capture stopped");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error stopping packet capture");
        }
    }

    /// <summary>
    /// Packet arrival event handler
    /// </summary>
    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            lock (_statsLock)
            {
                _totalPackets++;
            }

            // Process Ethernet packet
            if (packet is EthernetPacket ethernetPacket)
            {
                ProcessEthernetPacket(ethernetPacket);
            }

            PacketCaptured?.Invoke(this, new PacketCapturedEventArgs
            {
                Timestamp = rawPacket.Timeval.Date,
                Length = rawPacket.Data.Length
            });
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Error processing packet");
        }
    }

    /// <summary>
    /// Processes Ethernet packets
    /// </summary>
    private void ProcessEthernetPacket(EthernetPacket ethernetPacket)
    {
        // Check for ARP
        if (ethernetPacket.Type == EthernetType.Arp)
        {
            ProcessArpPacket(ethernetPacket);
            return;
        }

        // Process IP packets
        if (ethernetPacket.PayloadPacket is IPPacket ipPacket)
        {
            ProcessIpPacket(ipPacket);
        }
    }

    /// <summary>
    /// Processes IP packets
    /// </summary>
    private void ProcessIpPacket(IPPacket ipPacket)
    {
        string sourceIp = ipPacket.SourceAddress.ToString();
        string destIp = ipPacket.DestinationAddress.ToString();
        int srcPort = 0;
        int destPort = 0;
        string protocol = "IP";
        byte[] payloadData = Array.Empty<byte>();

        // TCP
        if (ipPacket.Protocol == ProtocolType.Tcp)
        {
            lock (_statsLock)
            {
                _tcpPackets++;
            }

            if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
            {
                srcPort = tcpPacket.SourcePort;
                destPort = tcpPacket.DestinationPort;
                protocol = "TCP";
                payloadData = tcpPacket.PayloadData;

                // Check for DNS over TCP (port 53)
                if (tcpPacket.SourcePort == 53 || tcpPacket.DestinationPort == 53)
                {
                    ProcessDnsPacket(tcpPacket.PayloadData, sourceIp);
                }
            }
        }
        // UDP
        else if (ipPacket.Protocol == ProtocolType.Udp)
        {
            lock (_statsLock)
            {
                _udpPackets++;
            }

            if (ipPacket.PayloadPacket is UdpPacket udpPacket)
            {
                srcPort = udpPacket.SourcePort;
                destPort = udpPacket.DestinationPort;
                protocol = "UDP";

                // Check for DNS (port 53)
                if (udpPacket.SourcePort == 53 || udpPacket.DestinationPort == 53)
                {
                    ProcessDnsPacket(udpPacket.PayloadData, sourceIp);
                }
            }
        }
        // ICMP
        else if (ipPacket.Protocol == ProtocolType.Icmp || ipPacket.Protocol == ProtocolType.IcmpV6)
        {
            lock (_statsLock)
            {
                _icmpPackets++;
            }
        }

        // Track active connection flows (excluding loopbacks)
        if (srcPort > 0 && destPort > 0 && sourceIp != "127.0.0.1" && destIp != "127.0.0.1")
        {
            UpdateFlow(sourceIp, srcPort, destIp, destPort, protocol);

            // Check for unencrypted HTTP login forms (port 80)
            if (destPort == 80 && payloadData != null && payloadData.Length > 0)
            {
                ProcessHttpPacket(payloadData, sourceIp);
            }
            // Check for unencrypted HTTP responses (port 80 source port)
            else if (srcPort == 80 && payloadData != null && payloadData.Length > 0)
            {
                ProcessHttpResponsePacket(payloadData, destIp, sourceIp);
            }
        }
    }

    /// <summary>
    /// Processes ARP packets
    /// </summary>
    private void ProcessArpPacket(EthernetPacket ethernetPacket)
    {
        lock (_statsLock)
        {
            _arpPackets++;
        }

        try
        {
            if (ethernetPacket.PayloadPacket is ArpPacket arpPacket)
            {
                ArpPacketDetected?.Invoke(this, new ArpEventArgs
                {
                    SenderIpAddress = arpPacket.SenderProtocolAddress.ToString(),
                    SenderMacAddress = arpPacket.SenderHardwareAddress.ToString(),
                    TargetIpAddress = arpPacket.TargetProtocolAddress.ToString(),
                    IsRequest = arpPacket.Operation == ArpOperation.Request
                });
            }
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Error processing ARP packet");
        }
    }

    /// <summary>
    /// Processes DNS packets (basic extraction)
    /// </summary>
    private void ProcessDnsPacket(byte[] payload, string sourceIp)
    {
        try
        {
            lock (_statsLock)
            {
                _dnsQueries++;
            }

            // Basic DNS query detection (this is simplified)
            // In production, you'd use a proper DNS parser
            if (payload != null && payload.Length > 12)
            {
                // DNS queries are complex to parse, simplified here
                var query = ExtractDnsQuery(payload);
                if (!string.IsNullOrEmpty(query))
                {
                    lock (_recentDnsQueries)
                    {
                        _recentDnsQueries.Add(query);
                        if (_recentDnsQueries.Count > 100)
                        {
                            _recentDnsQueries.RemoveAt(0);
                        }
                    }

                    DnsQueryDetected?.Invoke(this, new DnsQueryEventArgs
                    {
                        Query = query,
                        SourceIp = sourceIp,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Error processing DNS packet");
        }
    }

    /// <summary>
    /// Extracts DNS query from packet (simplified)
    /// </summary>
    private string ExtractDnsQuery(byte[] payload)
    {
        // This is a simplified DNS query extraction
        // A production implementation would use a proper DNS parser library
        try
        {
            if (payload.Length < 13)
                return string.Empty;

            // Skip DNS header (12 bytes) and parse query name
            int offset = 12;
            var labels = new List<string>();

            while (offset < payload.Length && payload[offset] != 0)
            {
                int labelLength = payload[offset];
                if (labelLength == 0 || offset + labelLength >= payload.Length)
                    break;

                offset++;
                var label = System.Text.Encoding.ASCII.GetString(payload, offset, labelLength);
                labels.Add(label);
                offset += labelLength;
            }

            return labels.Count > 0 ? string.Join(".", labels) : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Statistics collection loop
    /// </summary>
    private async Task StatisticsLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(60000, cancellationToken); // Every minute

                PacketStats stats;
                lock (_statsLock)
                {
                    stats = new PacketStats
                    {
                        Timestamp = DateTime.UtcNow,
                        TotalPackets = _totalPackets,
                        TcpPackets = _tcpPackets,
                        UdpPackets = _udpPackets,
                        IcmpPackets = _icmpPackets,
                        ArpPackets = _arpPackets,
                        DnsQueries = _dnsQueries
                    };
                }

                await _database.AddPacketStatsAsync(stats);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in packet statistics loop");
            }
        }
    }

    /// <summary>
    /// Gets recent DNS queries
    /// </summary>
    public List<string> GetRecentDnsQueries()
    {
        lock (_recentDnsQueries)
        {
            return new List<string>(_recentDnsQueries);
        }
    }

    /// <summary>
    /// Gets packet statistics
    /// </summary>
    public PacketStats GetCurrentStats()
    {
        lock (_statsLock)
        {
            return new PacketStats
            {
                Timestamp = DateTime.UtcNow,
                TotalPackets = _totalPackets,
                TcpPackets = _tcpPackets,
                UdpPackets = _udpPackets,
                IcmpPackets = _icmpPackets,
                ArpPackets = _arpPackets,
                DnsQueries = _dnsQueries
            };
        }
    }

    public string ResolveDomainName(string ipAddress)
    {
        if (string.IsNullOrEmpty(ipAddress) || ipAddress == "0.0.0.0" || ipAddress == "127.0.0.1" || ipAddress == "*")
            return ipAddress;

        if (_resolvedDomains.TryGetValue(ipAddress, out var domain))
        {
            return domain;
        }

        // Run reverse DNS in background to avoid blocking packet processing
        Task.Run(() =>
        {
            try
            {
                var host = System.Net.Dns.GetHostEntry(ipAddress);
                var name = host.HostName;
                _resolvedDomains[ipAddress] = name;
            }
            catch
            {
                _resolvedDomains[ipAddress] = ipAddress; // Cache IP as fallback to prevent repeated retries
            }
        });

        return ipAddress;
    }

    private void UpdateFlow(string srcIp, int srcPort, string destIp, int destPort, string protocol)
    {
        var now = DateTime.UtcNow;
        lock (_activeFlows)
        {
            // Prune old flows (older than 25 seconds)
            _activeFlows.RemoveAll(f => (now - f.LastSeen).TotalSeconds > 25);

            var existing = _activeFlows.FirstOrDefault(f => 
                f.SourceIp == srcIp && f.SourcePort == srcPort && 
                f.DestinationIp == destIp && f.DestinationPort == destPort);

            if (existing != null)
            {
                existing.LastSeen = now;
            }
            else
            {
                _activeFlows.Add(new SniffedConnection
                {
                    SourceIp = srcIp,
                    SourcePort = srcPort,
                    DestinationIp = destIp,
                    DestinationPort = destPort,
                    Protocol = protocol,
                    LastSeen = now
                });
            }
        }
    }

    private void ProcessHttpPacket(byte[] payload, string sourceIp)
    {
        try
        {
            if (payload == null || payload.Length < 40) return;

            var text = System.Text.Encoding.ASCII.GetString(payload);
            // Check if it's a HTTP POST request
            if (text.StartsWith("POST ", StringComparison.OrdinalIgnoreCase))
            {
                // Check if it's a login attempt by scanning form parameters
                if (text.Contains("password=") || text.Contains("passwd=") || text.Contains("pwd=") || text.Contains("pass="))
                {
                    var host = ExtractHostHeader(text);
                    var username = ExtractCredential(text, new[] { "username", "user", "email", "login", "id" });

                    HttpLoginAttemptDetected?.Invoke(this, new HttpLoginEventArgs
                    {
                        SourceIp = sourceIp,
                        Website = host,
                        Username = username,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Error processing HTTP login payload");
        }
    }

    private void ProcessHttpResponsePacket(byte[] payload, string clientIp, string serverIp)
    {
        try
        {
            if (payload == null || payload.Length < 40) return;

            var text = System.Text.Encoding.ASCII.GetString(payload);
            
            // Check if it looks like an HTTP response and contains login failure keywords
            if (text.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
            {
                var lowerText = text.ToLowerInvariant();
                var loginErrorKeywords = new[] {
                    "email and password do not match",
                    "emails and passwords do not match",
                    "username and password do not match",
                    "user and password do not match",
                    "credentials do not match",
                    "incorrect password",
                    "incorrect credentials",
                    "invalid credentials",
                    "invalid username or password",
                    "invalid email or password",
                    "wrong password",
                    "password you entered is incorrect",
                    "wrong email or password",
                    "authentication failed",
                    "wrong credentials",
                    "credentials you entered are invalid"
                };

                if (loginErrorKeywords.Any(k => lowerText.Contains(k)))
                {
                    var website = ResolveDomainName(serverIp);
                    if (string.IsNullOrEmpty(website) || website == serverIp)
                    {
                        website = "HTTP Web Service";
                    }

                    HttpLoginFailureDetected?.Invoke(this, new HttpLoginFailureEventArgs
                    {
                        SourceIp = clientIp,
                        Website = website,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Error processing HTTP response payload");
        }
    }

    private string ExtractHostHeader(string httpText)
    {
        var lines = httpText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        var hostLine = lines.FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase));
        if (hostLine != null)
        {
            return hostLine.Substring(5).Trim();
        }
        return "Unknown Website";
    }

    private string ExtractCredential(string httpText, string[] keys)
    {
        // Find empty line marking start of HTTP body
        var bodyIndex = httpText.IndexOf("\r\n\r\n");
        if (bodyIndex < 0) return "unknown";

        var body = httpText.Substring(bodyIndex + 4);
        var pairs = body.Split('&');
        foreach (var pair in pairs)
        {
            var parts = pair.Split('=');
            if (parts.Length == 2)
            {
                var paramName = parts[0].ToLowerInvariant();
                if (keys.Any(k => paramName.Contains(k)))
                {
                    try
                    {
                        return Uri.UnescapeDataString(parts[1]);
                    }
                    catch
                    {
                        return parts[1];
                    }
                }
            }
        }
        return "unknown";
    }
}

/// <summary>
/// Packet captured event arguments
/// </summary>
public class PacketCapturedEventArgs : EventArgs
{
    public DateTime Timestamp { get; set; }
    public int Length { get; set; }
}

/// <summary>
/// DNS query event arguments
/// </summary>
public class DnsQueryEventArgs : EventArgs
{
    public string Query { get; set; } = string.Empty;
    public string SourceIp { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// ARP event arguments
/// </summary>
public class ArpEventArgs : EventArgs
{
    public string SenderIpAddress { get; set; } = string.Empty;
    public string SenderMacAddress { get; set; } = string.Empty;
    public string TargetIpAddress { get; set; } = string.Empty;
    public bool IsRequest { get; set; }
}

/// <summary>
/// HTTP login attempt details
/// </summary>
public class HttpLoginEventArgs : EventArgs
{
    public string SourceIp { get; set; } = string.Empty;
    public string Website { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// Sniffed network connection flow
/// </summary>
public class SniffedConnection
{
    public string SourceIp { get; set; } = string.Empty;
    public int SourcePort { get; set; }
    public string DestinationIp { get; set; } = string.Empty;
    public int DestinationPort { get; set; }
    public string Protocol { get; set; } = "TCP";
    public DateTime LastSeen { get; set; }
}

/// <summary>
/// HTTP login failure details
/// </summary>
public class HttpLoginFailureEventArgs : EventArgs
{
    public string SourceIp { get; set; } = string.Empty;
    public string Website { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

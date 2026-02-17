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
        // TCP
        if (ipPacket.Protocol == ProtocolType.Tcp)
        {
            lock (_statsLock)
            {
                _tcpPackets++;
            }

            if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
            {
                // Check for DNS over TCP (port 53)
                if (tcpPacket.SourcePort == 53 || tcpPacket.DestinationPort == 53)
                {
                    ProcessDnsPacket(tcpPacket.PayloadData);
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
                // Check for DNS (port 53)
                if (udpPacket.SourcePort == 53 || udpPacket.DestinationPort == 53)
                {
                    ProcessDnsPacket(udpPacket.PayloadData);
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
    private void ProcessDnsPacket(byte[] payload)
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

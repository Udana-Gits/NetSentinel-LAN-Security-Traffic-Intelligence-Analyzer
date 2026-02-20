using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using NetSentinel.Data;
using Serilog;

namespace NetSentinel.Core;

/// <summary>
/// Monitors network bandwidth usage in real-time
/// </summary>
public class BandwidthMonitor
{
    private readonly ILogger _logger;
    private readonly DatabaseService _database;
    private readonly NetworkManager _networkManager;
    
    private long _lastBytesSent;
    private long _lastBytesReceived;
    private DateTime _lastMeasurement;
    private bool _isRunning;
    private CancellationTokenSource? _cts;

    public double CurrentUploadSpeedKbps { get; private set; }
    public double CurrentDownloadSpeedKbps { get; private set; }
    public long TodayBytesSent { get; private set; }
    public long TodayBytesReceived { get; private set; }

    public event EventHandler<BandwidthEventArgs>? BandwidthUpdated;

    public BandwidthMonitor(ILogger logger, DatabaseService database, NetworkManager networkManager)
    {
        _logger = logger;
        _database = database;
        _networkManager = networkManager;
    }

    /// <summary>
    /// Starts monitoring bandwidth
    /// </summary>
    public async Task StartAsync()
    {
        if (_isRunning)
            return;

        _isRunning = true;
        _cts = new CancellationTokenSource();
        _lastMeasurement = DateTime.UtcNow;

        // Load today's totals from database
        var (sent, received) = await _database.GetTodayTotalAsync();
        TodayBytesSent = sent;
        TodayBytesReceived = received;

        // Initialize baseline
        GetCurrentStats(out _lastBytesSent, out _lastBytesReceived);

        _ = Task.Run(() => MonitorLoopAsync(_cts.Token), _cts.Token);
        
        _logger.Information("Bandwidth monitoring started");
    }

    /// <summary>
    /// Stops monitoring bandwidth
    /// </summary>
    public void Stop()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _logger.Information("Bandwidth monitoring stopped");
    }

    /// <summary>
    /// Main monitoring loop
    /// </summary>
    private async Task MonitorLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(1000, cancellationToken);

                var now = DateTime.UtcNow;
                var elapsed = (now - _lastMeasurement).TotalSeconds;

                if (elapsed < 0.5) continue;

                GetCurrentStats(out var currentBytesSent, out var currentBytesReceived);

                var bytesSentDelta = currentBytesSent - _lastBytesSent;
                var bytesReceivedDelta = currentBytesReceived - _lastBytesReceived;

                // Handle counter rollover or network interface change
                if (bytesSentDelta < 0 || bytesReceivedDelta < 0)
                {
                    _lastBytesSent = currentBytesSent;
                    _lastBytesReceived = currentBytesReceived;
                    _lastMeasurement = now;
                    continue;
                }

                // Calculate speeds in Kbps
                CurrentUploadSpeedKbps = (bytesSentDelta * 8) / (elapsed * 1000);
                CurrentDownloadSpeedKbps = (bytesReceivedDelta * 8) / (elapsed * 1000);

                // Update totals
                TodayBytesSent += bytesSentDelta;
                TodayBytesReceived += bytesReceivedDelta;

                // Save to database every minute
                if (now.Minute != _lastMeasurement.Minute)
                {
                    var entry = new BandwidthEntry
                    {
                        Timestamp = now,
                        BytesSent = bytesSentDelta,
                        BytesReceived = bytesReceivedDelta,
                        UploadSpeedKbps = CurrentUploadSpeedKbps,
                        DownloadSpeedKbps = CurrentDownloadSpeedKbps
                    };

                    await _database.AddBandwidthEntryAsync(entry);
                }

                // Reset daily totals at midnight
                if (now.Date > _lastMeasurement.Date)
                {
                    TodayBytesSent = 0;
                    TodayBytesReceived = 0;
                }

                _lastBytesSent = currentBytesSent;
                _lastBytesReceived = currentBytesReceived;
                _lastMeasurement = now;

                // Raise event
                BandwidthUpdated?.Invoke(this, new BandwidthEventArgs
                {
                    UploadSpeedKbps = CurrentUploadSpeedKbps,
                    DownloadSpeedKbps = CurrentDownloadSpeedKbps,
                    TodayBytesSent = TodayBytesSent,
                    TodayBytesReceived = TodayBytesReceived
                });
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in bandwidth monitoring loop");
                await Task.Delay(5000, cancellationToken);
            }
        }
    }

    /// <summary>
    /// Gets current network statistics from active interface
    /// </summary>
    private void GetCurrentStats(out long bytesSent, out long bytesReceived)
    {
        bytesSent = 0;
        bytesReceived = 0;

        try
        {
            // Get the current active network interface info
            var activeInterface = _networkManager.GetCurrentInterface();
            
            if (activeInterface != null)
            {
                // Find the specific network interface by name or MAC address
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.OperationalStatus == OperationalStatus.Up);

                foreach (var ni in interfaces)
                {
                    // Match by interface name or description
                    if (ni.Name == activeInterface.Name || 
                        ni.Description == activeInterface.Description)
                    {
                        var stats = ni.GetIPv4Statistics();
                        bytesSent = stats.BytesSent;
                        bytesReceived = stats.BytesReceived;
                        _logger.Debug("Bandwidth stats from {Interface}: Sent={Sent}, Received={Received}", 
                            ni.Name, bytesSent, bytesReceived);
                        return;
                    }
                }
            }
            
            // Fallback: if no active interface is set, use all non-virtual interfaces
            _logger.Debug("No active interface found, using all non-virtual interfaces");
            var fallbackInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up &&
                            ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                            ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                            !IsVirtualInterface(ni.Name, ni.Description));

            foreach (var ni in fallbackInterfaces)
            {
                var stats = ni.GetIPv4Statistics();
                bytesSent += stats.BytesSent;
                bytesReceived += stats.BytesReceived;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(ex, "Failed to get network statistics");
        }
    }

    /// <summary>
    /// Checks if a network interface is virtual
    /// </summary>
    private static bool IsVirtualInterface(string name, string description)
    {
        var virtualKeywords = new[] { "vmware", "virtualbox", "hyper-v", "docker", "wsl", "virtual", "vethernet" };
        var combinedText = $"{name} {description}".ToLower();
        
        return virtualKeywords.Any(keyword => combinedText.Contains(keyword));
    }

    /// <summary>
    /// Gets bandwidth history for a specified time period
    /// </summary>
    public async Task<BandwidthEntry[]> GetHistoryAsync(TimeSpan period)
    {
        var since = DateTime.UtcNow - period;
        var history = await _database.GetBandwidthHistoryAsync(since);
        return history.ToArray();
    }
}

/// <summary>
/// Bandwidth update event arguments
/// </summary>
public class BandwidthEventArgs : EventArgs
{
    public double UploadSpeedKbps { get; set; }
    public double DownloadSpeedKbps { get; set; }
    public long TodayBytesSent { get; set; }
    public long TodayBytesReceived { get; set; }
}

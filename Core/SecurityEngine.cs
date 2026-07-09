using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSentinel.Data;
using NetSentinel.Services;
using NetSentinel.Capture;
using Serilog;

namespace NetSentinel.Core;

/// <summary>
/// Security detection engine that evaluates rules and generates alerts
/// </summary>
public class SecurityEngine
{
    private readonly ILogger _logger;
    private readonly DatabaseService _database;
    private readonly AlertService _alertService;
    private readonly NetworkManager _networkManager;
    private readonly BandwidthMonitor _bandwidthMonitor;
    private readonly ConnectionMonitor _connectionMonitor;
    private readonly DeviceScanner _deviceScanner;
    private readonly PacketCaptureService _packetCapture;
    private readonly ThreatIntelService _threatIntelService;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<(string Ip, string Domain), DateTime> _lastMaliciousDomainAlertTimes = new();

    private readonly List<SecurityRule> _rules;
    private string? _lastKnownGatewayMac;
    private readonly HashSet<string> _knownDeviceMacs;
    private bool _isRunning;
    private CancellationTokenSource? _cts;

    // Excessive connections tracking
    private readonly Queue<(DateTime Timestamp, int ConnectionCount)> _connectionBaseline;
    private DateTime _lastExcessiveConnectionAlert;
    private const int BaselineWindowSeconds = 60;
    private const int DebounceSeconds = 30;
    private const double ThresholdMultiplier = 1.8;

    // Gateway MAC spoof detection tracking
    private string? _suspectedNewGatewayMac;
    private DateTime _gatewayMacChangeFirstDetected;
    private int _gatewayMacRecheckCount;
    private DateTime _lastNetworkInterfaceChange;
    private string? _lastNetworkInterfaceName;
    private const int MaxMacRecheckAttempts = 3;
    private const int MacRecheckWindowSeconds = 10;
    private const int MacConfirmationSeconds = 20;
    private const int NetworkChangeIgnoreSeconds = 30;

    // Hotspot mode detection
    private bool _isHotspotMode;
    private const double HotspotThresholdMultiplier = 3.0; // Higher threshold for hotspots
    private const int HotspotMaxExpectedDevices = 3;
    private const int HotspotMacConfirmationSeconds = 60; // Less sensitive to MAC changes

    public SecurityEngine(
        ILogger logger,
        DatabaseService database,
        AlertService alertService,
        NetworkManager networkManager,
        BandwidthMonitor bandwidthMonitor,
        ConnectionMonitor connectionMonitor,
        DeviceScanner deviceScanner,
        PacketCaptureService packetCapture,
        ThreatIntelService threatIntelService)
    {
        _logger = logger;
        _database = database;
        _alertService = alertService;
        _networkManager = networkManager;
        _bandwidthMonitor = bandwidthMonitor;
        _connectionMonitor = connectionMonitor;
        _deviceScanner = deviceScanner;
        _packetCapture = packetCapture;
        _threatIntelService = threatIntelService;

        _rules = InitializeDefaultRules();
        _knownDeviceMacs = new HashSet<string>();
        _connectionBaseline = new Queue<(DateTime, int)>();
        _lastExcessiveConnectionAlert = DateTime.MinValue;
        _gatewayMacChangeFirstDetected = DateTime.MinValue;
        _lastNetworkInterfaceChange = DateTime.UtcNow;
        _isHotspotMode = false;
    }

    /// <summary>
    /// Initializes default security rules
    /// </summary>
    private List<SecurityRule> InitializeDefaultRules()
    {
        return new List<SecurityRule>
        {
            new SecurityRule
            {
                Name = "Gateway MAC Change",
                Description = "Detects when the gateway MAC address changes (possible ARP spoofing)",
                Type = RuleType.GatewayMacChange,
                Severity = AlertSeverity.Critical,
                IsEnabled = true,
                ThresholdValue = 0,
                EvaluationInterval = TimeSpan.FromSeconds(30)
            },
            new SecurityRule
            {
                Name = "Unknown Device",
                Description = "Alerts when a new unknown device joins the network",
                Type = RuleType.UnknownDevice,
                Severity = AlertSeverity.Warning,
                IsEnabled = true,
                ThresholdValue = 0,
                EvaluationInterval = TimeSpan.FromSeconds(60)
            },
            new SecurityRule
            {
                Name = "Traffic Spike",
                Description = "Detects unusual traffic spikes",
                Type = RuleType.TrafficSpike,
                Severity = AlertSeverity.Warning,
                IsEnabled = true,
                ThresholdValue = 10000, // KB/s
                EvaluationInterval = TimeSpan.FromSeconds(10)
            },
            new SecurityRule
            {
                Name = "Excessive Connections",
                Description = "Alerts when connection count exceeds 1.8x baseline average (60s window)",
                Type = RuleType.ExcessiveConnections,
                Severity = AlertSeverity.Warning,
                IsEnabled = true,
                ThresholdValue = 0, // Dynamic baseline calculation
                EvaluationInterval = TimeSpan.FromSeconds(5)
            },
            new SecurityRule
            {
                Name = "Port Scan Detected",
                Description = "Alerts when a device connects to more than 8 distinct ports on another host",
                Type = RuleType.PortScan,
                Severity = AlertSeverity.Warning,
                IsEnabled = true,
                ThresholdValue = 8,
                EvaluationInterval = TimeSpan.FromSeconds(10)
            }
        };
    }

    /// <summary>
    /// Starts the security engine
    /// </summary>
    public async Task StartAsync()
    {
        if (_isRunning)
            return;

        _isRunning = true;
        _cts = new CancellationTokenSource();

        // Detect hotspot mode
        DetectHotspotMode();

        // Load known devices
        var devices = await _deviceScanner.GetKnownDevicesAsync();
        foreach (var device in devices)
        {
            _knownDeviceMacs.Add(device.MacAddress);
            
            if (device.IsGateway)
            {
                _lastKnownGatewayMac = device.MacAddress;
            }
        }

        _packetCapture.DnsQueryDetected += OnDnsQueryDetected;
        _packetCapture.HttpLoginAttemptDetected += OnHttpLoginAttemptDetected;
        _packetCapture.HttpLoginFailureDetected += OnHttpLoginFailureDetected;

        _ = Task.Run(() => EvaluationLoopAsync(_cts.Token), _cts.Token);
        
        _logger.Information("Security engine started with {RuleCount} active rules", _rules.Count(r => r.IsEnabled));
    }

    /// <summary>
    /// Stops the security engine
    /// </summary>
    public void Stop()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _packetCapture.DnsQueryDetected -= OnDnsQueryDetected;
        _packetCapture.HttpLoginAttemptDetected -= OnHttpLoginAttemptDetected;
        _packetCapture.HttpLoginFailureDetected -= OnHttpLoginFailureDetected;

        _logger.Information("Security engine stopped");
    }

    /// <summary>
    /// Main evaluation loop
    /// </summary>
    private async Task EvaluationLoopAsync(CancellationToken cancellationToken)
    {
        var lastEvaluations = new Dictionary<RuleType, DateTime>();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(5000, cancellationToken);

                foreach (var rule in _rules.Where(r => r.IsEnabled))
                {
                    if (lastEvaluations.TryGetValue(rule.Type, out var lastEval))
                    {
                        if (DateTime.UtcNow - lastEval < rule.EvaluationInterval)
                            continue;
                    }

                    await EvaluateRuleAsync(rule, cancellationToken);
                    lastEvaluations[rule.Type] = DateTime.UtcNow;
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in security engine evaluation loop");
                await Task.Delay(10000, cancellationToken);
            }
        }
    }

    /// <summary>
    /// Evaluates a specific rule
    /// </summary>
    private async Task EvaluateRuleAsync(SecurityRule rule, CancellationToken cancellationToken)
    {
        try
        {
            var settings = await _database.GetSettingsAsync();

            switch (rule.Type)
            {
                case RuleType.GatewayMacChange:
                    await CheckGatewayMacChangeAsync();
                    break;

                case RuleType.UnknownDevice:
                    await CheckUnknownDevicesAsync();
                    break;

                case RuleType.TrafficSpike:
                    await CheckTrafficSpikeAsync(settings.TrafficSpikeThreshold);
                    break;

                case RuleType.ExcessiveConnections:
                    await CheckExcessiveConnectionsAsync(settings.ConnectionCountThreshold);
                    break;

                case RuleType.PortScan:
                    var portScanThreshold = settings.PortScanThreshold > 0 ? settings.PortScanThreshold : 8;
                    await CheckPortScanAsync(portScanThreshold);
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to evaluate rule {RuleName}", rule.Name);
        }
    }

    /// <summary>
    /// Detects if the current network is a mobile hotspot
    /// </summary>
    private void DetectHotspotMode()
    {
        var networkInfo = _networkManager.GetCurrentInterface();
        if (networkInfo == null || string.IsNullOrEmpty(networkInfo.Gateway))
        {
            _isHotspotMode = false;
            return;
        }

        var gatewayParts = networkInfo.Gateway.Split('.');
        if (gatewayParts.Length != 4)
        {
            _isHotspotMode = false;
            return;
        }

        // Check for hotspot IP ranges:
        // 10.x.x.x
        // 172.20.x.x
        // 192.168.43.x
        bool isHotspot = false;

        if (gatewayParts[0] == "10")
        {
            isHotspot = true;
        }
        else if (gatewayParts[0] == "172" && gatewayParts[1] == "20")
        {
            isHotspot = true;
        }
        else if (gatewayParts[0] == "192" && gatewayParts[1] == "168" && gatewayParts[2] == "43")
        {
            isHotspot = true;
        }

        _isHotspotMode = isHotspot;

        if (_isHotspotMode)
        {
            _logger.Information("Hotspot mode detected! Gateway: {Gateway}. Adjusting security sensitivity.", networkInfo.Gateway);
        }
        else
        {
            _logger.Debug("Normal network mode. Gateway: {Gateway}", networkInfo.Gateway);
        }
    }

    /// <summary>
    /// Checks for gateway MAC address changes with validation and recheck logic
    /// </summary>
    private async Task CheckGatewayMacChangeAsync()
    {
        var networkInfo = _networkManager.GetCurrentInterface();
        if (networkInfo == null)
            return;

        // Re-detect hotspot mode periodically
        DetectHotspotMode();

        // Check if network interface changed
        if (_lastNetworkInterfaceName != null && _lastNetworkInterfaceName != networkInfo.Name)
        {
            _lastNetworkInterfaceChange = DateTime.UtcNow;
            _lastNetworkInterfaceName = networkInfo.Name;
            _lastKnownGatewayMac = null; // Reset gateway MAC when interface changes
            _suspectedNewGatewayMac = null;
            _gatewayMacChangeFirstDetected = DateTime.MinValue;
            _gatewayMacRecheckCount = 0;
            _logger.Information("Network interface changed to {Name}, resetting gateway MAC tracking", networkInfo.Name);
            return;
        }

        if (_lastNetworkInterfaceName == null)
        {
            _lastNetworkInterfaceName = networkInfo.Name;
        }

        var devices = await _deviceScanner.GetKnownDevicesAsync();
        var gateway = devices.FirstOrDefault(d => d.IsGateway);

        if (gateway == null)
            return;

        // Initialize known gateway MAC on first detection
        if (_lastKnownGatewayMac == null)
        {
            _lastKnownGatewayMac = gateway.MacAddress;
            _logger.Information("Initial gateway MAC stored: {MAC}", _lastKnownGatewayMac);
            return;
        }

        var now = DateTime.UtcNow;
        var currentGatewayMac = gateway.MacAddress;

        // Gateway MAC matches known MAC - all good
        if (currentGatewayMac == _lastKnownGatewayMac)
        {
            // Reset tracking if MAC returned to normal
            if (_suspectedNewGatewayMac != null)
            {
                _logger.Information("Gateway MAC returned to expected value: {MAC}", _lastKnownGatewayMac);
                _suspectedNewGatewayMac = null;
                _gatewayMacChangeFirstDetected = DateTime.MinValue;
                _gatewayMacRecheckCount = 0;
            }
            return;
        }

        // Ignore MAC changes if network interface changed within last 30 seconds
        var timeSinceInterfaceChange = (now - _lastNetworkInterfaceChange).TotalSeconds;
        if (timeSinceInterfaceChange < NetworkChangeIgnoreSeconds)
        {
            _logger.Debug("Ignoring gateway MAC change - network interface changed {Seconds}s ago", 
                (int)timeSinceInterfaceChange);
            return;
        }

        // First detection of MAC change
        if (_suspectedNewGatewayMac == null)
        {
            _suspectedNewGatewayMac = currentGatewayMac;
            _gatewayMacChangeFirstDetected = now;
            _gatewayMacRecheckCount = 1;
            _logger.Warning("Gateway MAC change detected! Expected: {Expected}, Found: {Found}. Starting validation...",
                _lastKnownGatewayMac, currentGatewayMac);
            return;
        }

        // MAC changed to a different value than suspected - reset
        if (currentGatewayMac != _suspectedNewGatewayMac)
        {
            _logger.Warning("Gateway MAC changed again during validation. Resetting. Previous: {Previous}, New: {New}",
                _suspectedNewGatewayMac, currentGatewayMac);
            _suspectedNewGatewayMac = currentGatewayMac;
            _gatewayMacChangeFirstDetected = now;
            _gatewayMacRecheckCount = 1;
            return;
        }

        // Suspected MAC confirmed for second+ time
        var timeSinceFirstDetection = (now - _gatewayMacChangeFirstDetected).TotalSeconds;

        // Still within 10-second recheck window
        if (timeSinceFirstDetection < MacRecheckWindowSeconds)
        {
            _gatewayMacRecheckCount++;
            _logger.Debug("Gateway MAC recheck {Count}/{Max}: MAC still {MAC}",
                _gatewayMacRecheckCount, MaxMacRecheckAttempts, currentGatewayMac);
            return;
        }

        // Use longer confirmation period in hotspot mode (60s vs 20s)
        var requiredConfirmationSeconds = _isHotspotMode ? HotspotMacConfirmationSeconds : MacConfirmationSeconds;

        // After confirmation period of consistent MAC change, trigger alert
        if (timeSinceFirstDetection >= requiredConfirmationSeconds && 
            _gatewayMacRecheckCount >= MaxMacRecheckAttempts)
        {
            await _alertService.RaiseAlertAsync(new SecurityAlert
            {
                Timestamp = now,
                Severity = _isHotspotMode ? AlertSeverity.Warning : AlertSeverity.Critical,
                Title = _isHotspotMode ? "Hotspot Gateway MAC Changed" : "Gateway MAC Address Changed!",
                Description = $"Gateway MAC changed from {_lastKnownGatewayMac} to {currentGatewayMac} and remained different for {(int)timeSinceFirstDetection}s. " +
                             $"Validated {_gatewayMacRecheckCount} times. " +
                             (_isHotspotMode ? "Hotspot mode: May be normal behavior." : "Possible ARP spoofing attack!"),
                SourceIp = gateway.IpAddress,
                SourceMac = currentGatewayMac
            });

            _logger.Error("CRITICAL: Gateway MAC spoof attack confirmed! Old: {Old}, New: {New}, Duration: {Duration}s",
                _lastKnownGatewayMac, currentGatewayMac, (int)timeSinceFirstDetection);

            // Update to new MAC and reset tracking
            _lastKnownGatewayMac = currentGatewayMac;
            _suspectedNewGatewayMac = null;
            _gatewayMacChangeFirstDetected = DateTime.MinValue;
            _gatewayMacRecheckCount = 0;
        }
    }

    /// <summary>
    /// Checks for unknown devices
    /// </summary>
    private async Task CheckUnknownDevicesAsync()
    {
        var devices = await _deviceScanner.GetKnownDevicesAsync();
        var onlineDevices = devices.Where(d => d.IsOnline).ToList();

        // In hotspot mode, expect max 3 devices
        if (_isHotspotMode && onlineDevices.Count > HotspotMaxExpectedDevices)
        {
            await _alertService.RaiseAlertAsync(new SecurityAlert
            {
                Timestamp = DateTime.UtcNow,
                Severity = AlertSeverity.Warning,
                Title = "Hotspot Device Limit Exceeded",
                Description = $"Hotspot mode detected with {onlineDevices.Count} devices (expected max {HotspotMaxExpectedDevices}). " +
                             "Verify all connected devices are authorized."
            });
        }
        
        foreach (var device in onlineDevices)
        {
            if (!_knownDeviceMacs.Contains(device.MacAddress))
            {
                _knownDeviceMacs.Add(device.MacAddress);

                await _alertService.RaiseAlertAsync(new SecurityAlert
                {
                    Timestamp = DateTime.UtcNow,
                    Severity = AlertSeverity.Warning,
                    Title = "New Device Detected",
                    Description = $"Unknown device joined the network: {device.Vendor} ({device.IpAddress})",
                    SourceIp = device.IpAddress,
                    SourceMac = device.MacAddress
                });
            }
        }
    }

    /// <summary>
    /// Checks for traffic spikes
    /// </summary>
    private async Task CheckTrafficSpikeAsync(int thresholdKbps)
    {
        var uploadSpeed = _bandwidthMonitor.CurrentUploadSpeedKbps;
        var downloadSpeed = _bandwidthMonitor.CurrentDownloadSpeedKbps;

        var localIp = GetLocalIPAddress();

        if (uploadSpeed > thresholdKbps)
        {
            await _alertService.RaiseAlertAsync(new SecurityAlert
            {
                Timestamp = DateTime.UtcNow,
                Severity = AlertSeverity.Warning,
                Title = "High Upload Traffic Detected",
                Description = $"Upload speed exceeded threshold: {uploadSpeed:F2} KB/s (threshold: {thresholdKbps} KB/s)",
                SourceIp = localIp
            });
        }

        if (downloadSpeed > thresholdKbps)
        {
            await _alertService.RaiseAlertAsync(new SecurityAlert
            {
                Timestamp = DateTime.UtcNow,
                Severity = AlertSeverity.Warning,
                Title = "High Download Traffic Detected",
                Description = $"Download speed exceeded threshold: {downloadSpeed:F2} KB/s (threshold: {thresholdKbps} KB/s)",
                SourceIp = localIp
            });
        }
    }

    /// <summary>
    /// Checks for excessive connections using dynamic baseline calculation and absolute limit
    /// </summary>
    private async Task CheckExcessiveConnectionsAsync(int minThreshold)
    {
        var stats = _connectionMonitor.GetStatistics();
        var now = DateTime.UtcNow;
        var currentConnections = stats.TotalConnections;

        // Add current connection count to baseline window
        _connectionBaseline.Enqueue((now, currentConnections));

        // Remove entries older than 60 seconds
        while (_connectionBaseline.Count > 0 && 
               (now - _connectionBaseline.Peek().Timestamp).TotalSeconds > BaselineWindowSeconds)
        {
            _connectionBaseline.Dequeue();
        }

        // Need at least 10 samples to establish baseline (avoid false positives on startup)
        if (_connectionBaseline.Count < 10)
        {
            _logger.Debug("Building connection baseline: {Count}/10 samples", _connectionBaseline.Count);
            return;
        }

        // Calculate baseline average
        var baselineAverage = _connectionBaseline.Average(x => x.ConnectionCount);
        
        // Use higher threshold multiplier in hotspot mode
        var thresholdMultiplier = _isHotspotMode ? HotspotThresholdMultiplier : ThresholdMultiplier;
        var dynamicThreshold = baselineAverage * thresholdMultiplier;

        _logger.Debug("Connection check - Current: {Current}, Baseline: {Baseline:F1}, Threshold: {Threshold:F1}, Hotspot: {IsHotspot}",
            currentConnections, baselineAverage, dynamicThreshold, _isHotspotMode);

        // Check if current connections exceed threshold and absolute minimum threshold
        if (currentConnections > dynamicThreshold && currentConnections > minThreshold)
        {
            // Apply debounce - only alert if 30 seconds have passed since last alert
            var timeSinceLastAlert = (now - _lastExcessiveConnectionAlert).TotalSeconds;
            if (timeSinceLastAlert < DebounceSeconds)
            {
                _logger.Debug("Excessive connections detected but debounced ({Seconds}s since last alert)", 
                    (int)timeSinceLastAlert);
                return;
            }

            _lastExcessiveConnectionAlert = now;

            await _alertService.RaiseAlertAsync(new SecurityAlert
            {
                Timestamp = now,
                Severity = AlertSeverity.Warning,
                Title = "Excessive Network Connections",
                Description = $"Connection count ({currentConnections}) exceeds baseline threshold ({dynamicThreshold:F0}). " +
                             $"Baseline average: {baselineAverage:F1} connections over {BaselineWindowSeconds}s.",
                SourceIp = GetLocalIPAddress()
            });

            _logger.Warning("Excessive connections alert raised: Current={Current}, Baseline={Baseline:F1}, Threshold={Threshold:F1}",
                currentConnections, baselineAverage, dynamicThreshold);
        }
    }

    // Track last port scan alerts to debounce
    private readonly Dictionary<string, DateTime> _lastPortScanAlert = new();

    private async Task CheckPortScanAsync(int thresholdPorts)
    {
        var activeConnections = _connectionMonitor.ActiveConnections;
        if (activeConnections == null || activeConnections.Count == 0)
            return;

        var now = DateTime.UtcNow;

        // Detect Inbound Scan (Remote IP scanning multiple Local Ports)
        var remoteGroups = activeConnections
            .Where(c => !string.IsNullOrEmpty(c.RemoteAddress) && c.RemoteAddress != "0.0.0.0" && c.RemoteAddress != "127.0.0.1" && c.RemoteAddress != "*")
            .GroupBy(c => c.RemoteAddress);

        foreach (var group in remoteGroups)
        {
            var remoteIp = group.Key;
            var distinctPorts = group.Select(c => c.LocalPort).Distinct().ToList();

            if (distinctPorts.Count > thresholdPorts)
            {
                lock (_lastPortScanAlert)
                {
                    if (_lastPortScanAlert.TryGetValue(remoteIp, out var lastAlert) && (now - lastAlert).TotalSeconds < 30)
                    {
                        continue;
                    }
                    _lastPortScanAlert[remoteIp] = now;
                }

                var devices = await _deviceScanner.GetKnownDevicesAsync();
                var dev = devices.FirstOrDefault(d => d.IpAddress == remoteIp);
                var deviceName = dev != null ? $"{dev.Vendor} ({remoteIp})" : remoteIp;

                await _alertService.RaiseAlertAsync(new SecurityAlert
                {
                    Timestamp = now,
                    Severity = AlertSeverity.Warning,
                    Title = "Inbound Port Scan Detected",
                    Description = $"Host {deviceName} attempted connections to {distinctPorts.Count} distinct local ports. This is highly indicative of network reconnaissance (port scanning).",
                    SourceIp = remoteIp,
                    SourceMac = dev?.MacAddress
                });
            }
        }

        // Detect Outbound Scan (Our host scanning a remote IP's multiple ports)
        var localGroups = activeConnections
            .Where(c => !string.IsNullOrEmpty(c.RemoteAddress) && c.RemoteAddress != "0.0.0.0" && c.RemoteAddress != "127.0.0.1" && c.RemoteAddress != "*")
            .GroupBy(c => c.RemoteAddress);

        foreach (var group in localGroups)
        {
            var remoteIp = group.Key;
            var distinctRemotePorts = group.Select(c => c.RemotePort).Distinct().ToList();

            if (distinctRemotePorts.Count > thresholdPorts)
            {
                lock (_lastPortScanAlert)
                {
                    if (_lastPortScanAlert.TryGetValue(remoteIp, out var lastAlert) && (now - lastAlert).TotalSeconds < 30)
                    {
                        continue;
                    }
                    _lastPortScanAlert[remoteIp] = now;
                }

                await _alertService.RaiseAlertAsync(new SecurityAlert
                {
                    Timestamp = now,
                    Severity = AlertSeverity.Warning,
                    Title = "Outbound Port Scan Activity",
                    Description = $"Local processes are connecting to {distinctRemotePorts.Count} distinct ports on remote host {remoteIp}. Possible local compromise or port scan tool active.",
                    SourceIp = GetLocalIPAddress()
                });
            }
        }
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
                    return endPoint.Address.ToString();
                }
            }
        }
        catch { }
        return "127.0.0.1";
    }

    // Track Facebook brute force queries: SourceIp -> (List of Timestamps)
    private readonly Dictionary<string, List<DateTime>> _fbDnsTracker = new();
    private readonly object _fbTrackerLock = new();
    private readonly Dictionary<string, DateTime> _lastFbAlertTime = new();

    private void OnDnsQueryDetected(object? sender, DnsQueryEventArgs e)
    {
        if (string.IsNullOrEmpty(e.SourceIp) || string.IsNullOrEmpty(e.Query))
            return;

        var query = e.Query.ToLowerInvariant();

        // Threat Intelligence & Reputation Filtering
        if (_threatIntelService.IsMalicious(query))
        {
            _ = RaiseMaliciousDomainAlertDebouncedAsync(e.SourceIp, query);
        }

        if (query.Contains("facebook.com") || query.Contains("fbcdn.net"))
        {
            var now = DateTime.UtcNow;
            int count = 0;

            lock (_fbTrackerLock)
            {
                if (!_fbDnsTracker.TryGetValue(e.SourceIp, out var timestamps))
                {
                    timestamps = new List<DateTime>();
                    _fbDnsTracker[e.SourceIp] = timestamps;
                }

                timestamps.Add(now);
                timestamps.RemoveAll(t => (now - t).TotalSeconds > 60);
                count = timestamps.Count;
            }

            if (count >= 15)
            {
                _ = RaiseFacebookAlertDebouncedAsync(e.SourceIp, count);
            }
        }
    }

    private async Task RaiseMaliciousDomainAlertDebouncedAsync(string ipAddress, string domain)
    {
        var now = DateTime.UtcNow;
        var key = (ipAddress, domain);
        if (_lastMaliciousDomainAlertTimes.TryGetValue(key, out var lastAlert) && (now - lastAlert).TotalSeconds < 60)
        {
            return;
        }
        _lastMaliciousDomainAlertTimes[key] = now;

        var devices = await _deviceScanner.GetKnownDevicesAsync();
        var dev = devices.FirstOrDefault(d => d.IpAddress == ipAddress);
        
        var localIp = GetLocalIPAddress();
        string deviceName;
        string? sourceIp;
        string? sourceMac = dev?.MacAddress;

        if (ipAddress == localIp || ipAddress == "127.0.0.1")
        {
            deviceName = "Local Laptop (This PC)";
            sourceIp = localIp;
        }
        else
        {
            deviceName = dev != null ? $"{dev.Vendor} ({ipAddress})" : ipAddress;
            sourceIp = ipAddress;
        }

        await _alertService.RaiseAlertAsync(new SecurityAlert
        {
            Timestamp = now,
            Severity = AlertSeverity.Critical,
            Title = "Threat Intelligence Alert: Malicious Domain Contact",
            Description = $"Device {deviceName} attempted to contact a known malicious domain: {domain}. This domain is flagged on the threat intelligence blocklist as associated with malware, phishing, or command-and-control (C&C) activities.",
            SourceIp = sourceIp,
            SourceMac = sourceMac
        });
        
        _logger.Warning("Threat Intelligence Alert raised: {Device} tried to access malicious domain {Domain}", deviceName, domain);
    }

    private async Task RaiseFacebookAlertDebouncedAsync(string ipAddress, int count)
    {
        var now = DateTime.UtcNow;
        lock (_fbTrackerLock)
        {
            if (_lastFbAlertTime.TryGetValue(ipAddress, out var lastAlert) && (now - lastAlert).TotalSeconds < 30)
            {
                return;
            }
            _lastFbAlertTime[ipAddress] = now;
        }

        var devices = await _deviceScanner.GetKnownDevicesAsync();
        var dev = devices.FirstOrDefault(d => d.IpAddress == ipAddress);
        var deviceName = dev != null ? $"{dev.Vendor} ({ipAddress})" : ipAddress;

        await _alertService.RaiseAlertAsync(new SecurityAlert
        {
            Timestamp = now,
            Severity = AlertSeverity.Critical,
            Title = "Potential Facebook Brute Force",
            Description = $"Device {deviceName} made {count} rapid requests to Facebook domains in the last 60 seconds, indicating a potential brute-force or unauthorized credential stuffing attack.",
            SourceIp = ipAddress,
            SourceMac = dev?.MacAddress
        });
    }

    // Track HTTP login attempts: "SourceIp|Website" -> List of timestamps
    private readonly Dictionary<string, List<DateTime>> _loginTracker = new();
    private readonly object _loginTrackerLock = new();
    private readonly Dictionary<string, DateTime> _lastBruteForceAlertTime = new();

    // Track local HTTP login failures: "SourceIp|Website" -> FailedLoginTracker
    private readonly Dictionary<string, FailedLoginTracker> _localFailedLoginTrackers = new();
    private readonly object _localFailedLoginTrackersLock = new();

    private void OnHttpLoginAttemptDetected(object? sender, HttpLoginEventArgs e)
    {
        if (string.IsNullOrEmpty(e.SourceIp) || string.IsNullOrEmpty(e.Website))
            return;

        _ = ProcessHttpLoginAttemptAsync(e);
    }

    private void OnHttpLoginFailureDetected(object? sender, HttpLoginFailureEventArgs e)
    {
        if (string.IsNullOrEmpty(e.SourceIp) || string.IsNullOrEmpty(e.Website))
            return;

        _ = ProcessLocalLoginFailureAsync(e.SourceIp, e.Website);
    }

    public async Task ProcessLocalLoginFailureAsync(string sourceIp, string website)
    {
        var now = DateTime.UtcNow;
        var settings = await _database.GetSettingsAsync();
        int thresholdCritical = settings.FailedLoginThresholdCritical;
        int thresholdWarning = settings.FailedLoginThresholdWarning;
        int thresholdInfo = settings.FailedLoginThresholdInfo;

        // Get source device MAC address if possible
        var devices = await _deviceScanner.GetKnownDevicesAsync();
        var dev = devices.FirstOrDefault(d => d.IpAddress == sourceIp);
        var sourceMac = dev?.MacAddress;
        var deviceName = dev != null ? $"{dev.Vendor} ({sourceIp})" : sourceIp;

        var key = $"{sourceIp}|{website.ToLowerInvariant()}";
        FailedLoginTracker tracker;
        lock (_localFailedLoginTrackersLock)
        {
            if (!_localFailedLoginTrackers.TryGetValue(key, out tracker!))
            {
                tracker = new FailedLoginTracker();
                _localFailedLoginTrackers[key] = tracker;
            }
        }

        lock (tracker)
        {
            // Clean up timestamps older than 5 minutes from this attempt
            var windowCutoff = now.AddMinutes(-5);
            tracker.Timestamps.RemoveAll(t => t < windowCutoff);

            // Add this attempt
            tracker.Timestamps.Add(now);

            int count = tracker.Timestamps.Count;

            if (count >= thresholdCritical)
            {
                _ = _alertService.RaiseAlertAsync(new SecurityAlert
                {
                    Timestamp = now,
                    Severity = AlertSeverity.Critical,
                    Title = $"Password Brute Force Suspected: {website}",
                    Description = $"Device {deviceName} had {count} failed login attempts on '{website}' within the last 5 minutes. This indicates a potential brute-force attack.",
                    SourceIp = sourceIp,
                    SourceMac = sourceMac
                });
            }
            else if (count >= thresholdWarning)
            {
                _ = _alertService.RaiseAlertAsync(new SecurityAlert
                {
                    Timestamp = now,
                    Severity = AlertSeverity.Warning,
                    Title = $"Multiple Login Failures: {website}",
                    Description = $"Device {deviceName} had {count} failed login attempts on '{website}' within the last 5 minutes. Please verify if this is authorized activity.",
                    SourceIp = sourceIp,
                    SourceMac = sourceMac
                });
            }
            else if (count >= thresholdInfo)
            {
                _ = _alertService.RaiseAlertAsync(new SecurityAlert
                {
                    Timestamp = now,
                    Severity = AlertSeverity.Info,
                    Title = $"Login Failure Detected: {website}",
                    Description = $"Device {deviceName} failed to login on '{website}'.",
                    SourceIp = sourceIp,
                    SourceMac = sourceMac
                });
            }
        }
    }

    private async Task ProcessHttpLoginAttemptAsync(HttpLoginEventArgs e)
    {
        var now = DateTime.UtcNow;

        // 1. Get source device MAC address if possible
        var devices = await _deviceScanner.GetKnownDevicesAsync();
        var dev = devices.FirstOrDefault(d => d.IpAddress == e.SourceIp);
        var sourceMac = dev?.MacAddress;
        var deviceName = dev != null ? $"{dev.Vendor} ({e.SourceIp})" : e.SourceIp;

        // 2. Raise individual warning alert for each login attempt
        await _alertService.RaiseAlertAsync(new SecurityAlert
        {
            Timestamp = now,
            Severity = AlertSeverity.Warning,
            Title = "HTTP Login Attempt",
            Description = $"Unencrypted HTTP login attempt on {e.Website} by user '{e.Username}' from device {deviceName}.",
            SourceIp = e.SourceIp,
            SourceMac = sourceMac
        });

        // 3. Track brute force threshold: > 5 attempts to same website within 30 seconds
        int count = 0;
        var key = $"{e.SourceIp}|{e.Website.ToLowerInvariant()}";
        lock (_loginTrackerLock)
        {
            if (!_loginTracker.TryGetValue(key, out var timestamps))
            {
                timestamps = new List<DateTime>();
                _loginTracker[key] = timestamps;
            }
            timestamps.Add(now);
            timestamps.RemoveAll(t => (now - t).TotalSeconds > 30);
            count = timestamps.Count;
        }

        if (count > 5)
        {
            await RaiseBruteForceAlertDebouncedAsync(e.SourceIp, sourceMac, deviceName, e.Website, count);
        }
    }

    private async Task RaiseBruteForceAlertDebouncedAsync(string ipAddress, string? sourceMac, string deviceName, string website, int count)
    {
        var now = DateTime.UtcNow;
        var alertKey = $"{ipAddress}|{website.ToLowerInvariant()}";
        lock (_loginTrackerLock)
        {
            if (_lastBruteForceAlertTime.TryGetValue(alertKey, out var lastAlert) && (now - lastAlert).TotalSeconds < 30)
            {
                return;
            }
            _lastBruteForceAlertTime[alertKey] = now;
        }

        await _alertService.RaiseAlertAsync(new SecurityAlert
        {
            Timestamp = now,
            Severity = AlertSeverity.Critical,
            Title = $"Credential Brute Force Attack: {website}",
            Description = $"Device {deviceName} is suspected of brute-forcing credentials on {website}. Detected {count} login attempts within 30 seconds.",
            SourceIp = ipAddress,
            SourceMac = sourceMac
        });

        _logger.Warning("CRITICAL: Brute force attack detected from {IP} on {Website}! Attempt count: {Count}", ipAddress, website, count);
    }

    /// <summary>
    /// Gets all security rules
    /// </summary>
    public List<SecurityRule> GetRules() => _rules;

    /// <summary>
    /// Updates a security rule
    /// </summary>
    public void UpdateRule(SecurityRule rule)
    {
        var existing = _rules.FirstOrDefault(r => r.Type == rule.Type);
        if (existing != null)
        {
            existing.IsEnabled = rule.IsEnabled;
            existing.ThresholdValue = rule.ThresholdValue;
            existing.EvaluationInterval = rule.EvaluationInterval;
            
            _logger.Information("Updated security rule: {RuleName}", rule.Name);
        }
    }
}

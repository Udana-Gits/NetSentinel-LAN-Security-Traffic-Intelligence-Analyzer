using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetSentinel.Data;
using NetSentinel.Core;
using Serilog;

namespace NetSentinel.Services;

/// <summary>
/// Lightweight HTTP server that receives telemetry data from NetSentinel mobile agents.
/// Listens on the configured port for incoming POST requests from Android/iOS agents.
/// </summary>
public class AgentReceiver
{
    private readonly ILogger _logger;
    private readonly DatabaseService _database;
    private readonly AlertService _alertService;
    private readonly NetworkManager _networkManager;
    private HttpListener? _listener;
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private bool _isRunning;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, AgentTelemetry> _latestTelemetry = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Concurrent.ConcurrentDictionary<string, CachedDomainVisit>> _activeMobileDomains = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<(string ip, string target), FailedLoginTracker> _failedLoginTrackers = new();

    /// <summary>
    /// Holds the latest received telemetry from each active mobile agent, keyed by device IP address.
    /// </summary>
    public System.Collections.Generic.IReadOnlyDictionary<string, AgentTelemetry> LatestTelemetry => _latestTelemetry;

    /// <summary>
    /// Returns the currently active domain connections for a mobile agent
    /// </summary>
    public System.Collections.Generic.List<DomainVisit> GetActiveDomainsForDevice(string ipAddress)
    {
        if (_activeMobileDomains.TryGetValue(ipAddress, out var domains))
        {
            return domains.Values.Select(d => new DomainVisit
            {
                Domain = d.Domain,
                AppLabel = d.AppLabel,
                Timestamp = new DateTimeOffset(d.LastSeen).ToUnixTimeMilliseconds(),
                IsBackground = d.IsBackground
            }).ToList();
        }
        return new System.Collections.Generic.List<DomainVisit>();
    }

    private const int DefaultPort = 5095;
    private const string DefaultApiKey = "netsentinel-default-key-change-me";
    private const int _agentReportIntervalSec = 3;

    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// The port the receiver is listening on
    /// </summary>
    public int Port { get; private set; } = DefaultPort;

    /// <summary>
    /// The API key required for authentication
    /// </summary>
    public string ApiKey { get; set; } = DefaultApiKey;

    /// <summary>
    /// Whether the receiver is currently running
    /// </summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// Event raised when agent telemetry is received
    /// </summary>
    public event EventHandler<AgentTelemetryReceivedEventArgs>? TelemetryReceived;

    /// <summary>
    /// Event raised when a new agent registers
    /// </summary>
    public event EventHandler<AgentRegistrationEventArgs>? AgentRegistered;

    public AgentReceiver(ILogger logger, DatabaseService database, AlertService alertService, NetworkManager networkManager)
    {
        _logger = logger;
        _database = database;
        _alertService = alertService;
        _networkManager = networkManager;
    }

    /// <summary>
    /// Starts the HTTP listener on the configured port
    /// </summary>
    public async Task StartAsync(int port = DefaultPort)
    {
        if (_isRunning)
            return;

        Port = port;

        try
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://+:{Port}/");
            _listener.Start();

            _isRunning = true;
            _cts = new CancellationTokenSource();

            _ = Task.Run(() => ListenLoopAsync(_cts.Token), _cts.Token);
            _ = Task.Run(() => StartUdpDiscoveryAsync(_cts.Token), _cts.Token);

            _logger.Information("Agent receiver started on port {Port}", Port);
        }
        catch (HttpListenerException ex) when (ex.ErrorCode == 5)
        {
            // Access denied — try localhost only
            _logger.Warning("Cannot bind to all interfaces (requires admin). Trying localhost only...");
            
            try
            {
                _listener = new HttpListener();
                _listener.Prefixes.Add($"http://localhost:{Port}/");
                _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
                _listener.Start();

                _isRunning = true;
                _cts = new CancellationTokenSource();

                _ = Task.Run(() => ListenLoopAsync(_cts.Token), _cts.Token);
                _ = Task.Run(() => StartUdpDiscoveryAsync(_cts.Token), _cts.Token);

                _logger.Information("Agent receiver started on localhost:{Port} (limited — run as admin for LAN access)", Port);
            }
            catch (Exception innerEx)
            {
                _logger.Error(innerEx, "Failed to start agent receiver even on localhost");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to start agent receiver on port {Port}", Port);
        }
    }

    /// <summary>
    /// Stops the HTTP listener
    /// </summary>
    public void Stop()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        _cts?.Cancel();
        
        try
        {
            _listener?.Stop();
            _listener?.Close();
        }
        catch (Exception ex)
        {
            _logger.Warning(ex, "Error stopping agent receiver");
        }

        try
        {
            _udpClient?.Dispose();
        }
        catch (Exception ex)
        {
            _logger.Warning(ex, "Error disposing UDP client");
        }
        _udpClient = null;

        _cts?.Dispose();
        _cts = null;
        _listener = null;

        _logger.Information("Agent receiver stopped");
    }

    /// <summary>
    /// Main HTTP listener loop
    /// </summary>
    private async Task ListenLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _isRunning)
        {
            try
            {
                var context = await _listener!.GetContextAsync();
                _ = Task.Run(() => HandleRequestAsync(context), cancellationToken);
            }
            catch (HttpListenerException) when (!_isRunning)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    _logger.Error(ex, "Error in agent receiver listen loop");
                    await Task.Delay(1000, cancellationToken);
                }
            }
        }
    }

    /// <summary>
    /// Handles an incoming HTTP request
    /// </summary>
    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;

        try
        {
            // Set CORS headers
            response.Headers.Add("Access-Control-Allow-Origin", "*");
            response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, X-Api-Key");

            // Handle CORS preflight
            if (request.HttpMethod == "OPTIONS")
            {
                response.StatusCode = 200;
                response.Close();
                return;
            }

            var path = request.Url?.AbsolutePath?.ToLowerInvariant() ?? "";

            _logger.Debug("Agent receiver request: {Method} {Path} from {RemoteIP}",
                request.HttpMethod, path, request.RemoteEndPoint?.Address);

            switch (path)
            {
                case "/api/agent/ping":
                    await HandlePingAsync(request, response);
                    break;

                case "/api/agent/register":
                    await HandleRegisterAsync(request, response);
                    break;

                case "/api/agent/telemetry":
                    await HandleTelemetryAsync(request, response);
                    break;

                default:
                    await SendJsonResponseAsync(response, 404, new { success = false, message = "Not found" });
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling agent request");
            try
            {
                await SendJsonResponseAsync(response, 500, new { success = false, message = "Internal server error" });
            }
            catch { /* Response may already be closed */ }
        }
    }

    /// <summary>
    /// Validates the API key from request headers
    /// </summary>
    private bool ValidateApiKey(HttpListenerRequest request)
    {
        var apiKey = request.Headers["X-Api-Key"];
        return !string.IsNullOrEmpty(apiKey) && apiKey == ApiKey;
    }

    /// <summary>
    /// Handles GET /api/agent/ping — simple connectivity check
    /// </summary>
    private async Task HandlePingAsync(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (!ValidateApiKey(request))
        {
            await SendJsonResponseAsync(response, 401, new { success = false, message = "Invalid API key" });
            return;
        }

        await SendJsonResponseAsync(response, 200, new
        {
            success = true,
            message = "NetSentinel Agent Receiver is running",
            version = "1.0.0",
            timestamp = DateTime.UtcNow.ToString("o")
        });
    }

    /// <summary>
    /// Handles POST /api/agent/register — new agent registration
    /// </summary>
    private async Task HandleRegisterAsync(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (request.HttpMethod != "POST")
        {
            await SendJsonResponseAsync(response, 405, new { success = false, message = "Method not allowed" });
            return;
        }

        if (!ValidateApiKey(request))
        {
            await SendJsonResponseAsync(response, 401, new { success = false, message = "Invalid API key" });
            return;
        }

        try
        {
            var body = await ReadRequestBodyAsync(request);
            var registration = JsonSerializer.Deserialize<AgentRegistration>(body, _jsonOptions);

            if (registration?.DeviceInfo == null)
            {
                await SendJsonResponseAsync(response, 400, new { success = false, message = "Invalid registration data" });
                return;
            }

            _logger.Information("Agent registered: {Device} ({IP}) — {Manufacturer} {Model}",
                registration.DeviceInfo.DeviceName,
                registration.DeviceInfo.IpAddress,
                registration.DeviceInfo.Manufacturer,
                registration.DeviceInfo.Model);

            // Raise alert for new agent registration
            await _alertService.RaiseAlertAsync(new SecurityAlert
            {
                Timestamp = DateTime.UtcNow,
                Severity = AlertSeverity.Info,
                Title = "Mobile Agent Registered",
                Description = $"New agent connected: {registration.DeviceInfo.Manufacturer} {registration.DeviceInfo.Model} " +
                             $"(Android {registration.DeviceInfo.AndroidVersion}) from {registration.DeviceInfo.IpAddress}",
                SourceIp = registration.DeviceInfo.IpAddress,
                SourceMac = registration.DeviceInfo.MacAddress
            });

            AgentRegistered?.Invoke(this, new AgentRegistrationEventArgs { Registration = registration });

            await SendJsonResponseAsync(response, 200, new
            {
                success = true,
                message = "Agent registered successfully",
                reportingIntervalSeconds = 15
            });
        }
        catch (JsonException ex)
        {
            _logger.Warning(ex, "Invalid JSON in agent registration");
            await SendJsonResponseAsync(response, 400, new { success = false, message = "Invalid JSON format" });
        }
    }

    /// <summary>
    /// Handles POST /api/agent/telemetry — incoming telemetry data
    /// </summary>
    private async Task HandleTelemetryAsync(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (request.HttpMethod != "POST")
        {
            await SendJsonResponseAsync(response, 405, new { success = false, message = "Method not allowed" });
            return;
        }

        if (!ValidateApiKey(request))
        {
            await SendJsonResponseAsync(response, 401, new { success = false, message = "Invalid API key" });
            return;
        }

        try
        {
            var body = await ReadRequestBodyAsync(request);
            var telemetry = JsonSerializer.Deserialize<AgentTelemetry>(body, _jsonOptions);

            if (telemetry?.DeviceInfo == null)
            {
                await SendJsonResponseAsync(response, 400, new { success = false, message = "Invalid telemetry data" });
                return;
            }

            _logger.Debug("Telemetry received from {Device} ({IP}): WiFi={SSID}, Battery={Battery}%",
                telemetry.DeviceInfo.Model,
                telemetry.DeviceInfo.IpAddress,
                telemetry.WifiInfo?.Ssid ?? "N/A",
                telemetry.BatteryInfo?.Level ?? -1);

            // Log domain tracking data
            if (!string.IsNullOrEmpty(telemetry.ActiveWebsite))
            {
                _logger.Information("Mobile [{Device}] ActiveWebsite: {Website}",
                    telemetry.DeviceInfo.Model, telemetry.ActiveWebsite);
            }

            if (telemetry.RecentDomains != null && telemetry.RecentDomains.Count > 0)
            {
                _logger.Information("Mobile [{Device}] RecentDomains ({Count}): {Domains}",
                    telemetry.DeviceInfo.Model,
                    telemetry.RecentDomains.Count,
                    string.Join(", ", telemetry.RecentDomains.Select(d => $"{d.AppLabel}:{d.Domain}")));
            }

            // Process the telemetry — store in database as a device
            await ProcessTelemetryAsync(telemetry);

            // Update latest telemetry record
            _latestTelemetry[telemetry.DeviceInfo.IpAddress] = telemetry;

            // Raise event for UI updates
            TelemetryReceived?.Invoke(this, new AgentTelemetryReceivedEventArgs { Telemetry = telemetry });

            await SendJsonResponseAsync(response, 200, new
            {
                success = true,
                message = "Telemetry received",
                reportingIntervalSeconds = 3
            });
        }
        catch (JsonException ex)
        {
            _logger.Warning(ex, "Invalid JSON in agent telemetry");
            await SendJsonResponseAsync(response, 400, new { success = false, message = "Invalid JSON format" });
        }
    }

    /// <summary>
    /// Processes incoming telemetry and integrates it with NetSentinel's existing data
    /// </summary>
    private async Task ProcessTelemetryAsync(AgentTelemetry telemetry)
    {
        try
        {
            // Normalize and resolve MAC address
            var macAddress = telemetry.DeviceInfo.MacAddress?.Trim().ToUpperInvariant() ?? string.Empty;
            if (macAddress == "02:00:00:00:00:00" || string.IsNullOrEmpty(macAddress))
            {
                // 1. Try to find a device in the database with the same IP address and a valid MAC address
                var existingDevice = await _database.GetDeviceByIpAsync(telemetry.DeviceInfo.IpAddress);
                if (existingDevice != null && !string.IsNullOrEmpty(existingDevice.MacAddress) && existingDevice.MacAddress != "02:00:00:00:00:00")
                {
                    macAddress = existingDevice.MacAddress.ToUpperInvariant();
                }
                else
                {
                    // 2. Try to get it from ARP table
                    var resolvedMac = GetMacAddressFromArp(telemetry.DeviceInfo.IpAddress);
                    if (!string.IsNullOrEmpty(resolvedMac))
                    {
                        macAddress = resolvedMac.ToUpperInvariant();
                    }
                }
            }

            // Add/update the device in the database
            var device = new NetworkDevice
            {
                IpAddress = telemetry.DeviceInfo.IpAddress,
                MacAddress = macAddress,
                Vendor = $"{telemetry.DeviceInfo.Manufacturer} {telemetry.DeviceInfo.Model}",
                Hostname = telemetry.DeviceInfo.DeviceName,
                FirstSeen = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow,
                IsOnline = true,
                IsGateway = false,
                DeviceType = DeviceType.Mobile
            };

            await _database.UpsertDeviceAsync(device);

            // Update active mobile domains cache
            var deviceDomains = _activeMobileDomains.GetOrAdd(telemetry.DeviceInfo.IpAddress, _ => new());
            if (telemetry.RecentDomains != null)
            {
                foreach (var visit in telemetry.RecentDomains)
                {
                    var time = DateTimeOffset.FromUnixTimeMilliseconds(visit.Timestamp).UtcDateTime;
                    
                    bool isBg = visit.IsBackground;
                    if (deviceDomains.TryGetValue(visit.Domain, out var existing))
                    {
                        // If the cached visit was active (not background), keep it active
                        if (!visit.IsBackground || !existing.IsBackground)
                        {
                            isBg = false;
                        }
                    }

                    deviceDomains[visit.Domain] = new CachedDomainVisit
                    {
                        Domain = visit.Domain,
                        AppLabel = visit.AppLabel,
                        LastSeen = time,
                        IsBackground = isBg
                    };
                }
            }

            // Clean up expired domains (older than 60 seconds)
            var cutoff = DateTime.UtcNow.AddSeconds(-60);
            var expiredKeys = deviceDomains.Where(kvp => kvp.Value.LastSeen < cutoff).Select(kvp => kvp.Key).ToList();
            foreach (var key in expiredKeys)
            {
                deviceDomains.TryRemove(key, out _);
            }

            // Note: Cumulative data usage alerts removed — Android TrafficStats reports all-time
            // counters (since boot), not session-based deltas, causing persistent false positives.
            // Real data exfiltration is detected by the local packet analysis in SecurityEngine.cs.

            // Malicious Application Scanner (HIDS)
            if (telemetry.RunningApps != null && telemetry.RunningApps.Count > 0)
            {
                _logger.Debug("Mobile agent {Device} running {Count} apps: {Apps}",
                    telemetry.DeviceInfo.Model,
                    telemetry.RunningApps.Count,
                    string.Join(", ", telemetry.RunningApps.Take(5).Select(a => a.AppName)));

                var blacklistedKeywords = new[] { "termux", "nethunter", "fing", "wireshark", "zanti", "dsploit", "droidsheep", "faceniff", "netcut", "cspoof" };
                foreach (var app in telemetry.RunningApps)
                {
                    var pkgLower = app.PackageName.ToLowerInvariant();
                    var nameLower = app.AppName.ToLowerInvariant();

                    if (blacklistedKeywords.Any(k => pkgLower.Contains(k) || nameLower.Contains(k)))
                    {
                        await _alertService.RaiseAlertAsync(new SecurityAlert
                        {
                            Timestamp = DateTime.UtcNow,
                            Severity = AlertSeverity.Critical,
                            Title = "Malicious Application Alert",
                            Description = $"Mobile device {telemetry.DeviceInfo.Model} is running a suspicious/malicious security tool: {app.AppName} ({app.PackageName}).",
                            SourceIp = telemetry.DeviceInfo.IpAddress,
                            SourceMac = telemetry.DeviceInfo.MacAddress
                        });
                    }
                }
            }

            // Crypto-jacking / Overheat Check
            if (telemetry.BatteryInfo != null && telemetry.BatteryInfo.Temperature > 45.0f)
            {
                await _alertService.RaiseAlertAsync(new SecurityAlert
                {
                    Timestamp = DateTime.UtcNow,
                    Severity = AlertSeverity.Warning,
                    Title = "Device Battery Temperature Spike",
                    Description = $"Mobile device {telemetry.DeviceInfo.Model} battery temperature is critical: {telemetry.BatteryInfo.Temperature:F1}°C (normal: 20-38°C). Possible background crypto-jacking or hardware stress.",
                    SourceIp = telemetry.DeviceInfo.IpAddress,
                    SourceMac = telemetry.DeviceInfo.MacAddress
                });
            }

            // Mobile domain visit analysis — Rapid repeated login page visits (brute-force indicator)
            if (telemetry.RecentDomains != null && telemetry.RecentDomains.Count > 0)
            {
                // Group by domain and check for rapid repeated visits to login-related domains
                var loginDomains = new[] { "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com",
                    "gmail.com", "outlook.com", "live.com", "login.microsoftonline.com", "accounts.google.com",
                    "linkedin.com", "github.com", "paypal.com", "amazon.com" };

                var domainGroups = telemetry.RecentDomains
                    .GroupBy(d => d.Domain)
                    .Where(g => g.Count() >= 10) // 10+ visits to same domain in one telemetry cycle
                    .ToList();

                foreach (var group in domainGroups)
                {
                    var domain = group.Key;
                    var isLoginDomain = loginDomains.Any(ld => domain.Contains(ld));

                    if (isLoginDomain)
                    {
                        await _alertService.RaiseAlertAsync(new SecurityAlert
                        {
                            Timestamp = DateTime.UtcNow,
                            Severity = AlertSeverity.Critical,
                            Title = $"Mobile Brute Force Attack Suspected: {domain}",
                            Description = $"Mobile device {telemetry.DeviceInfo.Model} ({telemetry.DeviceInfo.IpAddress}) " +
                                         $"made {group.Count()} rapid DNS requests to '{domain}' in {_agentReportIntervalSec}s. " +
                                         $"This pattern is consistent with repeated login attempts (brute-force attack).",
                            SourceIp = telemetry.DeviceInfo.IpAddress,
                            SourceMac = telemetry.DeviceInfo.MacAddress
                        });
                    }
                    else if (group.Count() >= 20)
                    {
                        await _alertService.RaiseAlertAsync(new SecurityAlert
                        {
                            Timestamp = DateTime.UtcNow,
                            Severity = AlertSeverity.Warning,
                            Title = $"Excessive Domain Requests from Mobile: {domain}",
                            Description = $"Mobile device {telemetry.DeviceInfo.Model} ({telemetry.DeviceInfo.IpAddress}) " +
                                         $"made {group.Count()} DNS requests to '{domain}' in {_agentReportIntervalSec}s. " +
                                         $"Could indicate automated scanning or suspicious script activity.",
                            SourceIp = telemetry.DeviceInfo.IpAddress,
                            SourceMac = telemetry.DeviceInfo.MacAddress
                        });
                    }
                }
            }

            // Mobile failed login attempts / brute force evaluation
            if (telemetry.FailedLogins != null && telemetry.FailedLogins.Count > 0)
            {
                var settings = await _database.GetSettingsAsync();
                int thresholdCritical = settings.FailedLoginThresholdCritical;
                int thresholdWarning = settings.FailedLoginThresholdWarning;
                int thresholdInfo = settings.FailedLoginThresholdInfo;

                var nowTime = DateTime.UtcNow;
                foreach (var attempt in telemetry.FailedLogins)
                {
                    var target = attempt.Target;
                    // Fallback to UtcNow if invalid timestamp
                    var attemptTime = attempt.Timestamp > 0 
                        ? DateTimeOffset.FromUnixTimeMilliseconds(attempt.Timestamp).UtcDateTime 
                        : nowTime;

                    var trackerKey = (telemetry.DeviceInfo.IpAddress, target);
                    var tracker = _failedLoginTrackers.GetOrAdd(trackerKey, _ => new FailedLoginTracker());

                    lock (tracker)
                    {
                        // Clean up timestamps older than 5 minutes from this attempt
                        var windowCutoff = attemptTime.AddMinutes(-5);
                        tracker.Timestamps.RemoveAll(t => t < windowCutoff);

                        // Add this attempt
                        tracker.Timestamps.Add(attemptTime);

                        int count = tracker.Timestamps.Count;

                        if (count >= thresholdCritical)
                        {
                            _ = _alertService.RaiseAlertAsync(new SecurityAlert
                            {
                                Timestamp = DateTime.UtcNow,
                                Severity = AlertSeverity.Critical,
                                Title = $"Mobile Password Brute Force Suspected: {target}",
                                Description = $"Mobile device {telemetry.DeviceInfo.Model} ({telemetry.DeviceInfo.IpAddress}) " +
                                             $"had {count} failed login attempts on '{target}' within the last 5 minutes. " +
                                             $"This indicates a potential brute-force attack.",
                                SourceIp = telemetry.DeviceInfo.IpAddress,
                                SourceMac = telemetry.DeviceInfo.MacAddress
                            });
                        }
                        else if (count >= thresholdWarning)
                        {
                            _ = _alertService.RaiseAlertAsync(new SecurityAlert
                            {
                                Timestamp = DateTime.UtcNow,
                                Severity = AlertSeverity.Warning,
                                Title = $"Multiple Mobile Login Failures: {target}",
                                Description = $"Mobile device {telemetry.DeviceInfo.Model} ({telemetry.DeviceInfo.IpAddress}) " +
                                             $"had {count} failed login attempts on '{target}' within the last 5 minutes. " +
                                             $"Please verify if this is authorized activity.",
                                SourceIp = telemetry.DeviceInfo.IpAddress,
                                SourceMac = telemetry.DeviceInfo.MacAddress
                            });
                        }
                        else if (count >= thresholdInfo)
                        {
                            _ = _alertService.RaiseAlertAsync(new SecurityAlert
                            {
                                Timestamp = DateTime.UtcNow,
                                Severity = AlertSeverity.Info,
                                Title = $"Mobile Login Failure Detected: {target}",
                                Description = $"Mobile device {telemetry.DeviceInfo.Model} ({telemetry.DeviceInfo.IpAddress}) " +
                                             $"failed to login on '{target}'.",
                                SourceIp = telemetry.DeviceInfo.IpAddress,
                                SourceMac = telemetry.DeviceInfo.MacAddress
                            });
                        }
                    }
                }
            }

            // Periodically clean up idle/expired failed login trackers
            var receiverNow = DateTime.UtcNow;
            var expiredTrackerKeys = _failedLoginTrackers
                .Where(kvp =>
                {
                    lock (kvp.Value)
                    {
                        return kvp.Value.Timestamps.Count == 0 || 
                               (receiverNow - kvp.Value.Timestamps.Last()).TotalMinutes > 5;
                    }
                })
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expiredTrackerKeys)
            {
                _failedLoginTrackers.TryRemove(key, out _);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to process agent telemetry");
        }
    }

    /// <summary>
    /// Reads the request body as a string
    /// </summary>
    private static async Task<string> ReadRequestBodyAsync(HttpListenerRequest request)
    {
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        return await reader.ReadToEndAsync();
    }

    /// <summary>
    /// Sends a JSON response
    /// </summary>
    private static async Task SendJsonResponseAsync(HttpListenerResponse response, int statusCode, object data)
    {
        response.StatusCode = statusCode;
        response.ContentType = "application/json; charset=utf-8";

        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        var buffer = Encoding.UTF8.GetBytes(json);

        response.ContentLength64 = buffer.Length;
        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        response.Close();
    }

    private async Task StartUdpDiscoveryAsync(CancellationToken token)
    {
        const int udpPort = 5096;
        try
        {
            _udpClient = new UdpClient();
            _udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, udpPort));
            
            _logger.Information("Agent discovery service started on UDP port {Port}", udpPort);

            while (!token.IsCancellationRequested)
            {
                var result = await _udpClient.ReceiveAsync(token);
                string request = Encoding.UTF8.GetString(result.Buffer);
                
                if (request == "NETSENTINEL_DISCOVER")
                {
                    var responseObj = new
                    {
                        Ip = GetLocalIPAddress(),
                        Port = Port,
                        ApiKey = ApiKey
                    };
                    
                    string json = JsonSerializer.Serialize(responseObj, _jsonOptions);
                    byte[] responseBytes = Encoding.UTF8.GetBytes(json);
                    
                    await _udpClient.SendAsync(responseBytes, responseBytes.Length, result.RemoteEndPoint);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error in UDP Discovery service");
        }
        finally
        {
            _udpClient?.Dispose();
            _udpClient = null;
        }
    }

    private string GetLocalIPAddress()
    {
        try
        {
            // Use socket routing to find the interface used to connect to the Internet/router.
            // This does not actually send any network traffic, but queries the OS routing table.
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
            {
                socket.Connect("8.8.8.8", 65530);
                if (socket.LocalEndPoint is IPEndPoint endPoint)
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

        var activeInterface = _networkManager.GetCurrentInterface();
        if (activeInterface != null && !string.IsNullOrEmpty(activeInterface.IpAddress))
        {
            return activeInterface.IpAddress;
        }

        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ipList = host.AddressList
                .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                .Select(ip => ip.ToString())
                .ToList();

            var preferredIp = ipList.FirstOrDefault(ip => !ip.StartsWith("192.168.56.") && !ip.StartsWith("192.168.99.") && !ip.StartsWith("169.254."));
            if (preferredIp != null)
                return preferredIp;

            if (ipList.Count > 0)
                return ipList[0];
        }
        catch
        {
            // ignore
        }
        return "127.0.0.1";
    }

    private string? GetMacAddressFromArp(string ipAddress)
    {
        try
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                return null;

            var networkInfo = _networkManager.GetCurrentInterface();
            if (networkInfo == null)
                return null;

            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "arp",
                    Arguments = "-a",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            var lines = output.Split('\n');
            bool inCorrectInterface = false;
            
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (line.StartsWith("Interface:", StringComparison.OrdinalIgnoreCase))
                {
                    inCorrectInterface = line.Contains(networkInfo.IpAddress);
                    continue;
                }

                if (!inCorrectInterface)
                    continue;

                if (line.Contains(ipAddress))
                {
                    var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 3)
                    {
                        var ip = parts[0].Trim();
                        var mac = parts[1].Trim();
                        var type = parts[2].Trim().ToLower();

                        if (ip != ipAddress)
                            continue;

                        if (mac.Contains("incomplete", StringComparison.OrdinalIgnoreCase) || 
                            mac.Length < 12 ||
                            mac.All(c => c == '-' || c == '0'))
                        {
                            continue;
                        }

                        if (type == "static")
                        {
                            continue;
                        }

                        if (Utils.OUILookup.IsValidMacAddress(mac))
                        {
                            return mac.Replace("-", ":").ToUpperInvariant();
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Failed to get MAC address from ARP for {IP} in AgentReceiver", ipAddress);
        }

        return null;
    }
}

/// <summary>
/// Event args for telemetry received events
/// </summary>
public class AgentTelemetryReceivedEventArgs : EventArgs
{
    public AgentTelemetry Telemetry { get; set; } = null!;
}

/// <summary>
/// Event args for agent registration events
/// </summary>
public class AgentRegistrationEventArgs : EventArgs
{
    public AgentRegistration Registration { get; set; } = null!;
}

/// <summary>
/// Domain visit entry cached in memory on the server
/// </summary>
public class CachedDomainVisit
{
    public string Domain { get; set; } = string.Empty;
    public string AppLabel { get; set; } = "Unknown";
    public DateTime LastSeen { get; set; }
    public bool IsBackground { get; set; }
}

/// <summary>
/// Tracker for failed login attempts to detect brute-force activity
/// </summary>
public class FailedLoginTracker
{
    public System.Collections.Generic.List<DateTime> Timestamps { get; set; } = new();
    public bool InfoAlertRaised { get; set; }
    public bool Warning5AlertRaised { get; set; }
    public bool Warning10AlertRaised { get; set; }
    public bool Critical50AlertRaised { get; set; }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using NetSentinel.Data;
using NetSentinel.Utils;
using Serilog;

namespace NetSentinel.Core;

/// <summary>
/// Scans and discovers devices on the local network
/// </summary>
public class DeviceScanner
{
    private readonly ILogger _logger;
    private readonly DatabaseService _database;
    private readonly NetworkManager _networkManager;
    private bool _isScanning;
    private string? _lastKnownGateway;

    public event EventHandler<DeviceDiscoveredEventArgs>? DeviceDiscovered;
    public event EventHandler? ScanCompleted;
    public event EventHandler<NetworkChangedEventArgs>? NetworkChanged;

    public DeviceScanner(ILogger logger, DatabaseService database, NetworkManager networkManager)
    {
        _logger = logger;
        _database = database;
        _networkManager = networkManager;
    }

    /// <summary>
    /// Performs a full network scan to discover devices
    /// </summary>
    public async Task ScanNetworkAsync(CancellationToken cancellationToken = default)
    {
        if (_isScanning)
        {
            _logger.Warning("Scan already in progress");
            return;
        }

        _isScanning = true;
        var scanSessionTimestamp = DateTime.UtcNow;
        _logger.Information("Starting network device scan (Session: {SessionTime})", scanSessionTimestamp);

        try
        {
            var networkInfo = _networkManager.GetCurrentInterface();
            if (networkInfo == null)
            {
                _logger.Warning("No active network interface found");
                return;
            }

            // Detect network change before scanning
            await DetectAndHandleNetworkChangeAsync(networkInfo.Gateway);

            var ipAddress = IPAddress.Parse(networkInfo.IpAddress);
            var subnetMask = IPAddress.Parse(networkInfo.SubnetMask);
            var gateway = IPAddress.Parse(networkInfo.Gateway);

            var ipRange = GetSubnetRange(ipAddress, subnetMask);
            _logger.Information("Scanning {Count} IP addresses in subnet", ipRange.Count);

            var discoveredDevices = new HashSet<string>();

            // Scan in parallel with limited concurrency
            var semaphore = new SemaphoreSlim(50);
            var tasks = ipRange.Select(async ip =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    var discovered = await ScanHostAsync(ip, gateway, scanSessionTimestamp, cancellationToken);
                    if (discovered)
                    {
                        lock (discoveredDevices)
                        {
                            discoveredDevices.Add(ip);
                        }
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);

            // Mark devices not found in this scan as offline
            await MarkAbsentDevicesOffline(discoveredDevices, scanSessionTimestamp);

            _logger.Information("Network scan completed. Found {Count} active devices", discoveredDevices.Count);
            ScanCompleted?.Invoke(this, EventArgs.Empty);
        }
        catch (OperationCanceledException)
        {
            _logger.Information("Network scan cancelled");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during network scan");
        }
        finally
        {
            _isScanning = false;
        }
    }

    /// <summary>
    /// Scans a single host
    /// </summary>
    /// <returns>True if device was successfully discovered and is active</returns>
    private async Task<bool> ScanHostAsync(string ipAddress, IPAddress gateway, DateTime scanSessionTimestamp, CancellationToken cancellationToken)
    {
        try
        {
            // Try to ping the host - this ensures we only count actively responding devices
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ipAddress, 1000);

            // Only count device if ping is successful (not cached ARP entries)
            if (reply.Status != IPStatus.Success)
                return false;

            // Small delay to allow ARP table to update after successful ping
            await Task.Delay(50, cancellationToken);

            // Get MAC address from ARP table (now refreshed by the ping)
            var macAddress = GetMacAddressFromArp(ipAddress);
            if (string.IsNullOrEmpty(macAddress))
            {
                _logger.Debug("Ping succeeded but no MAC address found for {IP}", ipAddress);
                return false;
            }

            // Try to resolve hostname
            string? hostname = null;
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                hostname = hostEntry.HostName;
            }
            catch
            {
                // Hostname resolution failed, not critical
            }

            var vendor = OUILookup.GetVendor(macAddress);
            var isGateway = ipAddress == gateway.ToString();
            var deviceType = Utils.DeviceTypeDetector.DetectDeviceType(vendor, hostname, macAddress);

            var device = new NetworkDevice
            {
                IpAddress = ipAddress,
                MacAddress = macAddress,
                Vendor = vendor,
                Hostname = hostname,
                FirstSeen = DateTime.UtcNow,
                LastSeen = scanSessionTimestamp,
                IsOnline = true,
                IsGateway = isGateway,
                DeviceType = deviceType
            };

            await _database.UpsertDeviceAsync(device);

            DeviceDiscovered?.Invoke(this, new DeviceDiscoveredEventArgs { Device = device });

            _logger.Debug("Discovered active device: {IP} ({MAC}) - {Vendor}", ipAddress, macAddress, vendor);
            return true;
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Failed to scan host {IP}", ipAddress);
            return false;
        }
    }

    /// <summary>
    /// Detects if the network has changed by monitoring gateway IP
    /// </summary>
    private async Task DetectAndHandleNetworkChangeAsync(string currentGateway)
    {
        // First scan - initialize gateway tracking
        if (_lastKnownGateway == null)
        {
            _lastKnownGateway = currentGateway;
            _logger.Information("Network initialized with gateway: {Gateway}", currentGateway);
            return;
        }

        // Check if gateway has changed
        if (_lastKnownGateway != currentGateway)
        {
            _logger.Warning("Network change detected! Gateway changed from {OldGateway} to {NewGateway}",
                _lastKnownGateway, currentGateway);

            // Mark all current devices as offline (they're from the old network)
            await ClearDevicesFromOldNetworkAsync();

            // Update tracked gateway
            var oldGateway = _lastKnownGateway;
            _lastKnownGateway = currentGateway;

            // Notify subscribers of network change
            NetworkChanged?.Invoke(this, new NetworkChangedEventArgs
            {
                OldGateway = oldGateway,
                NewGateway = currentGateway
            });

            _logger.Information("Network change handled. Old devices cleared, ready for fresh scan.");
        }
    }

    /// <summary>
    /// Clears all devices from the previous network when network changes
    /// </summary>
    private async Task ClearDevicesFromOldNetworkAsync()
    {
        try
        {
            var allDevices = await _database.GetAllDevicesAsync();
            _logger.Information("Clearing {Count} devices from old network", allDevices.Count);

            // Mark all devices as offline since they're from a different network
            foreach (var device in allDevices)
            {
                device.IsOnline = false;
                device.LastSeen = DateTime.UtcNow;
                await _database.UpsertDeviceAsync(device);
            }

            _logger.Information("All devices from old network marked offline");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to clear devices from old network");
        }
    }

    /// <summary>
    /// Marks devices not found in current scan as offline
    /// </summary>
    private async Task MarkAbsentDevicesOffline(HashSet<string> discoveredIps, DateTime scanSessionTimestamp)
    {
        try
        {
            var allDevices = await _database.GetAllDevicesAsync();
            foreach (var device in allDevices)
            {
                if (!discoveredIps.Contains(device.IpAddress) && device.IsOnline)
                {
                    device.IsOnline = false;
                    device.LastSeen = scanSessionTimestamp;
                    await _database.UpsertDeviceAsync(device);
                    _logger.Debug("Marked device offline: {IP} - not detected in current scan", device.IpAddress);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to mark absent devices offline");
        }
    }

    /// <summary>
    /// Gets MAC address from ARP table with improved validation
    /// Filters by active interface, ignores incomplete entries, and validates freshness
    /// </summary>
    private string? GetMacAddressFromArp(string ipAddress)
    {
        try
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return null;

            var networkInfo = _networkManager.GetCurrentInterface();
            if (networkInfo == null)
                return null;

            // Get ARP table for all interfaces
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
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

            // Parse ARP output - look for our interface section
            var lines = output.Split('\n');
            bool inCorrectInterface = false;
            
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                
                // Check if we're in the correct interface section
                if (line.StartsWith("Interface:", StringComparison.OrdinalIgnoreCase))
                {
                    // Check if this is our active interface by IP
                    inCorrectInterface = line.Contains(networkInfo.IpAddress);
                    continue;
                }

                // Only process entries from our active interface
                if (!inCorrectInterface)
                    continue;

                // Look for the target IP in ARP entries
                if (line.Contains(ipAddress))
                {
                    // Split by whitespace: IP Address, Physical Address, Type
                    var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    
                    // ARP format: <IP> <MAC> <Type>
                    // Example: 192.168.1.1 00-11-22-33-44-55 dynamic
                    if (parts.Length >= 3)
                    {
                        var ip = parts[0].Trim();
                        var mac = parts[1].Trim();
                        var type = parts[2].Trim().ToLower();

                        // Verify this is our target IP
                        if (ip != ipAddress)
                            continue;

                        // Ignore incomplete entries (no valid MAC)
                        if (mac.Contains("incomplete", StringComparison.OrdinalIgnoreCase) || 
                            mac.Length < 12 ||
                            mac.All(c => c == '-' || c == '0'))
                        {
                            _logger.Debug("Ignoring incomplete ARP entry for {IP}", ipAddress);
                            continue;
                        }

                        // Ignore static entries older than 5 minutes (prefer dynamic/fresh entries)
                        // Dynamic entries are typically fresher
                        if (type == "static")
                        {
                            _logger.Debug("Ignoring static ARP entry for {IP}, preferring dynamic", ipAddress);
                            continue;
                        }

                        // Validate MAC address format
                        if (OUILookup.IsValidMacAddress(mac))
                        {
                            _logger.Debug("Found valid MAC {MAC} for {IP} (type: {Type})", mac, ipAddress, type);
                            return mac.Replace("-", ":");
                        }
                    }
                }
            }

            _logger.Debug("No valid ARP entry found for {IP} on interface {Interface}", 
                ipAddress, networkInfo.IpAddress);
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Failed to get MAC address from ARP for {IP}", ipAddress);
        }

        return null;
    }

    /// <summary>
    /// Generates list of IP addresses in the subnet
    /// </summary>
    /// <summary>
    /// Dynamically calculates all valid IP addresses within a subnet based on IP and subnet mask
    /// </summary>
    /// <param name="ipAddress">The IP address within the subnet</param>
    /// <param name="subnetMask">The subnet mask (e.g., 255.255.255.0)</param>
    /// <returns>List of all valid host IP addresses in the subnet</returns>
    private List<string> GetSubnetRange(IPAddress ipAddress, IPAddress subnetMask)
    {
        var ipBytes = ipAddress.GetAddressBytes();
        var maskBytes = subnetMask.GetAddressBytes();

        // Calculate network address (IP AND subnet mask)
        var networkBytes = new byte[4];
        // Calculate broadcast address (IP OR inverted subnet mask)
        var broadcastBytes = new byte[4];

        for (int i = 0; i < 4; i++)
        {
            networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
            broadcastBytes[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
        }

        // Convert to uint32 for easier iteration
        var networkAddress = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0);
        var broadcastAddress = BitConverter.ToUInt32(broadcastBytes.Reverse().ToArray(), 0);

        // Generate all valid host IPs (exclude network and broadcast addresses)
        var ipList = new List<string>();
        for (uint i = networkAddress + 1; i < broadcastAddress; i++)
        {
            var bytes = BitConverter.GetBytes(i).Reverse().ToArray();
            ipList.Add(new IPAddress(bytes).ToString());
        }

        return ipList;
    }

    /// <summary>
    /// Gets all known devices from database, filtered by current active subnet
    /// </summary>
    public async Task<List<NetworkDevice>> GetKnownDevicesAsync()
    {
        var allDevices = await _database.GetAllDevicesAsync();
        
        // Filter devices to only show those from current active subnet
        var currentSubnetDevices = allDevices
            .Where(device => IsIpInCurrentSubnet(device.IpAddress))
            .ToList();
        
        _logger.Debug("Filtered {Total} devices to {Current} devices in current subnet", 
            allDevices.Count, currentSubnetDevices.Count);
        
        return currentSubnetDevices;
    }

    /// <summary>
    /// Checks if an IP address belongs to the current active subnet
    /// </summary>
    /// <param name="ipAddress">The IP address to validate</param>
    /// <returns>True if the IP is in the current subnet, false otherwise</returns>
    private bool IsIpInCurrentSubnet(string ipAddress)
    {
        try
        {
            var networkInfo = _networkManager.GetCurrentInterface();
            if (networkInfo == null)
            {
                _logger.Debug("No active network interface found for subnet validation");
                return false;
            }

            var deviceIp = IPAddress.Parse(ipAddress);
            var currentIp = IPAddress.Parse(networkInfo.IpAddress);
            var subnetMask = IPAddress.Parse(networkInfo.SubnetMask);

            var deviceIpBytes = deviceIp.GetAddressBytes();
            var currentIpBytes = currentIp.GetAddressBytes();
            var maskBytes = subnetMask.GetAddressBytes();

            // Calculate network address for both IPs
            for (int i = 0; i < 4; i++)
            {
                var deviceNetwork = (byte)(deviceIpBytes[i] & maskBytes[i]);
                var currentNetwork = (byte)(currentIpBytes[i] & maskBytes[i]);

                // If network portions don't match, device is in different subnet
                if (deviceNetwork != currentNetwork)
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Failed to validate if IP {IP} is in current subnet", ipAddress);
            return false;
        }
    }

    /// <summary>
    /// Checks if a device is still online
    /// </summary>
    public async Task<bool> IsDeviceOnlineAsync(string ipAddress)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ipAddress, 1000);
            return reply.Status == IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>
/// Device discovered event arguments
/// </summary>
public class DeviceDiscoveredEventArgs : EventArgs
{
    public NetworkDevice Device { get; set; } = null!;
}

/// <summary>
/// Network changed event arguments
/// </summary>
public class NetworkChangedEventArgs : EventArgs
{
    public string OldGateway { get; set; } = string.Empty;
    public string NewGateway { get; set; } = string.Empty;
}

using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using NetSentinel.Data;
using Serilog;

namespace NetSentinel.Core;

/// <summary>
/// Manages network interface detection and monitoring
/// </summary>
public class NetworkManager
{
    private readonly ILogger _logger;
    private NetworkInterfaceInfo? _currentInterface;

    public NetworkManager(ILogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Gets the current active network interface information
    /// </summary>
    public async Task<NetworkInterfaceInfo?> GetActiveNetworkInterfaceAsync()
    {
        try
        {
            await Task.Run(() =>
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.OperationalStatus == OperationalStatus.Up &&
                                ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 &&
                                !IsVirtualInterface(ni.Name, ni.Description))
                    .ToList();

                foreach (var ni in interfaces)
                {
                    var ipProps = ni.GetIPProperties();
                    var ipv4 = ipProps.UnicastAddresses
                        .FirstOrDefault(ip => ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                    if (ipv4 == null) continue;

                    var gateway = ipProps.GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                    if (gateway == null) continue;

                    var info = new NetworkInterfaceInfo
                    {
                        Name = ni.Name,
                        Description = ni.Description,
                        IpAddress = ipv4.Address.ToString(),
                        SubnetMask = ipv4.IPv4Mask.ToString(),
                        Gateway = gateway.Address.ToString(),
                        MacAddress = FormatMacAddress(ni.GetPhysicalAddress().GetAddressBytes()),
                        DnsServers = ipProps.DnsAddresses
                            .Where(dns => dns.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            .Select(dns => dns.ToString())
                            .ToArray(),
                        IsWireless = true
                    };

                    // Get SSID for wireless interface
                    info.Ssid = GetWirelessSsid(ni);

                    _currentInterface = info;
                    return;
                }
            });

            if (_currentInterface != null)
            {
                _logger.Information("Active network interface detected: {Name} ({IP})", 
                    _currentInterface.Name, _currentInterface.IpAddress);
            }

            return _currentInterface;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get active network interface");
            return null;
        }
    }

    /// <summary>
    /// Gets the current network interface (cached)
    /// </summary>
    public NetworkInterfaceInfo? GetCurrentInterface() => _currentInterface;

    /// <summary>
    /// Resolves hostname for an IP address
    /// </summary>
    public async Task<string?> ResolveHostnameAsync(string ipAddress)
    {
        try
        {
            var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
            return hostEntry.HostName;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Formats MAC address bytes to standard format
    /// </summary>
    private static string FormatMacAddress(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0)
            return string.Empty;

        return string.Join(":", bytes.Select(b => b.ToString("X2")));
    }

    /// <summary>
    /// Checks if a network interface is virtual
    /// </summary>
    private static bool IsVirtualInterface(string name, string description)
    {
        var virtualKeywords = new[] { "vmware", "virtualbox", "hyper-v", "docker", "wsl", "virtual" };
        var combinedText = $"{name} {description}".ToLower();
        
        return virtualKeywords.Any(keyword => combinedText.Contains(keyword));
    }

    /// <summary>
    /// Gets SSID for wireless interface using Windows WLAN API
    /// </summary>
    private string? GetWirelessSsid(NetworkInterface ni)
    {
        try
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return null;

            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show interfaces",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            var lines = output.Split('\n');
            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                // Look for SSID but exclude BSSID line
                if (trimmedLine.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) &&
                    !trimmedLine.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                {
                    var colonIndex = trimmedLine.IndexOf(':');
                    if (colonIndex > 0 && colonIndex < trimmedLine.Length - 1)
                    {
                        var ssid = trimmedLine.Substring(colonIndex + 1).Trim();
                        if (!string.IsNullOrWhiteSpace(ssid))
                        {
                            _logger.Information("SSID detected: {SSID}", ssid);
                            return ssid;
                        }
                    }
                }
            }
            
            _logger.Warning("No SSID found in netsh output");
        }
        catch (Exception ex)
        {
            _logger.Warning(ex, "Failed to retrieve SSID");
        }

        return null;
    }

    /// <summary>
    /// Gets the SSID of the currently connected WiFi network
    /// </summary>
    /// <returns>SSID of active WiFi connection, or "Not Connected" if not connected</returns>
    public string GetConnectedSsid()
    {
        try
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _logger.Debug("GetConnectedSsid is only supported on Windows");
                return "Not Connected";
            }

            // Execute netsh command to get WiFi interface information
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show interfaces",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            // Validate output
            if (string.IsNullOrWhiteSpace(output))
            {
                _logger.Debug("Empty output from netsh command");
                return "Not Connected";
            }

            // Parse output to extract State and SSID
            var lines = output.Split('\n');
            string? ssid = null;
            bool isConnected = false;

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var trimmedLine = line.Trim();

                // Check connection state
                if (trimmedLine.StartsWith("State", StringComparison.OrdinalIgnoreCase))
                {
                    var colonIndex = trimmedLine.IndexOf(':');
                    if (colonIndex > 0 && colonIndex < trimmedLine.Length - 1)
                    {
                        var state = trimmedLine.Substring(colonIndex + 1).Trim();
                        isConnected = state.Equals("connected", StringComparison.OrdinalIgnoreCase);
                    }
                }

                // Extract SSID - must be exact "SSID" line, not "BSSID" or "SSID 1", "SSID 2", etc.
                if (trimmedLine.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) &&
                    !trimmedLine.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                {
                    // Check if it's a numbered SSID line (e.g., "SSID 1") - ignore those
                    var colonIndex = trimmedLine.IndexOf(':');
                    if (colonIndex > 0)
                    {
                        var beforeColon = trimmedLine.Substring(0, colonIndex).Trim();
                        
                        // Only accept lines that are exactly "SSID" (not "SSID 1", "SSID 2", etc.)
                        if (beforeColon.Equals("SSID", StringComparison.OrdinalIgnoreCase))
                        {
                            if (colonIndex < trimmedLine.Length - 1)
                            {
                                var extractedSsid = trimmedLine.Substring(colonIndex + 1).Trim();
                                
                                // Additional whitespace cleanup
                                if (!string.IsNullOrWhiteSpace(extractedSsid))
                                {
                                    ssid = extractedSsid;
                                }
                            }
                        }
                    }
                }
            }

            // Return SSID only if State is connected and SSID is valid
            if (isConnected && !string.IsNullOrWhiteSpace(ssid))
            {
                _logger.Debug("Retrieved connected SSID: {SSID}", ssid);
                return ssid;
            }

            _logger.Debug("Not connected to WiFi or SSID not found (State: {IsConnected}, SSID: {SSID})", 
                isConnected, ssid ?? "null");
            return "Not Connected";
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error retrieving connected SSID");
            return "Not Connected";
        }
    }

    /// <summary>
    /// Checks if network configuration has changed
    /// </summary>
    public async Task<bool> HasNetworkChangedAsync()
    {
        var current = _currentInterface;
        var updated = await GetActiveNetworkInterfaceAsync();

        if (current == null || updated == null)
            return true;

        return current.IpAddress != updated.IpAddress ||
               current.Gateway != updated.Gateway ||
               current.MacAddress != updated.MacAddress;
    }
}

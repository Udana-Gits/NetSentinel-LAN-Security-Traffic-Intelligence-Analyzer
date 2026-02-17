using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using NetSentinel.Data;
using Serilog;

namespace NetSentinel.Core;

/// <summary>
/// Monitors active network connections
/// </summary>
public class ConnectionMonitor
{
    private readonly ILogger _logger;
    private bool _isRunning;
    private CancellationTokenSource? _cts;

    public List<NetworkConnection> ActiveConnections { get; private set; }
    public event EventHandler<ConnectionsUpdatedEventArgs>? ConnectionsUpdated;

    public ConnectionMonitor(ILogger logger)
    {
        _logger = logger;
        ActiveConnections = new List<NetworkConnection>();
    }

    /// <summary>
    /// Starts monitoring connections
    /// </summary>
    public async Task StartAsync()
    {
        if (_isRunning)
            return;

        _isRunning = true;
        _cts = new CancellationTokenSource();

        _ = Task.Run(() => MonitorLoopAsync(_cts.Token), _cts.Token);
        
        _logger.Information("Connection monitoring started");
    }

    /// <summary>
    /// Stops monitoring connections
    /// </summary>
    public void Stop()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _logger.Information("Connection monitoring stopped");
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
                await Task.Delay(2000, cancellationToken);

                var connections = await GetActiveConnectionsAsync();
                ActiveConnections = connections;

                ConnectionsUpdated?.Invoke(this, new ConnectionsUpdatedEventArgs
                {
                    Connections = connections,
                    TotalCount = connections.Count
                });
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in connection monitoring loop");
                await Task.Delay(5000, cancellationToken);
            }
        }
    }

    /// <summary>
    /// Gets all active TCP connections and UDP listeners
    /// </summary>
    public async Task<List<NetworkConnection>> GetActiveConnectionsAsync()
    {
        var connections = new List<NetworkConnection>();

        await Task.Run(() =>
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();

                // Get TCP connections
                var tcpConnections = properties.GetActiveTcpConnections();
                foreach (var conn in tcpConnections)
                {
                    try
                    {
                        var (processName, pid) = GetProcessInfoForConnection(
                            conn.LocalEndPoint.Address.ToString(),
                            conn.LocalEndPoint.Port
                        );

                        connections.Add(new NetworkConnection
                        {
                            LocalAddress = conn.LocalEndPoint.Address.ToString(),
                            LocalPort = conn.LocalEndPoint.Port,
                            RemoteAddress = conn.RemoteEndPoint.Address.ToString(),
                            RemotePort = conn.RemoteEndPoint.Port,
                            Protocol = "TCP",
                            State = conn.State.ToString(),
                            ProcessName = processName,
                            ProcessId = pid
                        });
                    }
                    catch
                    {
                        // Skip if we can't get process info
                    }
                }

                // Get TCP listeners
                var tcpListeners = properties.GetActiveTcpListeners();
                foreach (var listener in tcpListeners)
                {
                    try
                    {
                        var (processName, pid) = GetProcessInfoForConnection(
                            listener.Address.ToString(),
                            listener.Port
                        );

                        connections.Add(new NetworkConnection
                        {
                            LocalAddress = listener.Address.ToString(),
                            LocalPort = listener.Port,
                            RemoteAddress = "0.0.0.0",
                            RemotePort = 0,
                            Protocol = "TCP",
                            State = "LISTENING",
                            ProcessName = processName,
                            ProcessId = pid
                        });
                    }
                    catch
                    {
                        // Skip if we can't get process info
                    }
                }

                // Get UDP listeners
                var udpListeners = properties.GetActiveUdpListeners();
                foreach (var listener in udpListeners)
                {
                    try
                    {
                        var (processName, pid) = GetProcessInfoForConnection(
                            listener.Address.ToString(),
                            listener.Port
                        );

                        connections.Add(new NetworkConnection
                        {
                            LocalAddress = listener.Address.ToString(),
                            LocalPort = listener.Port,
                            RemoteAddress = "*",
                            RemotePort = 0,
                            Protocol = "UDP",
                            State = "LISTENING",
                            ProcessName = processName,
                            ProcessId = pid
                        });
                    }
                    catch
                    {
                        // Skip if we can't get process info
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to get active connections");
            }
        });

        return connections;
    }

    /// <summary>
    /// Gets process name and PID for a connection
    /// </summary>
    private (string ProcessName, int Pid) GetProcessInfoForConnection(string localAddress, int localPort)
    {
        try
        {
            // Use netstat to find the process
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano",
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
                if (line.Contains(localAddress) && line.Contains($":{localPort}"))
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 5 && int.TryParse(parts[^1], out var pid))
                    {
                        try
                        {
                            var proc = Process.GetProcessById(pid);
                            return (proc.ProcessName, pid);
                        }
                        catch
                        {
                            return ("Unknown", pid);
                        }
                    }
                }
            }
        }
        catch
        {
            // Failed to get process info
        }

        return ("Unknown", 0);
    }

    /// <summary>
    /// Gets connection statistics
    /// </summary>
    public ConnectionStats GetStatistics()
    {
        var connections = ActiveConnections;
        return new ConnectionStats
        {
            TotalConnections = connections.Count,
            TcpConnections = connections.Count(c => c.Protocol == "TCP" && c.State != "LISTENING"),
            TcpListeners = connections.Count(c => c.Protocol == "TCP" && c.State == "LISTENING"),
            UdpListeners = connections.Count(c => c.Protocol == "UDP"),
            EstablishedConnections = connections.Count(c => c.State == "ESTABLISHED")
        };
    }
}

/// <summary>
/// Connections updated event arguments
/// </summary>
public class ConnectionsUpdatedEventArgs : EventArgs
{
    public List<NetworkConnection> Connections { get; set; } = new();
    public int TotalCount { get; set; }
}

/// <summary>
/// Connection statistics
/// </summary>
public class ConnectionStats
{
    public int TotalConnections { get; set; }
    public int TcpConnections { get; set; }
    public int TcpListeners { get; set; }
    public int UdpListeners { get; set; }
    public int EstablishedConnections { get; set; }
}

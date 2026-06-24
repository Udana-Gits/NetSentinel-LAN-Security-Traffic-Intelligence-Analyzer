using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Messages;
using NetSentinel.Services;
using Serilog;

namespace NetSentinel.ViewModels;

/// <summary>
/// ViewModel for the devices view
/// </summary>
public partial class DevicesViewModel : ObservableObject
{
    private readonly ILogger _logger;
    private readonly DeviceScanner _deviceScanner;
    private readonly DatabaseService _database;
    private readonly AgentReceiver _agentReceiver;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private int _totalDevices;

    [ObservableProperty]
    private int _onlineDevices;

    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private string _statusMessage = "Ready";

    /// <summary>
    /// Current network devices - all devices on current network
    /// </summary>
    public ObservableCollection<NetworkDevice> CurrentDevices { get; set; }

    /// <summary>
    /// Online network devices - UI binds to this collection
    /// </summary>
    public ObservableCollection<NetworkDevice> OnlineDevicesList { get; } = new();

    /// <summary>
    /// Offline / previously connected network devices - UI binds to this collection
    /// </summary>
    public ObservableCollection<NetworkDevice> OfflineDevicesList { get; } = new();
    
    /// <summary>
    /// Historical devices from database - loaded on demand only
    /// </summary>
    private List<NetworkDevice>? HistoricalDevices { get; set; }

    public DevicesViewModel(ILogger logger, DeviceScanner deviceScanner, DatabaseService database, AgentReceiver agentReceiver)
    {
        _logger = logger;
        _deviceScanner = deviceScanner;
        _database = database;
        _agentReceiver = agentReceiver;

        CurrentDevices = new ObservableCollection<NetworkDevice>();
        HistoricalDevices = null; // Not loaded initially

        _deviceScanner.DeviceDiscovered += OnDeviceDiscovered;
        _deviceScanner.ScanCompleted += OnScanCompleted;
        _deviceScanner.NetworkChanged += OnNetworkChanged;
        
        _agentReceiver.TelemetryReceived += OnTelemetryReceived;

        // Register for global refresh messages
        WeakReferenceMessenger.Default.Register<RefreshDevicesMessage>(this, (r, m) => HandleRefreshMessage());

        // Load devices from database asynchronously on startup
        _ = InitializeDevicesAsync();
    }

    /// <summary>
    /// Handles refresh message from global refresh command
    /// </summary>
    private void HandleRefreshMessage()
    {
        _logger.Information("DevicesViewModel received refresh message");
        Application.Current?.Dispatcher.Invoke(async () =>
        {
            await RefreshDevices();
        });
    }

    /// <summary>
    /// Loads historical devices from database on demand
    /// </summary>
    private async Task LoadHistoricalDevicesAsync()
    {
        try
        {
            HistoricalDevices = await _database.GetAllDevicesAsync();
            _logger.Information("Loaded {Count} historical devices from database", HistoricalDevices.Count);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to load historical devices");
        }
    }

    [RelayCommand]
    private async Task RefreshDevices()
    {
        if (IsScanning)
            return;

        IsScanning = true;
        StatusMessage = "Scanning network and refreshing devices...";
        
        try
        {
            // Perform an actual network scan to update LastSeen times
            await _deviceScanner.ScanNetworkAsync();
            
            // Then reload all devices from database (including offline ones)
            var allDevices = await _deviceScanner.GetKnownDevicesAsync();
            
            Application.Current?.Dispatcher.Invoke(() =>
            {
                CurrentDevices.Clear();
                
                // Show all devices, ordered by online status first, then by IsGateway, then by LastSeen
                foreach (var device in allDevices.OrderByDescending(d => d.IsOnline)
                                                  .ThenByDescending(d => d.IsGateway)
                                                  .ThenByDescending(d => d.LastSeen))
                {
                    CurrentDevices.Add(device);
                }

                UpdateCounts();
                RefreshViewCollections();
                StatusMessage = "Ready";
            });
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to refresh devices");
            StatusMessage = "Refresh failed";
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private async Task ExportDevices()
    {
        try
        {
            // Load historical devices if not already loaded
            if (HistoricalDevices == null)
            {
                await LoadHistoricalDevicesAsync();
            }

            var csv = await _database.ExportDevicesToCsvAsync();
            var path = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"NetSentinel_Devices_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            );

            await System.IO.File.WriteAllTextAsync(path, csv);
            StatusMessage = $"Exported to {path}";
            
            MessageBox.Show($"Devices exported to:\n{path}", "Export Successful", 
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to export devices");
            MessageBox.Show("Failed to export devices", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    partial void OnFilterTextChanged(string value)
    {
        RefreshViewCollections();
    }

    private void RefreshViewCollections()
    {
        var filter = FilterText?.Trim();
        var allDevices = CurrentDevices.ToList();

        var onlineFiltered = allDevices
            .Where(d => d.IsOnline && MatchesFilter(d, filter))
            .OrderByDescending(d => d.IsGateway)
            .ThenByDescending(d => d.LastSeen)
            .ToList();

        var offlineFiltered = allDevices
            .Where(d => !d.IsOnline && MatchesFilter(d, filter))
            .OrderByDescending(d => d.LastSeen)
            .ToList();

        SyncCollection(OnlineDevicesList, onlineFiltered);
        SyncCollection(OfflineDevicesList, offlineFiltered);
    }

    private bool MatchesFilter(NetworkDevice device, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
            return true;

        return (device.IpAddress?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false) ||
               (device.MacAddress?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false) ||
               (device.Vendor?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false) ||
               (device.Hostname?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private void SyncCollection(ObservableCollection<NetworkDevice> target, List<NetworkDevice> source)
    {
        target.Clear();
        foreach (var item in source)
        {
            target.Add(item);
        }
    }

    /// <summary>
    /// Pre-loads devices from database on startup
    /// </summary>
    private async Task InitializeDevicesAsync()
    {
        try
        {
            var allDevices = await _deviceScanner.GetKnownDevicesAsync();
            Application.Current?.Dispatcher.Invoke(() =>
            {
                CurrentDevices.Clear();
                foreach (var device in allDevices)
                {
                    CurrentDevices.Add(device);
                }
                UpdateCounts();
                RefreshViewCollections();
            });
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to initialize devices from database on startup");
        }
    }

    /// <summary>
    /// Handles real-time telemetry updates from NetSentinel mobile agents
    /// </summary>
    private void OnTelemetryReceived(object? sender, AgentTelemetryReceivedEventArgs e)
    {
        if (e?.Telemetry?.DeviceInfo == null)
            return;

        var ip = e.Telemetry.DeviceInfo.IpAddress;
        var mac = e.Telemetry.DeviceInfo.MacAddress?.Trim().ToUpperInvariant();

        Task.Run(async () =>
        {
            try
            {
                // Fetch the fully resolved device record from DB
                var dbDevice = await _database.GetDeviceByIpAsync(ip);
                if (dbDevice == null && !string.IsNullOrEmpty(mac))
                {
                    dbDevice = await _database.GetDeviceByMacAsync(mac);
                }

                if (dbDevice != null)
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        var existing = CurrentDevices.FirstOrDefault(d => 
                            d.MacAddress.Equals(dbDevice.MacAddress, StringComparison.OrdinalIgnoreCase) ||
                            (!string.IsNullOrEmpty(d.IpAddress) && d.IpAddress.Equals(dbDevice.IpAddress, StringComparison.OrdinalIgnoreCase)));

                        if (existing != null)
                        {
                            existing.IpAddress = dbDevice.IpAddress;
                            existing.Hostname = dbDevice.Hostname;
                            existing.LastSeen = dbDevice.LastSeen;
                            existing.IsOnline = dbDevice.IsOnline;
                            existing.DeviceType = dbDevice.DeviceType;
                            existing.Vendor = dbDevice.Vendor;
                            existing.IsGateway = dbDevice.IsGateway;
                        }
                        else
                        {
                            CurrentDevices.Add(dbDevice);
                        }

                        UpdateCounts();
                        RefreshViewCollections();
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error handling telemetry update in DevicesViewModel");
            }
        });
    }

    private void OnDeviceDiscovered(object? sender, DeviceDiscoveredEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            var existing = CurrentDevices.FirstOrDefault(d => d.MacAddress.Equals(e.Device.MacAddress, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                // Update existing device in current network
                existing.IpAddress = e.Device.IpAddress;
                existing.Hostname = e.Device.Hostname;
                existing.LastSeen = e.Device.LastSeen;
                existing.IsOnline = e.Device.IsOnline;
                existing.DeviceType = e.Device.DeviceType;
                existing.Vendor = e.Device.Vendor;
                existing.IsGateway = e.Device.IsGateway;
            }
            else
            {
                // Add new device to current network
                CurrentDevices.Add(e.Device);
            }

            UpdateCounts();
            RefreshViewCollections();
        });
    }

    private void OnScanCompleted(object? sender, EventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            IsScanning = false;
            StatusMessage = $"Scan completed - {TotalDevices} devices found";
        });
    }

    private void OnNetworkChanged(object? sender, NetworkChangedEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            _logger.Information("Network changed in UI. Clearing current devices. Gateway: {OldGateway} -> {NewGateway}",
                e.OldGateway, e.NewGateway);

            // Clear only current network devices
            CurrentDevices.Clear();
            
            UpdateCounts();
            RefreshViewCollections();
            StatusMessage = $"Network changed to {e.NewGateway}. Ready to scan.";
        });
    }

    private void UpdateCounts()
    {
        TotalDevices = CurrentDevices.Count;
        OnlineDevices = CurrentDevices.Count(d => d.IsOnline);
    }
}

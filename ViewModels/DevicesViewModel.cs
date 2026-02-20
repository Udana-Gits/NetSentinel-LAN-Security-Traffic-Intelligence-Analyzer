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
    /// Current network devices - UI binds to this collection
    /// </summary>
    public ObservableCollection<NetworkDevice> CurrentDevices { get; set; }
    
    /// <summary>
    /// Historical devices from database - loaded on demand only
    /// </summary>
    private List<NetworkDevice>? HistoricalDevices { get; set; }

    public DevicesViewModel(ILogger logger, DeviceScanner deviceScanner, DatabaseService database)
    {
        _logger = logger;
        _deviceScanner = deviceScanner;
        _database = database;

        CurrentDevices = new ObservableCollection<NetworkDevice>();
        HistoricalDevices = null; // Not loaded initially

        _deviceScanner.DeviceDiscovered += OnDeviceDiscovered;
        _deviceScanner.ScanCompleted += OnScanCompleted;
        _deviceScanner.NetworkChanged += OnNetworkChanged;

        // Register for global refresh messages
        WeakReferenceMessenger.Default.Register<RefreshDevicesMessage>(this, (r, m) => HandleRefreshMessage());

        // Don't auto-load devices - wait for network scan
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
                
                // Show all devices, ordered by online status first, then by LastSeen
                foreach (var device in allDevices.OrderByDescending(d => d.IsOnline)
                                                  .ThenByDescending(d => d.LastSeen))
                {
                    CurrentDevices.Add(device);
                }

                UpdateCounts();
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
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        // Note: Filtering is now handled by the UI binding directly
        // CurrentDevices contains only devices from the current network
        // No additional filtering needed at ViewModel level for network separation
        
        // If text filtering is needed, it would filter CurrentDevices collection
        // For now, CurrentDevices shows all devices from current network without text filtering
    }

    private void OnDeviceDiscovered(object? sender, DeviceDiscoveredEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            var existing = CurrentDevices.FirstOrDefault(d => d.MacAddress == e.Device.MacAddress);
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
            StatusMessage = $"Network changed to {e.NewGateway}. Ready to scan.";
        });
    }

    private void UpdateCounts()
    {
        TotalDevices = CurrentDevices.Count;
        OnlineDevices = CurrentDevices.Count(d => d.IsOnline);
    }
}

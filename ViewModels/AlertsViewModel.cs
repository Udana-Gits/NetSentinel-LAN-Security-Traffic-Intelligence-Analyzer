using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using NetSentinel.Data;
using NetSentinel.Messages;
using NetSentinel.Services;
using Serilog;

namespace NetSentinel.ViewModels;

/// <summary>
/// ViewModel representing security alerts for a specific device
/// </summary>
public partial class DeviceAlertsGroup : ObservableObject
{
    [ObservableProperty]
    private string _deviceName = string.Empty;

    [ObservableProperty]
    private string _ipAddress = string.Empty;

    [ObservableProperty]
    private string _deviceType = "Other"; // "Laptop", "Mobile", "Other", "Network"

    [ObservableProperty]
    private int _alertCount;

    [ObservableProperty]
    private int _criticalCount;

    [ObservableProperty]
    private int _warningCount;

    [ObservableProperty]
    private int _infoCount;

    [ObservableProperty]
    private bool _isExpanded = true;

    public ObservableCollection<SecurityAlert> Alerts { get; set; } = new();
}

/// <summary>
/// ViewModel for the alerts view
/// </summary>
public partial class AlertsViewModel : ObservableObject
{
    private static readonly DateTime AppStartupTime = DateTime.UtcNow;

    private readonly ILogger _logger;
    private readonly AlertService _alertService;
    private readonly DatabaseService _database;
    private readonly AgentReceiver _agentReceiver;

    [ObservableProperty]
    private int _totalAlerts;

    [ObservableProperty]
    private int _criticalAlerts;

    [ObservableProperty]
    private int _warningAlerts;

    [ObservableProperty]
    private int _infoAlerts;

    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private string _selectedSeverity = "All";

    [ObservableProperty]
    private bool _showOnlyUnread;

    public ObservableCollection<SecurityAlert> Alerts { get; set; }
    public ObservableCollection<DeviceAlertsGroup> DeviceGroups { get; set; }
    private readonly ObservableCollection<SecurityAlert> _allAlerts;

    public string[] SeverityFilters { get; } = { "All", "Critical", "Warning", "Info" };

    public AlertsViewModel(ILogger logger, AlertService alertService, DatabaseService database, AgentReceiver agentReceiver)
    {
        _logger = logger;
        _alertService = alertService;
        _database = database;
        _agentReceiver = agentReceiver;

        Alerts = new ObservableCollection<SecurityAlert>();
        DeviceGroups = new ObservableCollection<DeviceAlertsGroup>();
        _allAlerts = new ObservableCollection<SecurityAlert>();

        _alertService.AlertRaised += OnAlertRaised;

        // Register for global refresh messages
        WeakReferenceMessenger.Default.Register<RefreshAlertsMessage>(this, (r, m) => HandleRefreshMessage());

        _ = LoadAlertsAsync();
    }

    /// <summary>
    /// Handles refresh message from global refresh command
    /// </summary>
    private void HandleRefreshMessage()
    {
        _logger.Information("AlertsViewModel received refresh message");
        Application.Current?.Dispatcher.InvokeAsync(async () =>
        {
            await Refresh();
        });
    }

    private async Task LoadAlertsAsync()
    {
        try
        {
            var alerts = await _alertService.GetRecentAlertsAsync(500);
            
            Application.Current?.Dispatcher.Invoke(() =>
            {
                _allAlerts.Clear();
                
                foreach (var alert in alerts.Where(a => a.Timestamp >= AppStartupTime).OrderByDescending(a => a.Timestamp))
                {
                    _allAlerts.Add(alert);
                }

                UpdateStatistics();
                ApplyFilters();
            });
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to load alerts");
        }
    }

    [RelayCommand]
    private async Task Refresh()
    {
        await LoadAlertsAsync();
    }

    [RelayCommand]
    private async Task MarkAllAsRead()
    {
        foreach (var alert in _allAlerts.Where(a => !a.IsRead))
        {
            await _alertService.MarkAsReadAsync(alert.Id);
            alert.IsRead = true;
        }

        ApplyFilters();
    }

    [RelayCommand]
    private async Task ExportAlerts()
    {
        try
        {
            var csv = await _database.ExportAlertsToCsvAsync();
            var path = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"NetSentinel_Alerts_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            );

            await System.IO.File.WriteAllTextAsync(path, csv);
            
            MessageBox.Show($"Alerts exported to:\n{path}", "Export Successful", 
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to export alerts");
            MessageBox.Show("Failed to export alerts", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task MarkAsRead(SecurityAlert alert)
    {
        if (alert.IsRead)
            return;

        await _alertService.MarkAsReadAsync(alert.Id);
        alert.IsRead = true;
        
        ApplyFilters();
    }

    partial void OnFilterTextChanged(string value)
    {
        ApplyFilters();
    }

    partial void OnSelectedSeverityChanged(string value)
    {
        ApplyFilters();
    }

    partial void OnShowOnlyUnreadChanged(bool value)
    {
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        Application.Current?.Dispatcher.Invoke(async () =>
        {
            var filtered = _allAlerts.AsEnumerable();

            // Severity filter
            if (SelectedSeverity != "All")
            {
                filtered = filtered.Where(a => a.Severity.ToString() == SelectedSeverity);
            }

            // Unread filter
            if (ShowOnlyUnread)
            {
                filtered = filtered.Where(a => !a.IsRead);
            }

            // Text filter
            if (!string.IsNullOrWhiteSpace(FilterText))
            {
                filtered = filtered.Where(a =>
                    a.Title.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                    a.Description.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                    (a.SourceIp?.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ?? false)
                );
            }

            var localIp = GetLocalIPAddress();

            var filteredList = filtered.ToList();

            Alerts.Clear();
            foreach (var alert in filteredList)
            {
                Alerts.Add(alert);
            }

            // Fetch devices to get vendors and types
            System.Collections.Generic.List<NetworkDevice> devices = new();
            try
            {
                devices = await _database.GetAllDevicesAsync();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to load devices for alerts grouping");
            }

            // Group by SourceIp
            var groupedAlerts = filteredList
                .GroupBy(a => a.SourceIp ?? string.Empty)
                .ToList();

            var activeIpGroups = new System.Collections.Generic.HashSet<string>();

            foreach (var group in groupedAlerts)
            {
                var sourceIp = group.Key;
                activeIpGroups.Add(sourceIp);

                var deviceGroup = DeviceGroups.FirstOrDefault(dg => dg.IpAddress == sourceIp);
                if (deviceGroup == null)
                {
                    deviceGroup = new DeviceAlertsGroup
                    {
                        IpAddress = sourceIp
                    };
                    DeviceGroups.Add(deviceGroup);
                }

                // Identify device properties
                if (string.IsNullOrEmpty(sourceIp))
                {
                    deviceGroup.DeviceName = "Network & System Alerts";
                    deviceGroup.DeviceType = "Network";
                }
                else if (sourceIp == "127.0.0.1" || sourceIp == localIp)
                {
                    deviceGroup.DeviceName = "Local Laptop (This PC)";
                    deviceGroup.DeviceType = "Laptop";
                }
                else
                {
                    var dev = devices.FirstOrDefault(d => d.IpAddress == sourceIp);
                    if (dev != null)
                    {
                        deviceGroup.DeviceName = !string.IsNullOrEmpty(dev.Vendor) ? dev.Vendor : (dev.Hostname ?? $"Device {sourceIp}");
                        deviceGroup.DeviceType = dev.DeviceType.ToString();
                    }
                    else
                    {
                        deviceGroup.DeviceName = $"Unknown Device ({sourceIp})";
                        deviceGroup.DeviceType = "Other";
                    }
                }

                // Sync alerts inside this group
                var sortedAlerts = group.OrderByDescending(a => a.Timestamp).ToList();
                deviceGroup.Alerts.Clear();
                foreach (var alert in sortedAlerts)
                {
                    deviceGroup.Alerts.Add(alert);
                }

                deviceGroup.AlertCount = sortedAlerts.Count;
                deviceGroup.CriticalCount = sortedAlerts.Count(a => a.Severity == AlertSeverity.Critical);
                deviceGroup.WarningCount = sortedAlerts.Count(a => a.Severity == AlertSeverity.Warning);
                deviceGroup.InfoCount = sortedAlerts.Count(a => a.Severity == AlertSeverity.Info);
                deviceGroup.IsExpanded = sortedAlerts.Count > 0;
            }

            // Remove groups that have no matching alerts under current filters
            var toRemove = DeviceGroups.Where(dg => !activeIpGroups.Contains(dg.IpAddress)).ToList();
            foreach (var dg in toRemove)
            {
                DeviceGroups.Remove(dg);
            }
        });
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

    private void OnAlertRaised(object? sender, AlertRaisedEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            var existing = _allAlerts.FirstOrDefault(a => a.Id == e.Alert.Id);
            if (existing != null)
            {
                _allAlerts.Remove(existing);
            }
            
            if (e.Alert.Timestamp >= AppStartupTime)
            {
                _allAlerts.Insert(0, e.Alert);
                UpdateStatistics();
                ApplyFilters();
            }
        });
    }

    private void UpdateStatistics()
    {
        TotalAlerts = _allAlerts.Count;
        CriticalAlerts = _allAlerts.Count(a => a.Severity == AlertSeverity.Critical);
        WarningAlerts = _allAlerts.Count(a => a.Severity == AlertSeverity.Warning);
        InfoAlerts = _allAlerts.Count(a => a.Severity == AlertSeverity.Info);
    }
}

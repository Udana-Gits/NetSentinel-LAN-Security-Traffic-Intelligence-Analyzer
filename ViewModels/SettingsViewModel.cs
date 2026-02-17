using System;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using NetSentinel.Core;
using NetSentinel.Data;
using Serilog;

namespace NetSentinel.ViewModels;

/// <summary>
/// ViewModel for the settings view
/// </summary>
public partial class SettingsViewModel : ObservableObject
{
    private readonly ILogger _logger;
    private readonly DatabaseService _database;
    private readonly DeviceScanner _deviceScanner;
    private AppSettings _settings;

    [ObservableProperty]
    private bool _autoScanDevices;

    [ObservableProperty]
    private int _scanIntervalMinutes;

    [ObservableProperty]
    private bool _enablePacketCapture;

    [ObservableProperty]
    private bool _showNotifications;

    [ObservableProperty]
    private bool _minimizeToTray;

    [ObservableProperty]
    private bool _autoStartWithWindows;

    [ObservableProperty]
    private int _trafficSpikeThreshold;

    [ObservableProperty]
    private int _connectionCountThreshold;

    [ObservableProperty]
    private string _statusMessage = "Ready";

    public SettingsViewModel(ILogger logger, DatabaseService database, DeviceScanner deviceScanner)
    {
        _logger = logger;
        _database = database;
        _deviceScanner = deviceScanner;

        _settings = new AppSettings();

        _ = LoadSettingsAsync();
    }

    private async Task LoadSettingsAsync()
    {
        try
        {
            _settings = await _database.GetSettingsAsync();

            AutoScanDevices = _settings.AutoScanDevices;
            ScanIntervalMinutes = _settings.ScanIntervalMinutes;
            EnablePacketCapture = _settings.EnablePacketCapture;
            ShowNotifications = _settings.ShowNotifications;
            MinimizeToTray = _settings.MinimizeToTray;
            AutoStartWithWindows = _settings.AutoStartWithWindows;
            TrafficSpikeThreshold = _settings.TrafficSpikeThreshold;
            ConnectionCountThreshold = _settings.ConnectionCountThreshold;

            _logger.Information("Settings loaded");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to load settings");
            StatusMessage = "Error loading settings";
        }
    }

    [RelayCommand]
    private async Task SaveSettings()
    {
        try
        {
            StatusMessage = "Saving settings...";

            _settings.AutoScanDevices = AutoScanDevices;
            _settings.ScanIntervalMinutes = ScanIntervalMinutes;
            _settings.EnablePacketCapture = EnablePacketCapture;
            _settings.ShowNotifications = ShowNotifications;
            _settings.MinimizeToTray = MinimizeToTray;
            _settings.AutoStartWithWindows = AutoStartWithWindows;
            _settings.TrafficSpikeThreshold = TrafficSpikeThreshold;
            _settings.ConnectionCountThreshold = ConnectionCountThreshold;

            await _database.UpdateSettingsAsync(_settings);

            // Update Windows startup
            UpdateWindowsStartup(AutoStartWithWindows);

            StatusMessage = "Settings saved successfully";
            
            MessageBox.Show("Settings saved successfully!", "Success", 
                MessageBoxButton.OK, MessageBoxImage.Information);

            _logger.Information("Settings saved");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to save settings");
            StatusMessage = "Error saving settings";
            
            MessageBox.Show("Failed to save settings", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task ResetSettings()
    {
        var result = MessageBox.Show(
            "Are you sure you want to reset all settings to defaults?",
            "Reset Settings",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question
        );

        if (result == MessageBoxResult.Yes)
        {
            _settings = new AppSettings { Id = 1 };
            await _database.UpdateSettingsAsync(_settings);
            await LoadSettingsAsync();
            
            StatusMessage = "Settings reset to defaults";
        }
    }

    [RelayCommand]
    private async Task TestNetworkScan()
    {
        StatusMessage = "Running test network scan...";
        
        try
        {
            await _deviceScanner.ScanNetworkAsync();
            StatusMessage = "Test scan completed";
            
            MessageBox.Show("Network scan completed successfully!", "Test Successful", 
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Test scan failed");
            StatusMessage = "Test scan failed";
            
            MessageBox.Show($"Test scan failed: {ex.Message}", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void UpdateWindowsStartup(bool enable)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);

            if (key == null)
                return;

            const string appName = "NetSentinel";

            if (enable)
            {
                var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(exePath))
                {
                    key.SetValue(appName, $"\"{exePath}\"");
                    _logger.Information("Added to Windows startup");
                }
            }
            else
            {
                if (key.GetValue(appName) != null)
                {
                    key.DeleteValue(appName);
                    _logger.Information("Removed from Windows startup");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(ex, "Failed to update Windows startup setting");
        }
    }
}

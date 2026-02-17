using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Messages;
using NetSentinel.Services;
using Serilog;
using SkiaSharp;

namespace NetSentinel.ViewModels;

/// <summary>
/// ViewModel for the main dashboard
/// </summary>
public partial class DashboardViewModel : ObservableObject
{
    private readonly ILogger _logger;
    private readonly NetworkManager _networkManager;
    private readonly BandwidthMonitor _bandwidthMonitor;
    private readonly DeviceScanner _deviceScanner;
    private readonly ConnectionMonitor _connectionMonitor;
    private readonly AlertService _alertService;
    private readonly System.Windows.Threading.DispatcherTimer _updateTimer;

    [ObservableProperty]
    private string _currentSsid = "Not Connected";

    [ObservableProperty]
    private string _currentIpAddress = "0.0.0.0";

    [ObservableProperty]
    private string _currentGateway = "0.0.0.0";

    [ObservableProperty]
    private bool _isAdmin;

    [ObservableProperty]
    private double _uploadSpeedMbps;

    [ObservableProperty]
    private double _downloadSpeedMbps;

    [ObservableProperty]
    private string _todayUpload = "0 MB";

    [ObservableProperty]
    private string _todayDownload = "0 MB";

    [ObservableProperty]
    private int _deviceCount;

    [ObservableProperty]
    private int _activeConnectionsCount;

    [ObservableProperty]
    private int _unreadAlertsCount;

    [ObservableProperty]
    private string _statusMessage = "Initializing...";

    [ObservableProperty]
    private int _pingMs = -1;

    [ObservableProperty]
    private string _pingStatus = "Good";

    [ObservableProperty]
    private bool _isWifiConnected = true;

    [ObservableProperty]
    private string _connectedSsid = "Not Connected";

    public ObservableCollection<ISeries> BandwidthSeries { get; set; }
    public ObservableCollection<SecurityAlert> RecentAlerts { get; set; }
    public Axis[] XAxes { get; set; }
    public Axis[] YAxes { get; set; }

    private readonly ObservableCollection<DateTimePoint> _uploadData;
    private readonly ObservableCollection<DateTimePoint> _downloadData;

    public DashboardViewModel(
        ILogger logger,
        NetworkManager networkManager,
        BandwidthMonitor bandwidthMonitor,
        DeviceScanner deviceScanner,
        ConnectionMonitor connectionMonitor,
        AlertService alertService)
    {
        _logger = logger;
        _networkManager = networkManager;
        _bandwidthMonitor = bandwidthMonitor;
        _deviceScanner = deviceScanner;
        _connectionMonitor = connectionMonitor;
        _alertService = alertService;

        _uploadData = new ObservableCollection<DateTimePoint>();
        _downloadData = new ObservableCollection<DateTimePoint>();

        BandwidthSeries = new ObservableCollection<ISeries>
        {
            new LineSeries<DateTimePoint>
            {
                Name = "Upload",
                Values = _uploadData,
                Fill = null,
                GeometrySize = 0,
                LineSmoothness = 0.5,
                Stroke = new SolidColorPaint(new SKColor(16, 185, 129)) { StrokeThickness = 2 }
            },
            new LineSeries<DateTimePoint>
            {
                Name = "Download",
                Values = _downloadData,
                Fill = null,
                GeometrySize = 0,
                LineSmoothness = 0.5,
                Stroke = new SolidColorPaint(new SKColor(59, 130, 246)) { StrokeThickness = 2 }
            }
        };

        XAxes = new Axis[]
        {
            new Axis
            {
                Labeler = value => new DateTime((long)value).ToString("HH:mm:ss"),
                LabelsPaint = new SolidColorPaint(SKColors.White),
                SeparatorsPaint = new SolidColorPaint(new SKColor(71, 85, 105)) { StrokeThickness = 1 },
                MaxLimit = null,
                MinLimit = null
            }
        };

        YAxes = new Axis[]
        {
            new Axis
            {
                Labeler = value => $"{value:F2} Mbps",
                LabelsPaint = new SolidColorPaint(SKColors.White),
                SeparatorsPaint = new SolidColorPaint(new SKColor(71, 85, 105)) { StrokeThickness = 1 },
                MinLimit = 0
            }
        };

        RecentAlerts = new ObservableCollection<SecurityAlert>();

        // Subscribe to events
        _bandwidthMonitor.BandwidthUpdated += OnBandwidthUpdated;
        _connectionMonitor.ConnectionsUpdated += OnConnectionsUpdated;
        _alertService.AlertRaised += OnAlertRaised;

        // Register for global refresh messages
        WeakReferenceMessenger.Default.Register<RefreshBandwidthMessage>(this, (r, m) => HandleRefreshMessage());

        // Update timer
        _updateTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _updateTimer.Tick += async (s, e) => await UpdateDashboardAsync();
        _updateTimer.Start();

        IsAdmin = Utils.AdminChecker.IsRunningAsAdministrator();

        _ = InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        await UpdateNetworkInfoAsync();
        await LoadRecentAlertsAsync();
        StatusMessage = "Ready";
    }

    /// <summary>
    /// Handles refresh message from global refresh command
    /// </summary>
    private void HandleRefreshMessage()
    {
        _logger.Information("DashboardViewModel received refresh message");
        Application.Current?.Dispatcher.Invoke(async () =>
        {
            await UpdateDashboardAsync();
            await UpdateNetworkInfoAsync();
            await LoadRecentAlertsAsync();
        });
    }

    private async Task UpdateDashboardAsync()
    {
        try
        {
            var devices = await _deviceScanner.GetKnownDevicesAsync();
            DeviceCount = devices.Count(d => d.IsOnline);

            UnreadAlertsCount = await _alertService.GetUnreadCountAsync();
            
            // Measure ping to gateway
            await MeasurePingAsync();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error updating dashboard");
        }
    }

    private async Task MeasurePingAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(CurrentGateway) || CurrentGateway == "0.0.0.0")
            {
                IsWifiConnected = false;
                PingMs = -1;
                return;
            }

            IsWifiConnected = true;
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(CurrentGateway, 1000);
            
            if (reply.Status == IPStatus.Success)
            {
                PingMs = (int)reply.RoundtripTime;
                PingStatus = PingMs < 50 ? "Good" : PingMs < 100 ? "Medium" : "High";
            }
            else
            {
                PingMs = -1;
                PingStatus = "Failed";
            }
        }
        catch
        {
            PingMs = -1;
            PingStatus = "Failed";
        }
    }

    private async Task UpdateNetworkInfoAsync()
    {
        var networkInfo = await _networkManager.GetActiveNetworkInterfaceAsync();
        if (networkInfo != null)
        {
            // Try SSID first, then Name, then show "Not Connected"
            CurrentSsid = !string.IsNullOrWhiteSpace(networkInfo.Ssid) 
                ? networkInfo.Ssid 
                : !string.IsNullOrWhiteSpace(networkInfo.Name) 
                    ? networkInfo.Name 
                    : "Not Connected";
            CurrentIpAddress = networkInfo.IpAddress;
            CurrentGateway = networkInfo.Gateway;
            
            _logger.Information("Network info updated - SSID: {SSID}, IP: {IP}", CurrentSsid, CurrentIpAddress);
        }
        else
        {
            CurrentSsid = "Not Connected";
            CurrentIpAddress = "0.0.0.0";
            CurrentGateway = "0.0.0.0";
        }

        // Get connected SSID using direct method
        ConnectedSsid = _networkManager.GetConnectedSsid();
    }

    private void OnBandwidthUpdated(object? sender, BandwidthEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            UploadSpeedMbps = e.UploadSpeedKbps / 1024.0; // Convert KB/s to Mbps
            DownloadSpeedMbps = e.DownloadSpeedKbps / 1024.0;

            TodayUpload = FormatBytes(e.TodayBytesSent);
            TodayDownload = FormatBytes(e.TodayBytesReceived);

            // Update chart data (keep last 60 points) - convert to Mbps
            var now = DateTime.Now;
            _uploadData.Add(new DateTimePoint(now, e.UploadSpeedKbps / 1024.0));
            _downloadData.Add(new DateTimePoint(now, e.DownloadSpeedKbps / 1024.0));

            if (_uploadData.Count > 60)
            {
                _uploadData.RemoveAt(0);
                _downloadData.RemoveAt(0);
            }
        });
    }

    private void OnConnectionsUpdated(object? sender, ConnectionsUpdatedEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            ActiveConnectionsCount = e.TotalCount;
        });
    }

    private void OnAlertRaised(object? sender, AlertRaisedEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(async () =>
        {
            await LoadRecentAlertsAsync();
        });
    }

    private async Task LoadRecentAlertsAsync()
    {
        var alerts = await _alertService.GetRecentAlertsAsync(5);
        
        Application.Current?.Dispatcher.Invoke(() =>
        {
            RecentAlerts.Clear();
            foreach (var alert in alerts)
            {
                RecentAlerts.Add(alert);
            }
        });
    }

    [RelayCommand]
    private async Task RefreshNetworkInfo()
    {
        StatusMessage = "Refreshing network info...";
        await UpdateNetworkInfoAsync();
        StatusMessage = "Ready";
    }

    private string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }

    private string ClassifyDevice(string hostname, string vendor, string ipAddress)
    {
        if (!string.IsNullOrEmpty(hostname))
        {
            if (hostname.ToLower().Contains("iphone") || hostname.ToLower().Contains("android"))
            {
                return "📱";
            }
            if (hostname.ToLower().Contains("macbook") || hostname.ToLower().Contains("laptop"))
            {
                return "💻";
            }
        }

        if (!string.IsNullOrEmpty(vendor))
        {
            if (vendor.ToLower().Contains("dell") || vendor.ToLower().Contains("hp") || vendor.ToLower().Contains("lenovo"))
            {
                return "🖥";
            }
        }

        if (!string.IsNullOrEmpty(ipAddress) && ipAddress == "192.168.1.1") // Example gateway IP
        {
            return "📡";
        }

        return "❓";
    }
}

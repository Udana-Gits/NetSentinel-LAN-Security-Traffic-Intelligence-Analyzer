using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using NetSentinel.Data;
using NetSentinel.Messages;
using Serilog;

namespace NetSentinel.ViewModels;

/// <summary>
/// Main window ViewModel
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private readonly ILogger _logger;

    [ObservableProperty]
    private object? _currentView;

    [ObservableProperty]
    private string _currentViewName = "Dashboard";

    [ObservableProperty]
    private bool _isSidebarVisible = true;

    [ObservableProperty]
    private bool _isRefreshing = false;

    public DashboardViewModel DashboardViewModel { get; }
    public DevicesViewModel DevicesViewModel { get; }
    public ConnectionsViewModel ConnectionsViewModel { get; }
    public AlertsViewModel AlertsViewModel { get; }
    public SettingsViewModel SettingsViewModel { get; }

    public MainViewModel(
        ILogger logger,
        DashboardViewModel dashboardViewModel,
        DevicesViewModel devicesViewModel,
        ConnectionsViewModel connectionsViewModel,
        AlertsViewModel alertsViewModel,
        SettingsViewModel settingsViewModel)
    {
        _logger = logger;

        DashboardViewModel = dashboardViewModel;
        DevicesViewModel = devicesViewModel;
        ConnectionsViewModel = connectionsViewModel;
        AlertsViewModel = alertsViewModel;
        SettingsViewModel = settingsViewModel;

        // Set default view
        CurrentView = DashboardViewModel;
        CurrentViewName = "Dashboard";
    }

    [RelayCommand]
    private void NavigateToDashboard()
    {
        CurrentView = DashboardViewModel;
        CurrentViewName = "Dashboard";
    }

    [RelayCommand]
    private void NavigateToDevices()
    {
        CurrentView = DevicesViewModel;
        CurrentViewName = "Devices";
    }

    [RelayCommand]
    private void NavigateToConnections()
    {
        CurrentView = ConnectionsViewModel;
        CurrentViewName = "Connections";
    }

    [RelayCommand]
    private void NavigateToAlerts()
    {
        CurrentView = AlertsViewModel;
        CurrentViewName = "Alerts";
    }

    [RelayCommand]
    private void NavigateToSettings()
    {
        CurrentView = SettingsViewModel;
        CurrentViewName = "Settings";
    }

    [RelayCommand]
    private void ToggleSidebar()
    {
        IsSidebarVisible = !IsSidebarVisible;
    }

    /// <summary>
    /// Global refresh command that triggers refresh across all components
    /// </summary>
    [RelayCommand]
    private async Task RefreshAll()
    {
        if (IsRefreshing)
        {
            _logger.Warning("Refresh already in progress, ignoring request");
            return;
        }

        IsRefreshing = true;
        _logger.Information("Global refresh triggered");

        try
        {
            // Refresh devices (scan network)
            _logger.Information("Triggering devices refresh");
            WeakReferenceMessenger.Default.Send(new RefreshDevicesMessage());
            
            // Refresh connections
            _logger.Information("Triggering connections refresh");
            WeakReferenceMessenger.Default.Send(new RefreshConnectionsMessage());
            
            // Refresh alerts
            _logger.Information("Triggering alerts refresh");
            WeakReferenceMessenger.Default.Send(new RefreshAlertsMessage());
            
            // Refresh dashboard/bandwidth
            _logger.Information("Triggering bandwidth/dashboard refresh");
            WeakReferenceMessenger.Default.Send(new RefreshBandwidthMessage());

            _logger.Information("Global refresh messages sent to all components");

            // Give time for refresh operations to complete
            await Task.Delay(1500);

            _logger.Information("Global refresh completed");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during global refresh");
        }
        finally
        {
            IsRefreshing = false;
        }
    }
}

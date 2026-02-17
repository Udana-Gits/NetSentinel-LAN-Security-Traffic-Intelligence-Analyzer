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
            // Send refresh messages to all components via Messenger
            WeakReferenceMessenger.Default.Send(new RefreshDevicesMessage());
            WeakReferenceMessenger.Default.Send(new RefreshConnectionsMessage());
            WeakReferenceMessenger.Default.Send(new RefreshAlertsMessage());
            WeakReferenceMessenger.Default.Send(new RefreshBandwidthMessage());

            _logger.Information("Global refresh messages sent to all components");

            // Wait for components to process (most are async)
            await Task.Delay(2000);

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

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
/// ViewModel for the alerts view
/// </summary>
public partial class AlertsViewModel : ObservableObject
{
    private readonly ILogger _logger;
    private readonly AlertService _alertService;
    private readonly DatabaseService _database;

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
    private readonly ObservableCollection<SecurityAlert> _allAlerts;

    public string[] SeverityFilters { get; } = { "All", "Critical", "Warning", "Info" };

    public AlertsViewModel(ILogger logger, AlertService alertService, DatabaseService database)
    {
        _logger = logger;
        _alertService = alertService;
        _database = database;

        Alerts = new ObservableCollection<SecurityAlert>();
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
                
                foreach (var alert in alerts.OrderByDescending(a => a.Timestamp))
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
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Alerts.Clear();

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

            foreach (var alert in filtered)
            {
                Alerts.Add(alert);
            }
        });
    }

    private void OnAlertRaised(object? sender, AlertRaisedEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            _allAlerts.Insert(0, e.Alert);
            UpdateStatistics();
            ApplyFilters();
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

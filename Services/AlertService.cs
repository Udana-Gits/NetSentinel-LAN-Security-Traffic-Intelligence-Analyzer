using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using NetSentinel.Data;
using Serilog;

namespace NetSentinel.Services;

/// <summary>
/// Manages security alerts and notifications
/// </summary>
public class AlertService
{
    private readonly ILogger _logger;
    private readonly DatabaseService _database;
    private readonly AppSettings _settings;

    public event EventHandler<AlertRaisedEventArgs>? AlertRaised;

    public AlertService(ILogger logger, DatabaseService database)
    {
        _logger = logger;
        _database = database;
        _settings = database.GetSettingsAsync().Result;
    }

    /// <summary>
    /// Raises a security alert
    /// </summary>
    public async Task RaiseAlertAsync(SecurityAlert alert)
    {
        try
        {
            // Save to database
            await _database.AddAlertAsync(alert);

            _logger.Warning("Security Alert [{Severity}]: {Title} - {Description}", 
                alert.Severity, alert.Title, alert.Description);

            // Show notification if enabled
            if (_settings.ShowNotifications)
            {
                ShowNotification(alert);
            }

            // Raise event
            AlertRaised?.Invoke(this, new AlertRaisedEventArgs { Alert = alert });
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to raise alert");
        }
    }

    /// <summary>
    /// Shows a Windows notification
    /// </summary>
    private void ShowNotification(SecurityAlert alert)
    {
        try
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                var severityIcon = alert.Severity switch
                {
                    AlertSeverity.Critical => MessageBoxImage.Error,
                    AlertSeverity.Warning => MessageBoxImage.Warning,
                    _ => MessageBoxImage.Information
                };

                // In a production app, you'd use a custom notification window or toast
                // For now, we'll just log it (actual toast notifications would require additional libraries)
                _logger.Information("Notification: {Title}", alert.Title);
            });
        }
        catch (Exception ex)
        {
            _logger.Warning(ex, "Failed to show notification");
        }
    }

    /// <summary>
    /// Gets recent alerts
    /// </summary>
    public async Task<System.Collections.Generic.List<SecurityAlert>> GetRecentAlertsAsync(int count = 50)
    {
        return await _database.GetRecentAlertsAsync(count);
    }

    /// <summary>
    /// Marks an alert as read
    /// </summary>
    public async Task MarkAsReadAsync(int alertId)
    {
        await _database.MarkAlertAsReadAsync(alertId);
    }

    /// <summary>
    /// Gets unread alert count
    /// </summary>
    public async Task<int> GetUnreadCountAsync()
    {
        var alerts = await _database.GetRecentAlertsAsync(1000);
        return alerts.Count(a => !a.IsRead);
    }
}

/// <summary>
/// Alert raised event arguments
/// </summary>
public class AlertRaisedEventArgs : EventArgs
{
    public SecurityAlert Alert { get; set; } = null!;
}

using System;
using System.Threading;
using System.Threading.Tasks;
using NetSentinel.Core;
using NetSentinel.Data;
using Serilog;

namespace NetSentinel.Services;

/// <summary>
/// Background scheduler for periodic tasks
/// </summary>
public class BackgroundScheduler
{
    private readonly ILogger _logger;
    private readonly DatabaseService _database;
    private readonly DeviceScanner _deviceScanner;
    private CancellationTokenSource? _cts;
    private bool _isRunning;

    public BackgroundScheduler(ILogger logger, DatabaseService database, DeviceScanner deviceScanner)
    {
        _logger = logger;
        _database = database;
        _deviceScanner = deviceScanner;
    }

    /// <summary>
    /// Starts the background scheduler
    /// </summary>
    public async Task StartAsync()
    {
        if (_isRunning)
            return;

        _isRunning = true;
        _cts = new CancellationTokenSource();

        _logger.Information("Background scheduler started");

        _ = Task.Run(() => SchedulerLoopAsync(_cts.Token), _cts.Token);
    }

    /// <summary>
    /// Stops the background scheduler
    /// </summary>
    public void Stop()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _logger.Information("Background scheduler stopped");
    }

    /// <summary>
    /// Main scheduler loop
    /// </summary>
    private async Task SchedulerLoopAsync(CancellationToken cancellationToken)
    {
        var lastDeviceScan = DateTime.MinValue;
        var lastDataCleanup = DateTime.MinValue;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var settings = await _database.GetSettingsAsync();
                var now = DateTime.UtcNow;

                // Auto device scan
                if (settings.AutoScanDevices)
                {
                    var scanInterval = TimeSpan.FromMinutes(settings.ScanIntervalMinutes);
                    if (now - lastDeviceScan >= scanInterval)
                    {
                        _logger.Information("Starting scheduled device scan");
                        await _deviceScanner.ScanNetworkAsync(cancellationToken);
                        lastDeviceScan = now;
                    }
                }

                // Data cleanup (once per day)
                if (now - lastDataCleanup >= TimeSpan.FromDays(1))
                {
                    _logger.Information("Starting scheduled data cleanup");
                    await _database.CleanupOldDataAsync(30);
                    lastDataCleanup = now;
                }

                // Sleep for a minute before checking again
                await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in background scheduler loop");
                await Task.Delay(TimeSpan.FromMinutes(5), cancellationToken);
            }
        }
    }
}

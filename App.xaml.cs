using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NetSentinel.Capture;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Services;
using NetSentinel.UI;
using NetSentinel.ViewModels;
using Serilog;

namespace NetSentinel;

public partial class App : Application
{
    private IHost? _host;
    private ILogger? _logger;

    private void Application_Startup(object sender, StartupEventArgs e)
    {
        try
        {
            // Initialize Serilog
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.File(
                    System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "NetSentinel",
                        "logs",
                        "netsentinel-.log"
                    ),
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 7
                )
                .WriteTo.Console()
                .CreateLogger();

            _logger = Log.Logger;
            _logger.Information("NetSentinel starting up...");
            _logger.Information("Administrator privileges: {IsAdmin}", Utils.AdminChecker.IsRunningAsAdministrator());

            // Show ethical usage notice on first launch
            ShowEthicalUsageNotice();

            // Build the dependency injection container
            _host = Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    // Register Serilog
                    services.AddSingleton(_logger);

                    // Register Data
                    services.AddSingleton<DatabaseService>();

                    // Register Core Services
                    services.AddSingleton<NetworkManager>();
                    services.AddSingleton<BandwidthMonitor>();
                    services.AddSingleton<DeviceScanner>();
                    services.AddSingleton<ConnectionMonitor>();
                    services.AddSingleton<SecurityEngine>();

                    // Register Capture
                    services.AddSingleton<PacketCaptureService>();

                    // Register Services
                    services.AddSingleton<AlertService>();
                    services.AddSingleton<BackgroundScheduler>();

                    // Register ViewModels
                    services.AddSingleton<DashboardViewModel>();
                    services.AddSingleton<DevicesViewModel>();
                    services.AddSingleton<ConnectionsViewModel>();
                    services.AddSingleton<AlertsViewModel>();
                    services.AddSingleton<SettingsViewModel>();
                    services.AddSingleton<MainViewModel>();

                    // Register Views
                    services.AddTransient<MainWindow>();
                })
                .Build();

            // Start background services
            StartBackgroundServicesAsync();

            // Create and show main window
            var mainWindow = _host.Services.GetRequiredService<MainWindow>();
            var mainViewModel = _host.Services.GetRequiredService<MainViewModel>();
            mainWindow.DataContext = mainViewModel;
            mainWindow.Show();

            _logger.Information("NetSentinel started successfully");
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Application failed to start");
            MessageBox.Show(
                $"Failed to start NetSentinel:\n{ex.Message}",
                "Startup Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
            Shutdown();
        }
    }

    private void ShowEthicalUsageNotice()
    {
        var settingsPath = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "NetSentinel",
            "accepted_terms"
        );

        if (!System.IO.File.Exists(settingsPath))
        {
            var result = MessageBox.Show(
                "ETHICAL USAGE NOTICE\n\n" +
                "NetSentinel is a network monitoring and security analysis tool.\n\n" +
                "You MUST only use this tool on:\n" +
                "• Networks that you own\n" +
                "• Networks where you have explicit authorization to monitor\n\n" +
                "Unauthorized network monitoring may violate laws and regulations in your jurisdiction.\n\n" +
                "By clicking 'Accept', you confirm that you will use this tool ethically and legally.",
                "Ethical Usage Agreement",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning
            );

            if (result == MessageBoxResult.OK)
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(settingsPath)!);
                System.IO.File.WriteAllText(settingsPath, DateTime.UtcNow.ToString("o"));
                _logger?.Information("User accepted ethical usage terms");
            }
            else
            {
                _logger?.Warning("User declined ethical usage terms");
                Shutdown();
            }
        }
    }

    private async void StartBackgroundServicesAsync()
    {
        try
        {
            if (_host == null) return;

            var networkManager = _host.Services.GetRequiredService<NetworkManager>();
            var bandwidthMonitor = _host.Services.GetRequiredService<BandwidthMonitor>();
            var connectionMonitor = _host.Services.GetRequiredService<ConnectionMonitor>();
            var securityEngine = _host.Services.GetRequiredService<SecurityEngine>();
            var scheduler = _host.Services.GetRequiredService<BackgroundScheduler>();
            var packetCapture = _host.Services.GetRequiredService<PacketCaptureService>();
            var database = _host.Services.GetRequiredService<DatabaseService>();

            // Get settings
            var settings = await database.GetSettingsAsync();

            // Initialize network manager
            await networkManager.GetActiveNetworkInterfaceAsync();

            // Start bandwidth monitoring
            await bandwidthMonitor.StartAsync();

            // Start connection monitoring
            await connectionMonitor.StartAsync();

            // Start security engine
            await securityEngine.StartAsync();

            // Start background scheduler
            await scheduler.StartAsync();

            // Start packet capture if enabled and admin
            if (settings.EnablePacketCapture && Utils.AdminChecker.IsRunningAsAdministrator())
            {
                var networkInfo = networkManager.GetCurrentInterface();
                if (networkInfo != null)
                {
                    await packetCapture.StartCaptureAsync(networkInfo.Name);
                }
            }

            _logger?.Information("All background services started");
        }
        catch (Exception ex)
        {
            _logger?.Error(ex, "Failed to start background services");
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _logger?.Information("NetSentinel shutting down...");

            if (_host != null)
            {
                // Stop services
                var bandwidthMonitor = _host.Services.GetService<BandwidthMonitor>();
                var connectionMonitor = _host.Services.GetService<ConnectionMonitor>();
                var securityEngine = _host.Services.GetService<SecurityEngine>();
                var scheduler = _host.Services.GetService<BackgroundScheduler>();
                var packetCapture = _host.Services.GetService<PacketCaptureService>();

                bandwidthMonitor?.Stop();
                connectionMonitor?.Stop();
                securityEngine?.Stop();
                scheduler?.Stop();
                packetCapture?.StopCapture();

                _host.Dispose();
            }

            Log.CloseAndFlush();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Error during shutdown");
        }

        base.OnExit(e);
    }
}

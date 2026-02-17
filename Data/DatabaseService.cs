using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Data.Sqlite;
using Serilog;

namespace NetSentinel.Data;

/// <summary>
/// Manages SQLite database operations
/// </summary>
public class DatabaseService
{
    private readonly string _connectionString;
    private readonly ILogger _logger;

    public DatabaseService(ILogger logger)
    {
        _logger = logger;
        var dbPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "NetSentinel",
            "netsentinel.db"
        );
        
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
        _connectionString = $"Data Source={dbPath}";
        
        InitializeDatabaseAsync().Wait();
    }

    private async Task InitializeDatabaseAsync()
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            // Create tables
            await connection.ExecuteAsync(@"
                CREATE TABLE IF NOT EXISTS NetworkDevices (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    IpAddress TEXT NOT NULL,
                    MacAddress TEXT NOT NULL,
                    Vendor TEXT,
                    Hostname TEXT,
                    FirstSeen TEXT NOT NULL,
                    LastSeen TEXT NOT NULL,
                    IsOnline INTEGER NOT NULL,
                    IsGateway INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_devices_ip ON NetworkDevices(IpAddress);
                CREATE INDEX IF NOT EXISTS idx_devices_mac ON NetworkDevices(MacAddress);
            ");

            await connection.ExecuteAsync(@"
                CREATE TABLE IF NOT EXISTS SecurityAlerts (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT NOT NULL,
                    Severity INTEGER NOT NULL,
                    Title TEXT NOT NULL,
                    Description TEXT NOT NULL,
                    SourceIp TEXT,
                    SourceMac TEXT,
                    IsRead INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON SecurityAlerts(Timestamp);
            ");

            await connection.ExecuteAsync(@"
                CREATE TABLE IF NOT EXISTS BandwidthHistory (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT NOT NULL,
                    BytesSent INTEGER NOT NULL,
                    BytesReceived INTEGER NOT NULL,
                    UploadSpeedKbps REAL NOT NULL,
                    DownloadSpeedKbps REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bandwidth_timestamp ON BandwidthHistory(Timestamp);
            ");

            await connection.ExecuteAsync(@"
                CREATE TABLE IF NOT EXISTS PacketStatistics (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT NOT NULL,
                    TotalPackets INTEGER NOT NULL,
                    TcpPackets INTEGER NOT NULL,
                    UdpPackets INTEGER NOT NULL,
                    IcmpPackets INTEGER NOT NULL,
                    ArpPackets INTEGER NOT NULL,
                    DnsQueries INTEGER NOT NULL
                );
            ");

            await connection.ExecuteAsync(@"
                CREATE TABLE IF NOT EXISTS Settings (
                    Id INTEGER PRIMARY KEY CHECK (Id = 1),
                    AutoScanDevices INTEGER NOT NULL DEFAULT 1,
                    ScanIntervalMinutes INTEGER NOT NULL DEFAULT 5,
                    EnablePacketCapture INTEGER NOT NULL DEFAULT 1,
                    ShowNotifications INTEGER NOT NULL DEFAULT 1,
                    MinimizeToTray INTEGER NOT NULL DEFAULT 1,
                    AutoStartWithWindows INTEGER NOT NULL DEFAULT 0,
                    TrafficSpikeThreshold INTEGER NOT NULL DEFAULT 10000,
                    ConnectionCountThreshold INTEGER NOT NULL DEFAULT 100,
                    DarkMode INTEGER NOT NULL DEFAULT 1
                );
            ");

            // Insert default settings if not exists
            await connection.ExecuteAsync(@"
                INSERT OR IGNORE INTO Settings (Id, AutoScanDevices, ScanIntervalMinutes, 
                    EnablePacketCapture, ShowNotifications, MinimizeToTray, AutoStartWithWindows,
                    TrafficSpikeThreshold, ConnectionCountThreshold, DarkMode)
                VALUES (1, 1, 5, 1, 1, 1, 0, 10000, 100, 1);
            ");

            _logger.Information("Database initialized successfully");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to initialize database");
            throw;
        }
    }

    // Network Devices
    public async Task<List<NetworkDevice>> GetAllDevicesAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        var devices = await connection.QueryAsync<NetworkDevice>("SELECT * FROM NetworkDevices ORDER BY LastSeen DESC");
        return devices.AsList();
    }

    public async Task UpsertDeviceAsync(NetworkDevice device)
    {
        using var connection = new SqliteConnection(_connectionString);
        
        var existing = await connection.QueryFirstOrDefaultAsync<int>(
            "SELECT Id FROM NetworkDevices WHERE MacAddress = @MacAddress",
            new { device.MacAddress }
        );

        if (existing > 0)
        {
            await connection.ExecuteAsync(@"
                UPDATE NetworkDevices 
                SET IpAddress = @IpAddress, Vendor = @Vendor, Hostname = @Hostname, 
                    LastSeen = @LastSeen, IsOnline = @IsOnline, IsGateway = @IsGateway
                WHERE MacAddress = @MacAddress",
                device
            );
        }
        else
        {
            await connection.ExecuteAsync(@"
                INSERT INTO NetworkDevices (IpAddress, MacAddress, Vendor, Hostname, FirstSeen, LastSeen, IsOnline, IsGateway)
                VALUES (@IpAddress, @MacAddress, @Vendor, @Hostname, @FirstSeen, @LastSeen, @IsOnline, @IsGateway)",
                device
            );
        }
    }

    public async Task MarkDeviceOfflineAsync(string macAddress)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.ExecuteAsync(
            "UPDATE NetworkDevices SET IsOnline = 0 WHERE MacAddress = @MacAddress",
            new { MacAddress = macAddress }
        );
    }

    // Security Alerts
    public async Task<List<SecurityAlert>> GetRecentAlertsAsync(int count = 100)
    {
        using var connection = new SqliteConnection(_connectionString);
        var alerts = await connection.QueryAsync<SecurityAlert>(
            "SELECT * FROM SecurityAlerts ORDER BY Timestamp DESC LIMIT @Count",
            new { Count = count }
        );
        return alerts.AsList();
    }

    public async Task AddAlertAsync(SecurityAlert alert)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.ExecuteAsync(@"
            INSERT INTO SecurityAlerts (Timestamp, Severity, Title, Description, SourceIp, SourceMac, IsRead)
            VALUES (@Timestamp, @Severity, @Title, @Description, @SourceIp, @SourceMac, @IsRead)",
            alert
        );
    }

    public async Task MarkAlertAsReadAsync(int alertId)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.ExecuteAsync(
            "UPDATE SecurityAlerts SET IsRead = 1 WHERE Id = @Id",
            new { Id = alertId }
        );
    }

    // Bandwidth History
    public async Task AddBandwidthEntryAsync(BandwidthEntry entry)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.ExecuteAsync(@"
            INSERT INTO BandwidthHistory (Timestamp, BytesSent, BytesReceived, UploadSpeedKbps, DownloadSpeedKbps)
            VALUES (@Timestamp, @BytesSent, @BytesReceived, @UploadSpeedKbps, @DownloadSpeedKbps)",
            entry
        );
    }

    public async Task<List<BandwidthEntry>> GetBandwidthHistoryAsync(DateTime since)
    {
        using var connection = new SqliteConnection(_connectionString);
        var entries = await connection.QueryAsync<BandwidthEntry>(
            "SELECT * FROM BandwidthHistory WHERE Timestamp >= @Since ORDER BY Timestamp",
            new { Since = since.ToString("o") }
        );
        return entries.AsList();
    }

    public async Task<(long TotalSent, long TotalReceived)> GetTodayTotalAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        var today = DateTime.Today.ToString("o");
        
        var result = await connection.QueryFirstOrDefaultAsync<(long, long)>(@"
            SELECT COALESCE(SUM(BytesSent), 0), COALESCE(SUM(BytesReceived), 0)
            FROM BandwidthHistory 
            WHERE Timestamp >= @Today",
            new { Today = today }
        );
        
        return result;
    }

    // Packet Statistics
    public async Task AddPacketStatsAsync(PacketStats stats)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.ExecuteAsync(@"
            INSERT INTO PacketStatistics (Timestamp, TotalPackets, TcpPackets, UdpPackets, IcmpPackets, ArpPackets, DnsQueries)
            VALUES (@Timestamp, @TotalPackets, @TcpPackets, @UdpPackets, @IcmpPackets, @ArpPackets, @DnsQueries)",
            stats
        );
    }

    // Settings
    public async Task<AppSettings> GetSettingsAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        var settings = await connection.QueryFirstOrDefaultAsync<AppSettings>("SELECT * FROM Settings WHERE Id = 1");
        return settings ?? new AppSettings { Id = 1 };
    }

    public async Task UpdateSettingsAsync(AppSettings settings)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.ExecuteAsync(@"
            UPDATE Settings 
            SET AutoScanDevices = @AutoScanDevices,
                ScanIntervalMinutes = @ScanIntervalMinutes,
                EnablePacketCapture = @EnablePacketCapture,
                ShowNotifications = @ShowNotifications,
                MinimizeToTray = @MinimizeToTray,
                AutoStartWithWindows = @AutoStartWithWindows,
                TrafficSpikeThreshold = @TrafficSpikeThreshold,
                ConnectionCountThreshold = @ConnectionCountThreshold,
                DarkMode = @DarkMode
            WHERE Id = 1",
            settings
        );
    }

    // Cleanup old data
    public async Task CleanupOldDataAsync(int daysToKeep = 30)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-daysToKeep).ToString("o");
        
        using var connection = new SqliteConnection(_connectionString);
        await connection.ExecuteAsync(@"
            DELETE FROM BandwidthHistory WHERE Timestamp < @CutoffDate;
            DELETE FROM PacketStatistics WHERE Timestamp < @CutoffDate;
            DELETE FROM SecurityAlerts WHERE Timestamp < @CutoffDate AND IsRead = 1;
        ", new { CutoffDate = cutoffDate });
        
        _logger.Information("Cleaned up data older than {Days} days", daysToKeep);
    }

    // Export functionality
    public async Task<string> ExportDevicesToCsvAsync()
    {
        var devices = await GetAllDevicesAsync();
        var csv = "IP Address,MAC Address,Vendor,Hostname,First Seen,Last Seen,Online,Is Gateway\n";
        
        foreach (var device in devices)
        {
            csv += $"{device.IpAddress},{device.MacAddress},{device.Vendor}," +
                   $"{device.Hostname},{device.FirstSeen:yyyy-MM-dd HH:mm:ss}," +
                   $"{device.LastSeen:yyyy-MM-dd HH:mm:ss},{device.IsOnline},{device.IsGateway}\n";
        }
        
        return csv;
    }

    public async Task<string> ExportAlertsToCsvAsync()
    {
        var alerts = await GetRecentAlertsAsync(1000);
        var csv = "Timestamp,Severity,Title,Description,Source IP,Source MAC\n";
        
        foreach (var alert in alerts)
        {
            csv += $"{alert.Timestamp:yyyy-MM-dd HH:mm:ss},{alert.Severity}," +
                   $"\"{alert.Title}\",\"{alert.Description}\"," +
                   $"{alert.SourceIp},{alert.SourceMac}\n";
        }
        
        return csv;
    }
}

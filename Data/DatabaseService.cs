using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
                    IsRead INTEGER NOT NULL DEFAULT 0,
                    Count INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON SecurityAlerts(Timestamp);
            ");

            // Migration: Add Count column if it doesn't exist
            try
            {
                await connection.ExecuteAsync("ALTER TABLE SecurityAlerts ADD COLUMN Count INTEGER NOT NULL DEFAULT 1;");
            }
            catch (SqliteException)
            {
                // Column already exists
            }

            // Migration: Add customizable failed login thresholds to Settings if they don't exist
            try
            {
                await connection.ExecuteAsync("ALTER TABLE Settings ADD COLUMN FailedLoginThresholdInfo INTEGER NOT NULL DEFAULT 1;");
            }
            catch (SqliteException) { }
            try
            {
                await connection.ExecuteAsync("ALTER TABLE Settings ADD COLUMN FailedLoginThresholdWarning INTEGER NOT NULL DEFAULT 5;");
            }
            catch (SqliteException) { }
            try
            {
                await connection.ExecuteAsync("ALTER TABLE Settings ADD COLUMN FailedLoginThresholdCritical INTEGER NOT NULL DEFAULT 50;");
            }
            catch (SqliteException) { }

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
                    DarkMode INTEGER NOT NULL DEFAULT 1,
                    FailedLoginThresholdInfo INTEGER NOT NULL DEFAULT 1,
                    FailedLoginThresholdWarning INTEGER NOT NULL DEFAULT 5,
                    FailedLoginThresholdCritical INTEGER NOT NULL DEFAULT 50
                );
            ");

            // Insert default settings if not exists
            await connection.ExecuteAsync(@"
                INSERT OR IGNORE INTO Settings (Id, AutoScanDevices, ScanIntervalMinutes, 
                    EnablePacketCapture, ShowNotifications, MinimizeToTray, AutoStartWithWindows,
                    TrafficSpikeThreshold, ConnectionCountThreshold, DarkMode,
                    FailedLoginThresholdInfo, FailedLoginThresholdWarning, FailedLoginThresholdCritical)
                VALUES (1, 1, 5, 1, 1, 1, 0, 10000, 100, 1, 1, 5, 50);
            ");

            // Migration: Clean up and merge duplicate MAC addresses (case-insensitive merge)
            try
            {
                var devices = (await connection.QueryAsync<NetworkDevice>("SELECT * FROM NetworkDevices")).ToList();
                if (devices.Count > 0)
                {
                    // 1. Group and merge case-insensitive duplicates
                    var merged = new Dictionary<string, NetworkDevice>(StringComparer.OrdinalIgnoreCase);
                    foreach (var device in devices)
                    {
                        var mac = device.MacAddress?.Trim().ToUpperInvariant() ?? string.Empty;
                        if (string.IsNullOrEmpty(mac)) continue;

                        if (merged.TryGetValue(mac, out var existing))
                        {
                            if (device.LastSeen > existing.LastSeen)
                            {
                                existing.LastSeen = device.LastSeen;
                                existing.IpAddress = device.IpAddress;
                                existing.IsOnline = device.IsOnline;
                            }
                            if (device.FirstSeen < existing.FirstSeen)
                            {
                                existing.FirstSeen = device.FirstSeen;
                            }
                            if (device.IsGateway)
                            {
                                existing.IsGateway = true;
                            }
                            if ((string.IsNullOrEmpty(existing.Hostname) || existing.Hostname == "Unknown Device") && !string.IsNullOrEmpty(device.Hostname))
                            {
                                existing.Hostname = device.Hostname;
                            }
                            if ((string.IsNullOrEmpty(existing.Vendor) || existing.Vendor == "Unknown Vendor") && !string.IsNullOrEmpty(device.Vendor) && device.Vendor != "Unknown Vendor")
                            {
                                existing.Vendor = device.Vendor;
                            }
                            if (existing.DeviceType == DeviceType.Unknown && device.DeviceType != DeviceType.Unknown)
                            {
                                existing.DeviceType = device.DeviceType;
                            }
                        }
                        else
                        {
                            device.MacAddress = mac;
                            merged[mac] = device;
                        }
                    }

                    // 2. Group by IP address and clean up dummy MAC duplicates if we have the real MAC for the same IP
                    var uniqueDevicesList = merged.Values.ToList();
                    var ipGroups = uniqueDevicesList.GroupBy(d => d.IpAddress).Where(g => g.Count() > 1).ToList();
                    var toRemove = new List<NetworkDevice>();
                    foreach (var group in ipGroups)
                    {
                        var realMacDevice = group.FirstOrDefault(d => d.MacAddress != "02:00:00:00:00:00" && !string.IsNullOrEmpty(d.MacAddress));
                        var dummyMacDevice = group.FirstOrDefault(d => d.MacAddress == "02:00:00:00:00:00");
                        
                        if (realMacDevice != null && dummyMacDevice != null)
                        {
                            // Merge details into the real MAC device
                            if ((realMacDevice.Vendor == "Unknown Vendor" || string.IsNullOrEmpty(realMacDevice.Vendor)) && 
                                !string.IsNullOrEmpty(dummyMacDevice.Vendor) && dummyMacDevice.Vendor != "Unknown Vendor")
                            {
                                realMacDevice.Vendor = dummyMacDevice.Vendor;
                            }
                            if (string.IsNullOrEmpty(realMacDevice.Hostname) && !string.IsNullOrEmpty(dummyMacDevice.Hostname))
                            {
                                realMacDevice.Hostname = dummyMacDevice.Hostname;
                            }
                            if (realMacDevice.DeviceType == DeviceType.Unknown && dummyMacDevice.DeviceType != DeviceType.Unknown)
                            {
                                realMacDevice.DeviceType = dummyMacDevice.DeviceType;
                            }
                            
                            toRemove.Add(dummyMacDevice);
                        }
                    }
                    
                    foreach (var d in toRemove)
                    {
                        uniqueDevicesList.Remove(d);
                    }

                    bool needsMigration = uniqueDevicesList.Count < devices.Count || devices.Any(d => d.MacAddress != d.MacAddress.ToUpperInvariant());
                    if (needsMigration)
                    {
                        _logger.Information("Migrating and cleaning up {Count} devices in database to {MergedCount} unique devices", devices.Count, uniqueDevicesList.Count);
                        
                        using var transaction = connection.BeginTransaction();
                        try
                        {
                            await connection.ExecuteAsync("DELETE FROM NetworkDevices", transaction: transaction);
                            foreach (var d in uniqueDevicesList)
                            {
                                await connection.ExecuteAsync(@"
                                    INSERT INTO NetworkDevices (IpAddress, MacAddress, Vendor, Hostname, FirstSeen, LastSeen, IsOnline, IsGateway)
                                    VALUES (@IpAddress, @MacAddress, @Vendor, @Hostname, @FirstSeen, @LastSeen, @IsOnline, @IsGateway)",
                                    d, transaction: transaction
                                );
                            }
                            transaction.Commit();
                            _logger.Information("Database devices cleanup completed successfully");
                        }
                        catch (Exception ex)
                        {
                            transaction.Rollback();
                            _logger.Error(ex, "Failed to complete transaction during database devices cleanup");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to migrate/cleanup duplicate devices in database");
            }

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

    public async Task<NetworkDevice?> GetDeviceByIpAsync(string ipAddress)
    {
        using var connection = new SqliteConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<NetworkDevice>(
            "SELECT * FROM NetworkDevices WHERE IpAddress = @IpAddress AND MacAddress != '02:00:00:00:00:00' AND MacAddress != '' ORDER BY LastSeen DESC LIMIT 1",
            new { IpAddress = ipAddress }
        );
    }

    public async Task<NetworkDevice?> GetDeviceByMacAsync(string macAddress)
    {
        using var connection = new SqliteConnection(_connectionString);
        var normalizedMac = macAddress?.Trim().ToUpperInvariant() ?? string.Empty;
        return await connection.QueryFirstOrDefaultAsync<NetworkDevice>(
            "SELECT * FROM NetworkDevices WHERE MacAddress = @MacAddress",
            new { MacAddress = normalizedMac }
        );
    }

    public async Task UpsertDeviceAsync(NetworkDevice device)
    {
        using var connection = new SqliteConnection(_connectionString);
        
        // Normalize MAC and IP
        device.MacAddress = device.MacAddress?.Trim().ToUpperInvariant() ?? string.Empty;
        device.IpAddress = device.IpAddress?.Trim() ?? string.Empty;

        // If the incoming device has a valid MAC address, check if there's a dummy MAC record with the same IP
        if (device.MacAddress != "02:00:00:00:00:00" && !string.IsNullOrEmpty(device.MacAddress))
        {
            var dummyRecord = await connection.QueryFirstOrDefaultAsync<NetworkDevice>(
                "SELECT * FROM NetworkDevices WHERE IpAddress = @IpAddress AND MacAddress = '02:00:00:00:00:00'",
                new { device.IpAddress }
            );

            if (dummyRecord != null)
            {
                // Preserve specific hostname/vendor from the dummy telemetry record
                if ((device.Vendor == "Unknown Vendor" || string.IsNullOrEmpty(device.Vendor)) && 
                    !string.IsNullOrEmpty(dummyRecord.Vendor) && dummyRecord.Vendor != "Unknown Vendor")
                {
                    device.Vendor = dummyRecord.Vendor;
                }
                if (string.IsNullOrEmpty(device.Hostname) && !string.IsNullOrEmpty(dummyRecord.Hostname))
                {
                    device.Hostname = dummyRecord.Hostname;
                }

                // Delete the dummy record from the database so it doesn't cause duplicates
                await connection.ExecuteAsync(
                    "DELETE FROM NetworkDevices WHERE Id = @Id",
                    new { dummyRecord.Id }
                );
            }
        }

        var existing = await connection.QueryFirstOrDefaultAsync<NetworkDevice>(
            "SELECT * FROM NetworkDevices WHERE MacAddress = @MacAddress",
            new { device.MacAddress }
        );

        if (existing != null)
        {
            device.Id = existing.Id;
            device.FirstSeen = existing.FirstSeen;

            // Preserve specific/known vendor if incoming is generic/unknown
            if ((device.Vendor == "Unknown Vendor" || string.IsNullOrEmpty(device.Vendor)) && 
                !string.IsNullOrEmpty(existing.Vendor) && existing.Vendor != "Unknown Vendor")
            {
                device.Vendor = existing.Vendor;
            }

            // Preserve specific/known hostname if incoming is empty/unknown
            if (string.IsNullOrEmpty(device.Hostname) && !string.IsNullOrEmpty(existing.Hostname))
            {
                device.Hostname = existing.Hostname;
            }

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

        // If this device is a gateway, ensure no other device is marked as a gateway
        if (device.IsGateway)
        {
            await connection.ExecuteAsync(
                "UPDATE NetworkDevices SET IsGateway = 0 WHERE MacAddress != @MacAddress",
                new { device.MacAddress }
            );
        }
    }

    public async Task MarkDeviceOfflineAsync(string macAddress)
    {
        using var connection = new SqliteConnection(_connectionString);
        var normalizedMac = macAddress?.Trim().ToUpperInvariant() ?? string.Empty;
        await connection.ExecuteAsync(
            "UPDATE NetworkDevices SET IsOnline = 0 WHERE MacAddress = @MacAddress",
            new { MacAddress = normalizedMac }
        );
    }

    // Security Alerts
    public async Task<List<SecurityAlert>> GetRecentAlertsAsync(int count = 100)
    {
        using var connection = new SqliteConnection(_connectionString);
        // Query more rows than requested to ensure that after grouping duplicates, we still satisfy the requested count
        var limit = Math.Max(2000, count * 2);
        var alerts = await connection.QueryAsync<SecurityAlert>(
            "SELECT * FROM SecurityAlerts ORDER BY Timestamp DESC LIMIT @Limit",
            new { Limit = limit }
        );

        var aggregated = new List<SecurityAlert>();
        foreach (var alert in alerts)
        {
            var existing = aggregated.FirstOrDefault(a => 
                a.Title == alert.Title && 
                a.Severity == alert.Severity && 
                (a.SourceIp == alert.SourceIp || (string.IsNullOrEmpty(a.SourceIp) && string.IsNullOrEmpty(alert.SourceIp))) && 
                (a.SourceMac == alert.SourceMac || (string.IsNullOrEmpty(a.SourceMac) && string.IsNullOrEmpty(alert.SourceMac)))
            );

            if (existing != null)
            {
                existing.Count += alert.Count;
                if (!alert.IsRead)
                {
                    existing.IsRead = false;
                }
                if (alert.Timestamp > existing.Timestamp)
                {
                    existing.Timestamp = alert.Timestamp;
                    existing.Description = alert.Description;
                }
            }
            else
            {
                aggregated.Add(alert);
            }
        }

        return aggregated.Take(count).ToList();
    }

    public async Task AddAlertAsync(SecurityAlert alert)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        // Normalize empty strings to null for consistent DB storage and comparison
        alert.SourceMac = string.IsNullOrWhiteSpace(alert.SourceMac) ? null : alert.SourceMac.Trim();
        alert.SourceIp = string.IsNullOrWhiteSpace(alert.SourceIp) ? null : alert.SourceIp.Trim();

        // Check if there is an existing alert with same Title, Severity, SourceIp, and SourceMac
        var existingAlert = await connection.QueryFirstOrDefaultAsync<SecurityAlert>(@"
            SELECT * FROM SecurityAlerts 
            WHERE Title = @Title 
              AND Severity = @Severity
              AND (SourceMac = @SourceMac OR (SourceMac IS NULL AND @SourceMac IS NULL))
              AND (SourceIp = @SourceIp OR (SourceIp IS NULL AND @SourceIp IS NULL))
            ORDER BY Timestamp DESC
            LIMIT 1",
            new { 
                alert.Title, 
                alert.Severity, 
                SourceMac = alert.SourceMac, 
                SourceIp = alert.SourceIp 
            }
        );

        if (existingAlert != null)
        {
            // Aggregation: Update count, timestamp, description, and return the existing Alert's ID
            alert.Id = existingAlert.Id;
            alert.Count = existingAlert.Count + 1;
            alert.IsRead = false;

            await connection.ExecuteAsync(@"
                UPDATE SecurityAlerts 
                SET Timestamp = @Timestamp, 
                    Count = @Count,
                    IsRead = 0,
                    Description = @Description
                WHERE Id = @Id",
                alert
            );
        }
        else
        {
            // Insert new alert (ID is auto-generated, we can read it back to keep in-memory sync correct)
            var id = await connection.QuerySingleAsync<int>(@"
                INSERT INTO SecurityAlerts (Timestamp, Severity, Title, Description, SourceIp, SourceMac, IsRead, Count)
                VALUES (@Timestamp, @Severity, @Title, @Description, @SourceIp, @SourceMac, @IsRead, @Count);
                SELECT last_insert_rowid();",
                alert
            );
            alert.Id = id;
        }
    }

    public async Task MarkAlertAsReadAsync(int alertId)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();
        
        // Find the alert to get its grouping properties
        var alert = await connection.QueryFirstOrDefaultAsync<SecurityAlert>(
            "SELECT * FROM SecurityAlerts WHERE Id = @Id",
            new { Id = alertId }
        );
        
        if (alert != null)
        {
            await connection.ExecuteAsync(@"
                UPDATE SecurityAlerts 
                SET IsRead = 1 
                WHERE Title = @Title 
                  AND Severity = @Severity 
                  AND (SourceIp = @SourceIp OR (SourceIp IS NULL AND @SourceIp IS NULL))
                  AND (SourceMac = @SourceMac OR (SourceMac IS NULL AND @SourceMac IS NULL))",
                alert
            );
        }
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
                DarkMode = @DarkMode,
                FailedLoginThresholdInfo = @FailedLoginThresholdInfo,
                FailedLoginThresholdWarning = @FailedLoginThresholdWarning,
                FailedLoginThresholdCritical = @FailedLoginThresholdCritical
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

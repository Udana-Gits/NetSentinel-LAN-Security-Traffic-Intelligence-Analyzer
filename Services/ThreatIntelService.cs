using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Serilog;

namespace NetSentinel.Services;

/// <summary>
/// Service to manage and query the threat intelligence blocklist database (DNS Sinkholing / Reputation Filtering).
/// Loads and updates domains from local storage and online providers like Abuse.ch URLHaus.
/// </summary>
public class ThreatIntelService
{
    private readonly ILogger _logger;
    private readonly string _blocklistPath;
    private readonly HashSet<string> _blockedDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private bool _isUpdating;
    private bool _isLoaded;

    /// <summary>
    /// Total number of loaded blocked domains
    /// </summary>
    public int BlocklistCount
    {
        get
        {
            lock (_lock)
            {
                return _blockedDomains.Count;
            }
        }
    }

    /// <summary>
    /// Time when the blocklist file was last updated
    /// </summary>
    public DateTime LastUpdated { get; private set; }

    /// <summary>
    /// Indicates if a download/update is currently in progress
    /// </summary>
    public bool IsUpdating
    {
        get => _isUpdating;
        private set
        {
            _isUpdating = value;
            StatusChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>
    /// Indicates if the blocklist has been successfully loaded into memory
    /// </summary>
    public bool IsLoaded
    {
        get => _isLoaded;
        private set => _isLoaded = value;
    }

    /// <summary>
    /// Event raised when the blocklist count, update state, or timestamps change
    /// </summary>
    public event EventHandler? StatusChanged;

    // Built-in seed domains for testing and immediate validation
    private static readonly string[] SeedDomains = new[]
    {
        "malware-test.net",
        "phishing-test.org",
        "cc-test-server.xyz",
        "example-malicious.com",
        "urlhaus-test.abuse.ch",
        "abuse.ch"
    };

    public ThreatIntelService(ILogger logger)
    {
        _logger = logger;
        
        var appDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "NetSentinel"
        );
        _blocklistPath = Path.Combine(appDataFolder, "blocklist.txt");
    }

    /// <summary>
    /// Loads the blocklist from local disk, creating a seed file if none exists.
    /// </summary>
    public async Task LoadBlocklistAsync()
    {
        try
        {
            if (!File.Exists(_blocklistPath))
            {
                _logger.Information("Blocklist file not found. Creating with seed domains...");
                await CreateSeedBlocklistAsync();
            }

            await LoadFromFileAsync();
            _isLoaded = true;
            _logger.Information("Threat intelligence blocklist loaded successfully with {Count} domains.", BlocklistCount);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to load threat intelligence blocklist");
        }
    }

    private async Task CreateSeedBlocklistAsync()
    {
        try
        {
            var dir = Path.GetDirectoryName(_blocklistPath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var content = "# NetSentinel Threat Intelligence Seed Blocklist\n" +
                          "# Created: " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC\n" +
                          string.Join("\n", SeedDomains.Select(d => $"127.0.0.1\t{d}"));
            
            await File.WriteAllTextAsync(_blocklistPath, content);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to create seed blocklist file");
        }
    }

    private async Task LoadFromFileAsync()
    {
        if (!File.Exists(_blocklistPath)) return;

        try
        {
            var lines = await File.ReadAllLinesAsync(_blocklistPath);
            var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                    continue;

                var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 1)
                {
                    var domain = parts[0].Trim().ToLowerInvariant();
                    if (IsValidDomain(domain))
                    {
                        domains.Add(domain);
                    }
                }
                else if (parts.Length >= 2)
                {
                    var first = parts[0].Trim();
                    if (first == "127.0.0.1" || first == "0.0.0.0" || IPAddress.TryParse(first, out _))
                    {
                        var domain = parts[1].Trim().ToLowerInvariant();
                        if (IsValidDomain(domain))
                        {
                            domains.Add(domain);
                        }
                    }
                    else
                    {
                        var domain = parts[0].Trim().ToLowerInvariant();
                        if (IsValidDomain(domain))
                        {
                            domains.Add(domain);
                        }
                    }
                }
            }

            lock (_lock)
            {
                _blockedDomains.Clear();
                foreach (var d in domains)
                {
                    _blockedDomains.Add(d);
                }
            }

            LastUpdated = File.GetLastWriteTime(_blocklistPath);
            StatusChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error reading blocklist file from {Path}", _blocklistPath);
        }
    }

    private bool IsValidDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;
        if (domain.Length < 3) return false;
        if (domain.Contains('/') || domain.Contains(':') || domain.Contains('@') || domain.Contains('?')) return false;
        return domain.Contains('.');
    }

    /// <summary>
    /// Downloads the updated hosts list from Abuse.ch URLHaus, parses and loads it.
    /// </summary>
    public async Task<bool> UpdateBlocklistAsync()
    {
        if (IsUpdating) return false;

        IsUpdating = true;
        _logger.Information("Downloading updated threat intelligence blocklist from Abuse.ch URLHaus...");

        try
        {
            using var client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(30);
            
            var response = await client.GetAsync("https://urlhaus.abuse.ch/downloads/hostfile/");
            if (!response.IsSuccessStatusCode)
            {
                _logger.Warning("Failed to download blocklist. HTTP Status: {Status}", response.StatusCode);
                IsUpdating = false;
                return false;
            }

            var content = await response.Content.ReadAsStringAsync();
            
            // Prepend our seed domains to guarantee they are always available for local testing
            var header = "# NetSentinel Threat Intelligence Blocklist (With seed domains)\n" +
                         "# Updated: " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC\n";
            var seedSection = "\n# Seed Test Domains\n" + string.Join("\n", SeedDomains.Select(d => $"127.0.0.1\t{d}")) + "\n\n";

            await File.WriteAllTextAsync(_blocklistPath, header + seedSection + content);
            
            await LoadFromFileAsync();
            _logger.Information("Threat intelligence blocklist successfully updated. Count: {Count}", BlocklistCount);
            IsUpdating = false;
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error updating threat intelligence blocklist");
            IsUpdating = false;
            return false;
        }
    }

    /// <summary>
    /// Checks if the query domain or any of its parent domains matches the blocklist.
    /// </summary>
    public bool IsMalicious(string domain)
    {
        if (string.IsNullOrEmpty(domain))
            return false;

        var normalizedDomain = domain.Trim().ToLowerInvariant();

        lock (_lock)
        {
            // Direct match
            if (_blockedDomains.Contains(normalizedDomain))
                return true;

            // Check parent levels (e.g., deep.sub.domain.com -> domain.com)
            var parts = normalizedDomain.Split('.');
            for (int i = 1; i < parts.Length - 1; i++)
            {
                var parentDomain = string.Join(".", parts.Skip(i));
                if (_blockedDomains.Contains(parentDomain))
                    return true;
            }
        }

        return false;
    }

    // Direct parser dependency
    private static class IPAddress
    {
        public static bool TryParse(string ip, out System.Net.IPAddress? address)
        {
            return System.Net.IPAddress.TryParse(ip, out address);
        }
    }
}

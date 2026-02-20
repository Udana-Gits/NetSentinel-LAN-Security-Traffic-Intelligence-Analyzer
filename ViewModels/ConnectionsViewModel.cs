using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Messages;
using Serilog;

namespace NetSentinel.ViewModels;

/// <summary>
/// ViewModel for the connections view
/// </summary>
public partial class ConnectionsViewModel : ObservableObject
{
    private readonly ILogger _logger;
    private readonly ConnectionMonitor _connectionMonitor;

    [ObservableProperty]
    private int _totalConnections;

    [ObservableProperty]
    private int _tcpConnections;

    [ObservableProperty]
    private int _udpListeners;

    [ObservableProperty]
    private int _establishedConnections;

    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private string _selectedProtocol = "All";

    public ObservableCollection<NetworkConnection> Connections { get; set; }
    private readonly ObservableCollection<NetworkConnection> _allConnections;

    public string[] ProtocolFilters { get; } = { "All", "TCP", "UDP" };

    public ConnectionsViewModel(ILogger logger, ConnectionMonitor connectionMonitor)
    {
        _logger = logger;
        _connectionMonitor = connectionMonitor;

        Connections = new ObservableCollection<NetworkConnection>();
        _allConnections = new ObservableCollection<NetworkConnection>();

        _connectionMonitor.ConnectionsUpdated += OnConnectionsUpdated;

        // Register for global refresh messages
        WeakReferenceMessenger.Default.Register<RefreshConnectionsMessage>(this, (r, m) => HandleRefreshMessage());
    }

    /// <summary>
    /// Handles refresh message from global refresh command
    /// </summary>
    private void HandleRefreshMessage()
    {
        _logger.Information("ConnectionsViewModel received refresh message");
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Refresh();
        });
    }

    private void OnConnectionsUpdated(object? sender, ConnectionsUpdatedEventArgs e)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            _allConnections.Clear();
            foreach (var conn in e.Connections.OrderBy(c => c.ProcessName))
            {
                _allConnections.Add(conn);
            }

            UpdateStatistics(e.Connections);
            ApplyFilters();
        });
    }

    [RelayCommand]
    private void Refresh()
    {
        // Connections are automatically refreshed by the monitor
        var connections = _connectionMonitor.ActiveConnections;
        
        Application.Current?.Dispatcher.Invoke(() =>
        {
            _allConnections.Clear();
            foreach (var conn in connections)
            {
                _allConnections.Add(conn);
            }

            UpdateStatistics(connections);
            ApplyFilters();
        });
    }

    partial void OnFilterTextChanged(string value)
    {
        ApplyFilters();
    }

    partial void OnSelectedProtocolChanged(string value)
    {
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Connections.Clear();

            var filtered = _allConnections.AsEnumerable();

            // Protocol filter
            if (SelectedProtocol != "All")
            {
                filtered = filtered.Where(c => c.Protocol == SelectedProtocol);
            }

            // Text filter
            if (!string.IsNullOrWhiteSpace(FilterText))
            {
                filtered = filtered.Where(c =>
                    c.LocalAddress.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                    c.RemoteAddress.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                    c.ProcessName.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
                    c.LocalPort.ToString().Contains(FilterText) ||
                    c.RemotePort.ToString().Contains(FilterText)
                );
            }

            foreach (var conn in filtered)
            {
                Connections.Add(conn);
            }
        });
    }

    private void UpdateStatistics(System.Collections.Generic.List<NetworkConnection> connections)
    {
        TotalConnections = connections.Count;
        TcpConnections = connections.Count(c => c.Protocol == "TCP" && c.State != "LISTENING");
        UdpListeners = connections.Count(c => c.Protocol == "UDP");
        EstablishedConnections = connections.Count(c => c.State == "ESTABLISHED");
    }
}

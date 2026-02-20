using System.Windows;

namespace NetSentinel;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        
        // Update maximize button icon based on window state
        this.StateChanged += (s, e) => UpdateMaximizeButtonIcon();
    }
    
    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        this.WindowState = WindowState.Minimized;
    }
    
    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
    {
        if (this.WindowState == WindowState.Maximized)
        {
            this.WindowState = WindowState.Normal;
        }
        else
        {
            this.WindowState = WindowState.Maximized;
        }
        UpdateMaximizeButtonIcon();
    }
    
    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        this.Close();
    }
    
    private void UpdateMaximizeButtonIcon()
    {
        if (MaximizeButton != null)
        {
            // E922 = Maximize icon, E923 = Restore icon
            MaximizeButton.Content = this.WindowState == WindowState.Maximized ? "\uE923" : "\uE922";
        }
    }
}

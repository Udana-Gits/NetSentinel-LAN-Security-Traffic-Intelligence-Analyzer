using System.Windows.Controls;
using System;
using System.Globalization;
using System.Windows.Data;

namespace NetSentinel.UI;

public partial class DevicesView : UserControl
{
    public DevicesView()
    {
        InitializeComponent();
    }
}

public class BoolToStringConverter : IValueConverter
{
    public string TrueValue { get; set; } = "True";
    public string FalseValue { get; set; } = "False";

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue)
        {
            return boolValue ? TrueValue : FalseValue;
        }
        return FalseValue;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

using System;
using System.Collections.Generic;

namespace NetSentinel.Utils;

/// <summary>
/// Provides MAC address vendor lookup functionality using OUI (Organizationally Unique Identifier)
/// </summary>
public static class OUILookup
{
    private static readonly Dictionary<string, string> _ouiDatabase = new()
    {
        // Major vendors (OUI prefix -> Vendor name)
        { "00:00:0C", "Cisco Systems" },
        { "00:01:42", "Cisco Systems" },
        { "00:03:47", "Intel Corporate" },
        { "00:0A:95", "Apple Inc." },
        { "00:0D:93", "Apple Inc." },
        { "00:13:72", "Dell Inc." },
        { "00:14:22", "Dell Inc." },
        { "00:15:5D", "Microsoft Corporation" },
        { "00:16:CB", "Apple Inc." },
        { "00:17:F2", "Apple Inc." },
        { "00:19:E3", "Apple Inc." },
        { "00:1B:63", "Apple Inc." },
        { "00:1C:B3", "Apple Inc." },
        { "00:1D:4F", "Apple Inc." },
        { "00:1E:52", "Apple Inc." },
        { "00:1F:5B", "Apple Inc." },
        { "00:21:E9", "Dell Inc." },
        { "00:22:19", "Dell Inc." },
        { "00:23:24", "Apple Inc." },
        { "00:23:32", "Apple Inc." },
        { "00:23:DF", "Apple Inc." },
        { "00:24:36", "Dell Inc." },
        { "00:25:00", "Apple Inc." },
        { "00:25:4B", "Apple Inc." },
        { "00:25:BC", "Apple Inc." },
        { "00:26:08", "Apple Inc." },
        { "00:26:B0", "Apple Inc." },
        { "00:26:BB", "Apple Inc." },
        { "00:30:65", "Apple Inc." },
        { "00:3E:E1", "Apple Inc." },
        { "00:50:56", "VMware Inc." },
        { "00:50:F2", "Microsoft Corporation" },
        { "00:C0:CA", "Cisco Systems" },
        { "08:00:07", "Apple Inc." },
        { "08:00:20", "Sun Microsystems" },
        { "10:00:5A", "IBM Corp." },
        { "10:DD:B1", "Apple Inc." },
        { "14:10:9F", "Apple Inc." },
        { "18:3E:EF", "Dell Inc." },
        { "18:65:90", "Apple Inc." },
        { "18:E8:29", "Dell Inc." },
        { "1C:87:2C", "Dell Inc." },
        { "20:C9:D0", "Apple Inc." },
        { "24:A0:74", "Apple Inc." },
        { "24:AB:81", "Apple Inc." },
        { "28:6A:BA", "Dell Inc." },
        { "28:CF:E9", "Apple Inc." },
        { "2C:F0:EE", "Dell Inc." },
        { "30:3A:64", "Dell Inc." },
        { "34:17:EB", "Apple Inc." },
        { "34:36:3B", "Apple Inc." },
        { "38:C9:86", "Apple Inc." },
        { "3C:07:54", "Apple Inc." },
        { "3C:15:C2", "Apple Inc." },
        { "40:30:04", "Apple Inc." },
        { "40:6C:8F", "Apple Inc." },
        { "44:2A:60", "Apple Inc." },
        { "44:D9:E7", "Apple Inc." },
        { "48:44:F7", "Dell Inc." },
        { "48:D7:05", "Dell Inc." },
        { "4C:32:75", "Apple Inc." },
        { "50:BC:96", "Apple Inc." },
        { "54:26:96", "Apple Inc." },
        { "54:E4:3A", "Apple Inc." },
        { "58:55:CA", "Apple Inc." },
        { "5C:95:AE", "Apple Inc." },
        { "5C:F9:38", "Dell Inc." },
        { "60:03:08", "Apple Inc." },
        { "60:C5:47", "Apple Inc." },
        { "64:20:0C", "Apple Inc." },
        { "68:5B:35", "Apple Inc." },
        { "68:96:7B", "Apple Inc." },
        { "6C:40:08", "Apple Inc." },
        { "6C:94:66", "Apple Inc." },
        { "70:56:81", "Apple Inc." },
        { "70:CD:60", "Apple Inc." },
        { "74:E1:B6", "Dell Inc." },
        { "78:31:C1", "Apple Inc." },
        { "78:7B:8A", "Apple Inc." },
        { "7C:11:CB", "Apple Inc." },
        { "7C:D1:C3", "Apple Inc." },
        { "80:00:0B", "Cisco Systems" },
        { "80:E6:50", "Apple Inc." },
        { "84:38:35", "Apple Inc." },
        { "84:85:06", "Apple Inc." },
        { "84:89:AD", "Apple Inc." },
        { "88:53:95", "Apple Inc." },
        { "88:66:5A", "Apple Inc." },
        { "88:E8:7F", "Apple Inc." },
        { "8C:58:77", "Apple Inc." },
        { "8C:85:90", "Apple Inc." },
        { "90:27:E4", "Apple Inc." },
        { "90:72:40", "Apple Inc." },
        { "94:E9:6A", "Apple Inc." },
        { "98:01:A7", "Apple Inc." },
        { "98:D6:BB", "Apple Inc." },
        { "98:E0:D9", "Apple Inc." },
        { "9C:20:7B", "Apple Inc." },
        { "9C:FC:E8", "Apple Inc." },
        { "A0:99:9B", "Apple Inc." },
        { "A4:5E:60", "Apple Inc." },
        { "A4:83:E7", "Apple Inc." },
        { "A4:B1:97", "Dell Inc." },
        { "A8:20:66", "Apple Inc." },
        { "A8:60:B6", "Apple Inc." },
        { "A8:66:7F", "Apple Inc." },
        { "AC:87:A3", "Apple Inc." },
        { "AC:BC:32", "Apple Inc." },
        { "AC:DE:48", "Apple Inc." },
        { "B0:34:95", "Apple Inc." },
        { "B0:65:BD", "Apple Inc." },
        { "B4:18:D1", "Apple Inc." },
        { "B4:8B:19", "Dell Inc." },
        { "B4:F0:AB", "Apple Inc." },
        { "B8:09:8A", "Apple Inc." },
        { "B8:17:C2", "Apple Inc." },
        { "B8:27:EB", "Raspberry Pi Foundation" },
        { "B8:41:A4", "Dell Inc." },
        { "B8:C7:5D", "Apple Inc." },
        { "B8:E8:56", "Apple Inc." },
        { "BC:3B:AF", "Apple Inc." },
        { "BC:52:B7", "Apple Inc." },
        { "BC:9F:EF", "Apple Inc." },
        { "C0:63:94", "Dell Inc." },
        { "C4:2C:03", "Apple Inc." },
        { "C8:2A:14", "Apple Inc." },
        { "C8:B5:AD", "Apple Inc." },
        { "C8:BC:C8", "Apple Inc." },
        { "CC:25:EF", "Apple Inc." },
        { "CC:29:F5", "Apple Inc." },
        { "CC:78:5F", "Apple Inc." },
        { "D0:03:4B", "Apple Inc." },
        { "D0:25:98", "Apple Inc." },
        { "D0:E1:40", "Apple Inc." },
        { "D4:9A:20", "Apple Inc." },
        { "D8:30:62", "Apple Inc." },
        { "D8:9E:3F", "Apple Inc." },
        { "D8:A2:5E", "Apple Inc." },
        { "D8:BB:2C", "Apple Inc." },
        { "DC:2B:61", "Apple Inc." },
        { "DC:86:D8", "Raspberry Pi Trading Ltd" },
        { "DC:A9:04", "Google Inc." },
        { "E0:AC:CB", "Apple Inc." },
        { "E0:F8:47", "Apple Inc." },
        { "E4:25:E7", "Apple Inc." },
        { "E4:CE:8F", "Apple Inc." },
        { "E8:06:88", "Apple Inc." },
        { "E8:80:2E", "Apple Inc." },
        { "EC:35:86", "Apple Inc." },
        { "EC:85:2F", "Apple Inc." },
        { "F0:18:98", "Apple Inc." },
        { "F0:DB:E2", "Apple Inc." },
        { "F0:DC:E2", "Apple Inc." },
        { "F4:0F:24", "Dell Inc." },
        { "F4:1B:A1", "Dell Inc." },
        { "F4:F5:D8", "Google Inc." },
        { "F8:1E:DF", "Apple Inc." },
        { "FC:25:3F", "Apple Inc." },
        { "FC:FC:48", "Apple Inc." },
    };

    /// <summary>
    /// Looks up the vendor name for a given MAC address
    /// </summary>
    /// <param name="macAddress">MAC address in any common format</param>
    /// <returns>Vendor name or "Unknown Vendor" if not found</returns>
    public static string GetVendor(string macAddress)
    {
        if (string.IsNullOrWhiteSpace(macAddress))
            return "Unknown Vendor";

        try
        {
            // Normalize MAC address to XX:XX:XX format for OUI
            var cleaned = macAddress.Replace("-", ":").Replace(".", ":").ToUpper();
            var oui = string.Join(":", cleaned.Split(':')[..3]);

            if (_ouiDatabase.TryGetValue(oui, out var vendor))
                return vendor;

            return "Unknown Vendor";
        }
        catch
        {
            return "Unknown Vendor";
        }
    }

    /// <summary>
    /// Validates MAC address format
    /// </summary>
    public static bool IsValidMacAddress(string macAddress)
    {
        if (string.IsNullOrWhiteSpace(macAddress))
            return false;

        var cleaned = macAddress.Replace("-", "").Replace(":", "").Replace(".", "");
        return cleaned.Length == 12 && System.Text.RegularExpressions.Regex.IsMatch(cleaned, "^[0-9A-Fa-f]+$");
    }
}

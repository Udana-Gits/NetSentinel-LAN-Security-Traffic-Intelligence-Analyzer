using System;
using NetSentinel.Data;

namespace NetSentinel.Utils;

/// <summary>
/// Detects device type based on vendor, hostname, and MAC address
/// </summary>
public static class DeviceTypeDetector
{
    public static DeviceType DetectDeviceType(string vendor, string? hostname, string macAddress)
    {
        var vendorLower = vendor?.ToLowerInvariant() ?? "";
        var hostnameLower = hostname?.ToLowerInvariant() ?? "";

        // First check hostname patterns as they can be more specific
        if (!string.IsNullOrWhiteSpace(hostnameLower))
        {
            // Mobile device patterns in hostname
            if (hostnameLower.Contains("pixel") && (hostnameLower.Contains("pro") || hostnameLower.Contains("-9-") || hostnameLower.Contains("-8-")))
            {
                return DeviceType.Mobile;
            }
            if (hostnameLower.Contains("iphone") || hostnameLower.Contains("android"))
            {
                return DeviceType.Mobile;
            }
            if (hostnameLower.Contains("ipad"))
            {
                return DeviceType.Tablet;
            }
        }

        // Router/Gateway detection
        if (vendorLower.Contains("cisco") || vendorLower.Contains("netgear") || 
            vendorLower.Contains("asus") || vendorLower.Contains("tp-link") ||
            vendorLower.Contains("d-link") || vendorLower.Contains("linksys") ||
            vendorLower.Contains("ubiquiti") || vendorLower.Contains("mikrotik") ||
            hostnameLower.Contains("router") || hostnameLower.Contains("gateway") ||
            hostnameLower.Contains("ap-") || hostnameLower.Contains("access"))
        {
            return DeviceType.Router;
        }

        // Mobile device detection (Apple, Samsung, etc.)
        if (vendorLower.Contains("apple"))
        {
            if (hostnameLower.Contains("ipad")) return DeviceType.Tablet;
            if (hostnameLower.Contains("iphone")) return DeviceType.Mobile;
            if (hostnameLower.Contains("macbook") || hostnameLower.Contains("mac")) return DeviceType.Laptop;
            if (hostnameLower.Contains("imac")) return DeviceType.Desktop;
            // Default Apple devices to mobile
            return DeviceType.Mobile;
        }
        
        if (vendorLower.Contains("samsung"))
        {
            if (hostnameLower.Contains("galaxy") && hostnameLower.Contains("tab")) return DeviceType.Tablet;
            if (hostnameLower.Contains("tv")) return DeviceType.SmartTV;
            // Most Samsung devices are mobile
            return DeviceType.Mobile;
        }
        
        if (vendorLower.Contains("xiaomi") || vendorLower.Contains("huawei") ||
            vendorLower.Contains("oppo") || vendorLower.Contains("vivo") ||
            vendorLower.Contains("oneplus") || vendorLower.Contains("realme") ||
            vendorLower.Contains("motorola") || vendorLower.Contains("nokia"))
        {
            return DeviceType.Mobile;
        }
        
        if (vendorLower.Contains("google"))
        {
            if (hostnameLower.Contains("pixel")) return DeviceType.Mobile;
            if (hostnameLower.Contains("nest") || hostnameLower.Contains("home")) return DeviceType.IoT;
            if (hostnameLower.Contains("chromecast")) return DeviceType.SmartTV;
        }

        // Tablet detection
        if (hostnameLower.Contains("ipad") || hostnameLower.Contains("tablet") ||
            hostnameLower.Contains("tab-"))
        {
            return DeviceType.Tablet;
        }

        // Smart TV detection
        if (vendorLower.Contains("sony") || vendorLower.Contains("lg") ||
            vendorLower.Contains("roku") || vendorLower.Contains("amazon") ||
            hostnameLower.Contains("tv") || hostnameLower.Contains("firetv") ||
            hostnameLower.Contains("chromecast") || hostnameLower.Contains("bravia"))
        {
            return DeviceType.SmartTV;
        }

        // Printer detection
        if (vendorLower.Contains("hp") || vendorLower.Contains("canon") || 
            vendorLower.Contains("epson") || vendorLower.Contains("brother") ||
            hostnameLower.Contains("printer") || hostnameLower.Contains("print"))
        {
            return DeviceType.Printer;
        }

        // Gaming Console detection
        if (vendorLower.Contains("sony") || vendorLower.Contains("microsoft") ||
            vendorLower.Contains("nintendo") ||
            hostnameLower.Contains("playstation") || hostnameLower.Contains("ps3") || 
            hostnameLower.Contains("ps4") || hostnameLower.Contains("ps5") ||
            hostnameLower.Contains("xbox") || hostnameLower.Contains("switch"))
        {
            return DeviceType.Console;
        }

        // IoT device detection
        if (vendorLower.Contains("ring") || vendorLower.Contains("nest") ||
            vendorLower.Contains("philips") || vendorLower.Contains("ecobee") ||
            vendorLower.Contains("tuya") || vendorLower.Contains("shelly") ||
            hostnameLower.Contains("iot") || hostnameLower.Contains("smart") ||
            hostnameLower.Contains("alexa") || hostnameLower.Contains("echo") ||
            hostnameLower.Contains("sensor") || hostnameLower.Contains("camera"))
        {
            return DeviceType.IoT;
        }

        // Laptop vs Desktop detection
        if (vendorLower.Contains("dell") || vendorLower.Contains("lenovo") ||
            vendorLower.Contains("asus") || vendorLower.Contains("acer") ||
            vendorLower.Contains("msi") || vendorLower.Contains("toshiba"))
        {
            // Check if hostname indicates laptop
            if (hostnameLower.Contains("laptop") || hostnameLower.Contains("notebook"))
            {
                return DeviceType.Laptop;
            }
            // Check if hostname indicates desktop
            if (hostnameLower.Contains("desktop") || hostnameLower.Contains("pc"))
            {
                return DeviceType.Desktop;
            }
            // Dell, Lenovo, Asus typically make laptops
            return DeviceType.Laptop;
        }

        // Intel/Realtek network cards - check hostname
        if (vendorLower.Contains("intel") || vendorLower.Contains("realtek") ||
            vendorLower.Contains("broadcom") || vendorLower.Contains("qualcomm"))
        {
            if (hostnameLower.Contains("desktop") || hostnameLower.Contains("pc"))
            {
                return DeviceType.Desktop;
            }
            if (hostnameLower.Contains("laptop") || hostnameLower.Contains("notebook"))
            {
                return DeviceType.Laptop;
            }
            // Default to Desktop for generic network cards
            return DeviceType.Desktop;
        }

        // Windows PC hostname patterns
        if (hostnameLower.Contains("desktop") || hostnameLower.Contains("-pc"))
        {
            return DeviceType.Desktop;
        }
        if (hostnameLower.Contains("laptop") || hostnameLower.Contains("notebook"))
        {
            return DeviceType.Laptop;
        }
        
        // Additional hostname-based detection for unknown vendors
        if (hostnameLower.Contains("android") || hostnameLower.Contains("phone"))
        {
            return DeviceType.Mobile;
        }
        if (hostnameLower.Contains("server") || hostnameLower.Contains("nas"))
        {
            return DeviceType.Desktop;
        }
        if (hostnameLower.Contains("wifi") || hostnameLower.Contains("router"))
        {
            return DeviceType.Router;
        }
        
        // If hostname contains a recognizable pattern like "Pixel-9-Pro", detect as mobile
        if (hostnameLower.Contains("pixel"))
        {
            return DeviceType.Mobile;
        }

        return DeviceType.Unknown;
    }
}

using System;
using System.Security.Principal;

namespace NetSentinel.Utils;

/// <summary>
/// Checks if the application is running with administrator privileges
/// </summary>
public static class AdminChecker
{
    /// <summary>
    /// Determines whether the current process is running with administrator privileges
    /// </summary>
    public static bool IsRunningAsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}

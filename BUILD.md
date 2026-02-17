# Build Instructions for NetSentinel

## Prerequisites

1. **Visual Studio 2022** or **Visual Studio Code** with C# extension
2. **.NET 8 SDK** - Download from https://dotnet.microsoft.com/download/dotnet/8.0
3. **Npcap** - Download from https://npcap.com/ (required for packet capture)

## Build Steps

### Using Visual Studio 2022

1. **Open the Project**
   ```
   Open Visual Studio 2022
   File -> Open -> Project/Solution
   Navigate to NetSentinel.csproj and open it
   ```

2. **Restore NuGet Packages**
   ```
   Right-click on the solution in Solution Explorer
   Select "Restore NuGet Packages"
   Wait for all packages to download
   ```

3. **Build the Solution**
   ```
   Build -> Build Solution (Ctrl+Shift+B)
   Or select Release configuration for optimized build:
   Build -> Configuration Manager -> Select "Release"
   Build -> Rebuild Solution
   ```

4. **Run the Application**
   ```
   Press F5 to run with debugging
   Or Ctrl+F5 to run without debugging
   The application must run as Administrator for full functionality
   ```

### Using .NET CLI (Command Line)

1. **Navigate to Project Directory**
   ```bash
   cd "c:\Users\udana\Desktop\KDU\5 - Projects\.NET\NetSentinel"
   ```

2. **Restore Dependencies**
   ```bash
   dotnet restore
   ```

3. **Build the Project**
   ```bash
   # Debug build
   dotnet build

   # Release build (recommended for distribution)
   dotnet build --configuration Release
   ```

4. **Run the Application**
   ```bash
   # Debug build
   dotnet run

   # Release build
   dotnet run --configuration Release
   ```

5. **Publish Self-Contained Application**
   ```bash
   # Windows x64 single file
   dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true

   # Output will be in: bin\Release\net8.0-windows\win-x64\publish\
   ```

## Post-Build Steps

### First-Time Setup

1. **Install Npcap**
   - Download from https://npcap.com/
   - Run the installer
   - **Important:** Check "Install Npcap in WinPcap API-compatible Mode"
   - Restart your computer after installation

2. **Configure Windows Firewall**
   ```
   Allow NetSentinel.exe through Windows Firewall
   Windows Security -> Firewall & network protection -> Allow an app
   Add NetSentinel.exe
   ```

3. **Run as Administrator**
   - Packet capture features require administrator privileges
   - Right-click NetSentinel.exe -> Properties
   - Compatibility tab -> Check "Run this program as an administrator"
   - Click Apply and OK

### Testing the Build

1. Launch NetSentinel
2. Accept the Ethical Usage Agreement
3. Verify Dashboard shows network information
4. Navigate to Devices tab and click "Scan Network"
5. Check Connections tab for active connections
6. Review Settings to configure preferences

## Build Output Locations

### Debug Build
```
bin\Debug\net8.0-windows\NetSentinel.exe
```

### Release Build
```
bin\Release\net8.0-windows\NetSentinel.exe
```

### Published Self-Contained
```
bin\Release\net8.0-windows\win-x64\publish\NetSentinel.exe
```

## Common Build Issues

### Issue: NuGet package restore fails
**Solution:**
```bash
# Clear NuGet cache
dotnet nuget locals all --clear

# Restore again
dotnet restore
```

### Issue: SharpPcap/PacketDotNet errors
**Solution:**
- Ensure Npcap is installed
- Check that Npcap is in WinPcap compatibility mode
- Add Npcap DLL path to system PATH if needed

### Issue: LiveCharts2 not found
**Solution:**
```bash
# Manually install LiveCharts2
dotnet add package LiveChartsCore.SkiaSharpView.WPF --version 2.0.0-rc2
```

### Issue: "Type or namespace not found"
**Solution:**
- Clean and rebuild solution
```bash
dotnet clean
dotnet build
```

### Issue: Application manifest errors
**Solution:**
- Ensure app.manifest file exists and is configured correctly
- Verify it's set to request administrator privileges

## Optimization Tips

### For Smaller File Size
Remove unused NuGet packages and trim the application:
```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true
```

### For Better Performance
Use ReadyToRun compilation:
```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishReadyToRun=true
```

### For Debug Symbols
Include PDB files in release build:
```bash
dotnet build --configuration Release -p:DebugType=portable
```

## Distribution Checklist

Before distributing the application:

- [ ] Build in Release configuration
- [ ] Test all features (Dashboard, Devices, Connections, Alerts, Settings)
- [ ] Verify packet capture works (requires Npcap)
- [ ] Test on clean Windows installation
- [ ] Include README.md with installation instructions
- [ ] Include Npcap installation link
- [ ] Document administrator privilege requirement
- [ ] Include ethical usage notice
- [ ] Test database creation and migrations
- [ ] Verify log file creation
- [ ] Test export functionality (CSV)
- [ ] Check auto-start Windows registry modification

## Packaging for Distribution

### Create Installer (Optional)
Use tools like:
- **Inno Setup** - https://jrsoftware.org/isinfo.php
- **WiX Toolset** - https://wixtoolset.org/
- **Advanced Installer** - https://www.advancedinstaller.com/

### Zip Distribution
```bash
# Navigate to publish folder
cd bin\Release\net8.0-windows\win-x64\publish\

# Create zip (PowerShell)
Compress-Archive -Path * -DestinationPath NetSentinel-v1.0.0.zip
```

## Version Information

Current Version: **1.0.0**  
Build Date: **2026-02-17**  
Target Framework: **.NET 8**  
Platform: **Windows x64**

## Support

For build issues:
1. Check this document first
2. Review error messages in build output
3. Check .NET SDK version: `dotnet --version`
4. Verify NuGet packages are restored
5. Review log files in %AppData%\NetSentinel\logs\

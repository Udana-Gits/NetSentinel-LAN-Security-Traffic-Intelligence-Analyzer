# Security Policy for NetSentinel

## Reporting a Vulnerability

If you discover a security vulnerability in NetSentinel, please report it responsibly:

1. **Do NOT** create a public GitHub issue
2. Contact the development team privately
3. Provide detailed information about the vulnerability
4. Allow reasonable time for a fix to be developed and released

## Security Considerations

### Administrator Privileges
NetSentinel requires administrator privileges for packet capture functionality. This is necessary for:
- Accessing network interfaces at low level
- Capturing packets using Npcap/WinPcap
- Reading system network information

**Risk Mitigation:**
- The app.manifest explicitly requests administrator elevation
- Users are warned before installation
- All privileged operations are logged

### Network Data Collection
NetSentinel collects and stores:
- IP addresses of devices on the local network
- MAC addresses and vendor information
- Network traffic statistics
- Active connection information
- DNS queries (when packet capture is enabled)

**Data Protection:**
- All data is stored locally in SQLite database
- No data is transmitted to external servers
- Database files are stored in user's AppData folder
- Users can export and delete data at any time

### Packet Capture
When packet capture is enabled:
- Raw network packets are analyzed
- DNS queries are logged
- ARP packets are monitored
- Protocol statistics are collected

**Privacy Considerations:**
- Packet payload content is NOT stored
- Only metadata and statistics are retained
- Users control when capture is enabled
- Capture can be disabled in settings

### Ethical Usage Requirements
NetSentinel must only be used on:
- Networks you own
- Networks where you have explicit authorization

**Legal Compliance:**
- First-run agreement requires user consent
- Ethical usage notice is displayed prominently
- Application logs acceptance timestamp
- Clear warnings about unauthorized use

### Database Security
SQLite database at `%AppData%\NetSentinel\netsentinel.db`:
- Not encrypted by default
- Contains network topology information
- Readable by anyone with file system access
- Should be protected with Windows file permissions

**Recommendations:**
- Use Windows EFS encryption for AppData folder
- Regular backups of database
- Periodic cleanup of old data (configured in settings)

### Logging Security
Log files at `%AppData%\NetSentinel\logs\`:
- May contain IP addresses and network information
- Rotated daily, retained for 7 days by default
- Plain text format
- Should be protected from unauthorized access

**Best Practices:**
- Review logs periodically
- Delete logs containing sensitive information
- Use appropriate Windows file permissions

## Known Security Limitations

1. **No Encryption**
   - Database is not encrypted
   - Logs are plain text
   - Network data is stored unencrypted

2. **Local Storage**
   - All sensitive data in AppData folder
   - Vulnerable if system is compromised
   - No cloud backup or sync

3. **Admin Access**
   - Requires elevated privileges
   - Could be exploited by malware
   - Users must trust the application

4. **Packet Capture**
   - Can capture sensitive network traffic
   - Depends on Npcap driver security
   - May be detected by security software

## Secure Deployment Recommendations

### For Organizations
1. Code sign the executable
2. Deploy via managed distribution (SCCM, Intune)
3. Use Group Policy to control settings
4. Monitor usage through audit logs
5. Implement file system encryption
6. Regular security audits

### For Individual Users
1. Download only from trusted sources
2. Verify digital signatures before running
3. Run in isolated environment if testing
4. Use Windows Defender or antivirus
5. Keep Windows and .NET updated
6. Review application logs regularly

## Security Best Practices for Users

✅ **DO:**
- Run on networks you own or manage
- Use strong Windows account passwords
- Enable Windows Firewall
- Keep application updated
- Review security alerts regularly
- Export and backup important data

❌ **DON'T:**
- Use on unauthorized networks
- Share database files publicly
- Disable Windows security features
- Run on compromised systems
- Ignore security warnings
- Leave packet capture running continuously

## Compliance Considerations

### GDPR (if applicable in EU)
- Network device information may be personal data
- Implement data retention policies
- Provide data export capability (CSV)
- Allow data deletion (database cleanup)
- Inform users about data collection

### Other Regulations
- Computer Fraud and Abuse Act (CFAA) - US
- UK Computer Misuse Act
- Local cybersecurity laws

**Compliance Responsibility:**
- Users are responsible for legal compliance
- Application provides tools, not authorization
- Ethical usage agreement required

## Security Updates

Updates will be provided for:
- Critical security vulnerabilities
- Privilege escalation issues
- Data exposure risks
- Third-party library vulnerabilities

**Update Process:**
1. Security issue identified
2. Patch developed and tested
3. Release notes published
4. Users notified to update

## Third-Party Dependencies

Security of NetSentinel depends on:
- **SharpPcap** - Packet capture library
- **PacketDotNet** - Packet parsing
- **Npcap/WinPcap** - Windows drivers
- **SQLite** - Database engine
- **.NET Runtime** - Application framework

**Responsibility:**
- Monitor security advisories for all dependencies
- Update libraries when vulnerabilities are discovered
- Test updates before deployment

## Audit Logging

NetSentinel logs:
- Application startup/shutdown
- Network interface changes
- Security alert triggers
- User actions (scans, exports)
- Configuration changes
- Errors and exceptions

**Log Retention:**
- 7 days by default
- Configurable in code
- Automatic rotation

## Contact

For security concerns:
- Review this security policy
- Check for updates regularly
- Follow responsible disclosure practices

---

**Last Updated:** 2026-02-17  
**Version:** 1.0.0

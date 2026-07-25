# Firewall Privilege Escalation

## Problem

The Synergy Node Control Panel runs installer/orchestration steps that may need to configure firewall rules (`ufw`, `firewalld`, `iptables`). When those steps run from the desktop app, plain `sudo` cannot always prompt interactively.

## Solution

The installer scripts have been updated to intelligently handle privilege escalation:

1. **If running as root**: Commands execute directly
2. **If in interactive terminal**: Uses regular `sudo` (can prompt for password)
3. **If in GUI environment (DISPLAY set)**: Uses `pkexec` which shows a GUI password dialog
4. **Fallback**: Tries `sudo` (may work if password is cached)

This ensures firewall configuration can successfully run when executed from the GUI application.

## Optional: Enable Passwordless Sudo for Firewall Commands

If you want the firewall configuration to work automatically, you can configure passwordless sudo for specific firewall commands.

### For UFW (Ubuntu/Debian)

Add this to `/etc/sudoers.d/synergy-firewall` (use `sudo visudo -f /etc/sudoers.d/synergy-firewall`):

```
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/ufw
```

Or for a specific user:
```
yourusername ALL=(ALL) NOPASSWD: /usr/sbin/ufw
```

### For Firewalld (Fedora/RHEL/CentOS)

```
%sudo ALL=(ALL) NOPASSWD: /usr/bin/firewall-cmd
```

Or for a specific user:
```
yourusername ALL=(ALL) NOPASSWD: /usr/bin/firewall-cmd
```

### For iptables

```
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/iptables
```

Or for a specific user:
```
yourusername ALL=(ALL) NOPASSWD: /usr/sbin/iptables
```

## Alternative: Manual Firewall Configuration

If you prefer not to configure passwordless sudo, you can manually open the required ports:

1. Check which ports are needed in the node configuration
2. Open them using your firewall tool:
   - **UFW**: `sudo ufw allow <port>/tcp`
   - **Firewalld**: `sudo firewall-cmd --permanent --add-port=<port>/tcp && sudo firewall-cmd --reload`
   - **iptables**: `sudo iptables -A INPUT -p tcp --dport <port> -j ACCEPT`

## Verification

After setting up passwordless sudo, the installer scripts should run without authentication errors. The firewall rules will be configured automatically when nodes are started.

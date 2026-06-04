![deepshare](https://github.com/krack3nn/DeepShare/blob/d5daa7c8b8b7c099e53c47aa2ebfb99b3f76654a/meme.jpg)

## deepshare

Most SMB enumeration tools report share level permissions, the coarse Read/Write/Full Control setting at the share root. What they miss is that Windows enforces two completely separate permission layers:

**Share permissions** - one setting controlling access to the entire share root. This is what tools like nxc and smbmap report.

**NTFS permissions** - granular ACEs set per folder, per file, at every level of the directory tree. Completely independent from share permissions.

A share root can be READ only while a subfolder three levels deep grants full WRITE access via NTFS. No existing remote tool checks for that.

`DeepShare` empirically tests read, write, and delete permissions at every subdirectory level by actually attempting real operations - not by reading ACL entries, not by trusting what the root says.

It is also worth noting that deepshare is a wrapper around `smbclient`, which communicates directly at the raw SMB protocol level. Most tools enumerate shares through the `NetShareEnum` Windows API via named pipes (`srvsvc`, `samr`). These are commonly restricted in hardened environments through Group Policy and `RestrictAnonymous` registry keys. `smbclient` bypasses those API restrictions entirely, which means deepshare can enumerate and access shares in environments where API-based tools return `STATUS_ACCESS_DENIED`.

---

## About

- `smbclient`
- `awk`, `tr`, `sed` (standard on all Linux distros)

```bash
# Debian / Ubuntu / Kali
sudo apt install samba-common-bin

# Arch
sudo pacman -S smbclient

# Fedora / RHEL
sudo dnf install samba-client
```

---

## Installation

```bash
git clone https://github.com/krack3n/deepshare
cd deepshare
chmod +x deepshare.sh
```

Optionally add to PATH:
```bash
sudo cp deepshare.sh /usr/local/bin/deepshare
```

---

## Usage

```
Usage: deepshare -t <target> [OPTIONS]

Target:
  -t  --target    <IP|hostname|UNC|file>
  -s  --share     <share[/subpath]>
  -A  --auto      Auto-enumerate all accessible shares

Authentication:
  -u  --user      <username>
  -p  --pass      <password>
  -P  --prompt    Prompt for password interactively
  -H  --hash      <:NT or LM:NT>
  -d  --domain    <domain>
  -n  --null      Null session  (-u '' -p '' also works)
  -k  --kerberos  Kerberos via current ccache (requires FQDN)

Scan:
  -D  --depth     Max recursion depth      [Default: 5, Max: 10]
  -S  --sleep     Sleep between requests   [Default: 0, +jitter when set]
  -T  --timeout   Connection timeout       [Default: 10]
  -e  --ext       Flag files by extension  (e.g. pdf,kdbx,ps1 or all)
  -z  --no-write  Skip all write tests
  -L  --list      Root-level permissions only, no recursion
  -N  --spoof     NetBIOS workstation name [Default: random DESKTOP-XXXXXXXX]

Output:
  -f  --format    normal | json | csv      [Default: normal]
  -o  --output    Write output to file
```

---

## Examples

```bash
# Auto-enumerate all shares with domain credentials
deepshare -t 10.10.10.10 -A -u alice -p Pass123 -d CORP

# Null session - both forms work
deepshare -t 10.10.10.10 -A -n
deepshare -t 10.10.10.10 -A -u '' -p ''

# Pass-the-hash
deepshare -t 10.10.10.10 -s Data -u alice -H :aad3b435b51404eeaad3b435b51404ee

# Kerberos (requires KRB5CCNAME exported)
deepshare -t dc01.corp.local -s SYSVOL -k -d CORP.LOCAL

# Quick triage - root permissions only, no recursion
deepshare -t 10.10.10.10 -A -u alice -p Pass123 -L

# Read-only root check - zero writes
deepshare -t 10.10.10.10 -A -u alice -p Pass123 -L --no-write

# Scan a specific subfolder path
deepshare -t 10.10.10.10 -s Users/Public -u alice -p Pass123

# Hunt for sensitive files during traversal
deepshare -t 10.10.10.10 -A -u alice -p Pass123 --ext all

# Multiple targets from file, JSON output
deepshare -t hosts.txt -A -u alice -p Pass123 -f json -o results.json

# Rate limiting with jitter for quieter scanning
deepshare -t 10.10.10.10 -A -u alice -p Pass123 -S 2
```

---

## Output

```
deepshare  by krack3n

  Target     10.10.10.10
  Shares     Auto Discovery
  Auth       CORP/alice:Pass123
  NetBIOS    DESKTOP-3A9F21BC
  Timeout    10 Seconds
  Sleep      0s
  Format     Terminal

SMB  10.10.10.10  445  Departments Share  [READ]                   \
SMB  10.10.10.10  445  Departments Share  [READ][WRITE][DELETE]    Finance/Temp
SMB  10.10.10.10  445  Departments Share  [READ][WRITE]            IT/Scripts
SMB  10.10.10.10  445  Departments Share  [READ]                   HR
SMB  10.10.10.10  445  SYSVOL             [INSUFFICIENT PRIVILEGES] \
```

### Permission tags

| Tag | Meaning |
|---|---|
| `[READ]` | Directory listing confirmed |
| `[WRITE]` | File upload confirmed |
| `[DELETE]` | File deletion confirmed |
| `[READ][WRITE][DELETE]` | Full access |
| `[INSUFFICIENT PRIVILEGES]` | Authenticated but access denied |
| `[NO ACCESS]` | No read or write access |
| `[SHARE NOT FOUND]` | Share name does not exist on target |
| `[NULL SESSION DISABLED]` | Server rejected anonymous authentication |
| `[AUTH FAILED]` | Invalid credentials |
| `[UNREACHABLE]` | Host down or port 445 closed |

### File hunting

When `--ext` is used, matching files are flagged inline during traversal:

```
SMB  10.10.10.10  445  Data  [PDF File Found]    Finance/Q3_Report.pdf
SMB  10.10.10.10  445  Data  [KDBX File Found]   IT/passwords.kdbx
```

`--ext all` searches for: `kdbx kdb psafe3 pfx p12 pem key ppk pdf docx doc xlsx xls pptx ppt config conf cfg ini env xml yaml yml ps1 bat cmd sh vbs sql db sqlite bak`

---

## OpSec Considerations

deepshare generates real SMB traffic. Every subfolder means real connections, real file operations, real log entries. It is not silent.

What it does consider:

- Test artifacts use randomized names and are cleaned up immediately
- NetBIOS workstation name spoofing blends into normal domain traffic
- Configurable sleep with jitter avoids predictable request timing that scanner signatures look for
- `--no-write` mode limits all operations to read-only with zero writes touching the target
- `-L --no-write` provides the quietest possible scan - one `ls` per share, no uploads

---

## Disclaimer

deepshare is intended for authorized penetration testing and security assessments only. Use against systems you do not have explicit permission to test is illegal. The author is not responsible for misuse.

---

## Author

krack3n

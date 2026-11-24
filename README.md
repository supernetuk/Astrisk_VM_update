# Astrisk_VM_update

Security hardening for an Asterisk 22 PBX VM on AlmaLinux (DIDWW inbound → ElevenLabs AI agent).

**Developed by Ernest Tse** · Supernet UK Limited

## Run (on the VM, as root, connected over the public IP)

```bash
curl -fsSLo /root/harden-pbx1.sh https://raw.githubusercontent.com/supernetuk/Astrisk_VM_update/main/harden-pbx1.sh && ALLOWED_DIDS="441865679438" bash /root/harden-pbx1.sh 2>&1 | tee /root/harden.log
```

Verified version (only runs if the file matches the published SHA-256):

```bash
curl -fsSLo /root/harden-pbx1.sh https://raw.githubusercontent.com/supernetuk/Astrisk_VM_update/main/harden-pbx1.sh && echo "3e975d891013c646cec02959a0a18efa7726dcb32bdad44be84dbec0762a3044  /root/harden-pbx1.sh" | sha256sum -c - && ALLOWED_DIDS="441865679438" bash /root/harden-pbx1.sh 2>&1 | tee /root/harden.log
```

`ALLOWED_DIDS` = the phone numbers Asterisk will answer (digits only, space-separated). Add the HK number when it is live, e.g. `ALLOWED_DIDS="441865679438 852XXXXXXXX"`.

## What it does
1. Turns off unused Asterisk control interfaces: AMI (5038), HTTP/ARI (8088/8089).
2. Dialplan answers only the listed DIDs, max 10 concurrent calls.
3. RTP range 10000–10199 + `strictrtp=yes`; firewall opened to match.
4. Moves eth1 (shared libvirt network) into a DROP zone. Skipped if your SSH session is on eth1.
5. SSH key-only + root login by key only. Skipped if root has no `authorized_keys`, so you can't be locked out. Installs fail2ban for sshd.
6. Restarts Asterisk and prints listeners, ElevenLabs contact status, dialplan, firewall zones and fail2ban status.

Safe to re-run. Backups of the original configs are kept next to them (`*.sample-orig`, `extensions.conf.bak.<time>`).

After it finishes, open a **second** SSH session to confirm you can still log in before closing the first one.

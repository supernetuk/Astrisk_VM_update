#!/usr/bin/env bash
# Security hardening for pbx1 (from the GPT-5.4 security review, 24 Nov 2026).
# Run as root ON pbx1. Safe to re-run. Each step prints what it did.
# It will NOT disable SSH passwords unless root already has an authorized SSH key,
# and it will NOT touch eth1 if your SSH session comes in over eth1.
set -euo pipefail

ALLOWED_DIDS="${ALLOWED_DIDS:-441865679438}"   # space-separated, digits only. Add the HK DID when live.
RTP_START=10000
RTP_END=10199                                     # 100 simultaneous calls is plenty

say(){ printf '\n== %s ==\n' "$*"; }

say "0. Current listeners (before)"
ss -ltnup | grep -E 'asterisk|sshd' || true

say "1. Turn off Asterisk control planes we don't use (AMI 5038, HTTP/ARI 8088/8089)"
cd /etc/asterisk
for f in manager.conf http.conf ari.conf; do [ -f "$f" ] && cp -n "$f" "$f.sample-orig"; done
printf '[general]\nenabled = no\n' > manager.conf
printf '[general]\nenabled = no\n' > http.conf
printf '[general]\nenabled = no\n' > ari.conf
chown asterisk:asterisk manager.conf http.conf ari.conf

say "2. Dialplan: only answer our own DIDs, max 10 concurrent calls"
cp extensions.conf "extensions.conf.bak.$(date +%s)"
python3 - "$ALLOWED_DIDS" <<'PY'
import sys, re
dids = sys.argv[1].split()
checks = "\n".join(f' same => n,GotoIf($["${{NUM}}"="{d}"]?ok)' for d in dids)
block = f"""[from-didww]
; DIDWW may send the number with or without "+"
exten => _+X.,1,Goto(from-didww,${{EXTEN:1}},1)
exten => _X.,1,Set(NUM=${{FILTER(0-9,${{EXTEN}})}})
 same => n,NoOp(DIDWW call to ${{NUM}} from ${{CALLERID(num)}})
{checks}
 same => n,NoOp(Rejected: ${{NUM}} is not one of our DIDs)
 same => n,Hangup(21)
 same => n(ok),Set(GROUP()=didww-in)
 same => n,GotoIf($[${{GROUP_COUNT(didww-in)}} > 10]?busy)
 same => n,Answer()
 ; Number must match the E.164 number imported in ElevenLabs (Phone numbers -> SIP trunk)
 same => n,Dial(PJSIP/elevenlabs/sip:+${{NUM}}@sip.rtc.elevenlabs.io:5060\\;transport=tcp,30)
 same => n,NoOp(ElevenLabs result: ${{DIALSTATUS}} / ${{HANGUPCAUSE}})
 same => n,Playback(ss-noservice)
 same => n,Hangup()
 same => n(busy),Busy(5)
"""
p = "/etc/asterisk/extensions.conf"
s = open(p).read()
s = re.sub(r"\[from-didww\].*?(?=\n\[)", block.rstrip("\n") + "\n", s, flags=re.S)
open(p, "w").write(s)
PY
chown asterisk:asterisk extensions.conf

say "3. RTP: smaller port range, strict RTP (ignore media from unexpected sources)"
cat > rtp.conf <<EOF
[general]
rtpstart=${RTP_START}
rtpend=${RTP_END}
strictrtp=yes
probation=4
EOF
chown asterisk:asterisk rtp.conf
firewall-cmd --permanent --zone=public --remove-port=10000-20000/udp || true
firewall-cmd --permanent --zone=public --add-port=${RTP_START}-${RTP_END}/udp

say "4. eth1 (shared libvirt network) -> its own DROP zone"
SSH_FROM="$(echo "${SSH_CLIENT:-}" | awk '{print $1}')"
if [[ "$SSH_FROM" == 192.168.122.* ]]; then
  echo "SKIPPED: your SSH session comes in over eth1 ($SSH_FROM). Reconnect via the public IP and re-run."
else
  firewall-cmd --permanent --new-zone=internaldrop 2>/dev/null || true
  firewall-cmd --permanent --zone=internaldrop --set-target=DROP
  firewall-cmd --permanent --zone=public --remove-interface=eth1 || true
  firewall-cmd --permanent --zone=internaldrop --change-interface=eth1
  nmcli -t -f NAME,DEVICE con show --active | awk -F: '$2=="eth1"{print $1}' | while read -r c; do nmcli con mod "$c" connection.zone internaldrop; done
fi
firewall-cmd --reload

say "5. SSH: keys only + fail2ban"
if [ -s /root/.ssh/authorized_keys ]; then
  cat > /etc/ssh/sshd_config.d/90-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 20
EOF
  sshd -t && systemctl reload sshd && echo "SSH: password login disabled (key login still works)."
else
  echo "SKIPPED: /root/.ssh/authorized_keys is empty — add your SSH key first, then re-run, or you'd be locked out."
fi
dnf -y install fail2ban >/dev/null
cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

say "6. Apply Asterisk changes"
systemctl restart asterisk
sleep 3
asterisk -rx "pjsip qualify elevenlabs" >/dev/null; sleep 2

say "Results"
ss -ltnup | grep -E 'asterisk|sshd' || true
echo "(expect only :5060 udp/tcp on 2.26.217.37 and sshd — nothing on 5038/8088/8089)"
asterisk -rx "pjsip show contacts" | grep elevenlabs || true
asterisk -rx "dialplan show from-didww" | head -20
firewall-cmd --get-active-zones
firewall-cmd --zone=public --list-all
fail2ban-client status sshd | tail -3

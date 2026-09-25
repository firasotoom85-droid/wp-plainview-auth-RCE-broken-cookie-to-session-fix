# wp-plainview-auth-RCE-broken-cookie-to-session-fix

> WP Plainview Activity Monitor auth RCE fix: broken manual cookie parse → stable Session handling. CVE-2018-15877 educational fix.

> Fixed by: **GODK**

## Original

- Exploit Title: WordPress Plugin Plainview Activity Monitor 20161228 - Remote Code Execution (RCE) (Authenticated) (2)
- Exploit Author: Beren Kuday GORUN
- Vendor Homepage: https://wordpress.org/plugins/plainview-activity-monitor/
- Software Link: https://www.exploit-db.com/apps/2e1f384e5e49ab1d5fbf9eedf64c9a15-plainview-activity-monitor.20161228.zip
- Version: 20161228 and possibly prior
- Fixed version: 20180826
- CVE: CVE-2018-15877
- Exploit-DB: 50110.py
- File in this repo: `50110-fixed.py` (same prompts, fixed logic)

Main idea of script: authenticated command injection via `wp-admin/admin.php?page=plainview_activity_monitor&tab=activity_tools` `ip` parameter into `dig` (`google.com.tr | <cmd>`), output parsed from `<p>Output from dig: </p>`.

## Problems where

In original `50110.py`:

1. `getCookie()` used `x.headers["Set-Cookie"]` string split + `[:-1]` truncation — lost `wordpress_logged_in_*`, so commands ran unauthenticated.
2. Called `getCookie(ip)` inside every `while 1:` loop iteration — re-login per command.
3. Used globals `username/password`, no args, no timeout.
4. No login verification — continued to `poc()` even on bad credentials.
5. `split("<p>Output from dig: </p>")[1]` + `soup.p.text` with no guard — `IndexError` if plugin missing/patched or session expired.
6. Hardcoded `http://`, no input normalization, no `exit`.

## Improvements

- `login()` with `requests.Session()`, checks `wordpress_logged_in` cookie + `wp-admin/` reachable.
- `extract_dig_output()` + `run_command()` return `None` with clear message instead of crash.
- `normalize_target()` / `build_base()` accept `TARGET_IP`, `http://TARGET_IP/`, `TARGET_IP:port`.
- Single session reused for `poc()` + `exploit()` loop.
- `TIMEOUT=10`, `User-Agent`, `exit/quit/q` + `Ctrl+C` handling, `main()` + `__main__` guard.
- Empty-vs-missing handling: `cd` / empty file / stderr-only permission error returns `[*] empty output` with absolute-path hint, `[!] No dig output` only on real plugin/session fail with `DEBUG len/marker/url`. Keeps `|` delimiter (`;` filtered), warns against typing own `| & > ;`.

## Usage

```bash
python3 50110-fixed.py
What's your target IP?
TARGET_IP
What's your username?
YOUR_USER
What's your password?
...
[*] Please wait...
[*] Perfect!
www-data@TARGET_IP
```

Type `exit` to quit.

## Validation

- `python3 -m py_compile 50110-fixed.py` — OK
- `normalize_target` / `extract_dig_output` unit check — OK
- Lab test: `run_command('whoami')` → `www-data`

## Before / After

- `getCookie()` manual `Set-Cookie` split → `login()` with `requests.Session()` + `wordpress_logged_in` check
- `getCookie()` per loop → single session reuse
- `split(MARKER)[1]` crash → `extract_dig_output()` guard + empty-vs-missing handling
- Hardcoded `http://` + globals → `normalize_target()` / `build_base()` + args

## Changelog

- `5427e6d` Fix broken cookie to session handling for WP Plainview RCE
- `0a10e3b` Update fix: distinguish empty output from session fail, keep pipe delimiter

## Credits

- Original exploit: Beren Kuday GORUN (Exploit-DB 50110, CVE-2018-15877)
- Fix / maintenance: **GODK**

## Disclaimer

Educational fix for lab systems you own. Do not use on systems without explicit permission.

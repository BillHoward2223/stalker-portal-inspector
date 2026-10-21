# Stalker / Ministra Portal Account Inspector

Desktop tool for an administrator of a Stalker or Ministra portal. It signs in with a documented administrator API, shows the account fields that API actually returns, and counts channel metadata. It does not play streams.

Live portal authentication is not built in. This repository does not contain a set-top-box handshake or a guessed signing scheme. Until you supply the middleware version and an official or administrator-written API specification, use **Synthetic demo**. Demo mode shows fictional Northwind data and does not open a network connection.

## What you need before a live connection

1. The Stalker or Ministra version running on the portal you administer.
2. The official API documentation, or an endpoint specification you are authorized to use.
3. A portal hostname you control, an HTTPS certificate that validates normally, and one device MAC address you are allowed to inspect.

Copy `config/api_spec.example.json`, replace the fictional host and paths with that documentation, and select the file in the window. Requests are limited to `allowed_hosts` and to the paths in the file. Certificate verification stays on. Redirects are not followed. Environment proxies are ignored so account data is not sent through an undeclared proxy.

If the documentation does not expose expiry or channel metadata, the report says that field is not available. The application will not try another URL to find it.

SNCUT, DEV1, and DEV2 are omitted unless `confirmed_proprietary_fields` states the vendor meaning. A similarly named JSON property is not displayed on its own.

## Requirements

- Python 3.12 or newer
- Windows is the supported desktop target. The same source runs on other systems for development and tests.
- On Windows, credentials are stored with Windows Credential Manager through the `keyring` package.

## Install and start

From this directory:

```bash
python -m venv .venv
```

Windows:

```bat
.venv\Scripts\activate
python -m pip install -r requirements.txt
python main.py
```

macOS or Linux:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

The window opens in synthetic demo mode. Enter any well-formed HTTPS origin and one MAC address, then choose Connect. The report is labeled synthetic.

For a portal you administer:

1. Choose **Documented administrator API**.
2. Select your specification JSON.
3. Choose **Credentials** and save the username, password, API key, or bearer token. Those values go to the operating-system credential store. They are not written to `settings.json`.
4. Choose Connect.

Connection settings other than secrets are saved under `%APPDATA%\StalkerPortalInspector` on Windows and `~/.config/StalkerPortalInspector` elsewhere. Logs in that folder are passed through a redacting formatter.

## Tests

Tests use fictional JSON fixtures and an in-memory HTTP transport. They do not contact an IPTV service.

```bash
python -m pytest
```

Covered cases include a successful documented session, an expired session with one refresh, a failed refresh that stops, HTTP 401 and 403, missing account fields, an empty catalogue, duplicate channel rows, incomplete pagination, malformed JSON, timeouts, TLS and DNS failures, rate limiting, redirects, oversized responses, and an undeclared channel endpoint.

## Windows executable

On a Windows machine with Python 3.12 or newer:

```bat
build_windows.bat
```

The script installs the requirements, installs PyInstaller, and writes `dist\StalkerPortalInspector\StalkerPortalInspector.exe`. Ship the whole `dist\StalkerPortalInspector` folder. The example specification is bundled as data. Secrets are still stored in Windows Credential Manager, not beside the executable.

## Specification contract

`config/api_spec.example.json` is a fictional administrator API. Version `"1.0"` accepts only the keys in that file.

- `allowed_hosts` lists exact hostnames. Wildcards are rejected.
- `auth.type` is `none`, `bearer`, `api_key`, `basic`, or `session`.
- A session login may include `expires_in` and a refresh path. The client refreshes at most twice per connection and does not retry a rejected login.
- Paths are relative. `{mac}` and `{serial}` are the only placeholders.
- Account fields are dotted paths. Booleans are accepted for the live-channel flag. Other live values are not guessed.
- Channel pagination uses integer totals. Rows are counted as returned. Unique channels are distinct ids. If an id is missing, the unique count is left as not available.
- A confirmed proprietary field looks like this:

```json
{
  "name": "sncut",
  "response_path": "device.sncut",
  "meaning": "Meaning copied from the vendor documentation you were given."
}
```

Do not put passwords, tokens, or cookies in the specification file.

## Report

The report shows the configured portal, the MAC address you entered, the API status, expiry, and serial number, then the channel record count, unique channel count, live count, and category count. Copy report and Export JSON are on the report panel. Export passes the document through redaction so keys such as `password`, `token`, and `cookie` are replaced.

`This session` is the time this application finished the inspection. `Last connection` is shown only when the API returns that field.

## Behavior boundaries

- HTTPS only, with normal TLS verification.
- One automatic authentication attempt per connection, plus the specification's own token refresh.
- Response bodies are capped at 2 MB. Channel reads stop after 50 pages or 20,000 records.
- HTTP 429 is retried once only when `Retry-After` is two seconds or less. HTTP 5xx is retried once.
- A MAC address is the device you asked about. It is not treated as proof of account ownership.
- The application does not scan MAC addresses, enumerate accounts, call undeclared paths, download media, or decrypt streams.

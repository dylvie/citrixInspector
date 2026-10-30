# citrixInspector

`citrixInspector.py` is a Python command-line tool for identifying Citrix ADC / Citrix Gateway (formerly NetScaler) appliances, fingerprinting firmware builds where possible, and checking those builds against a maintained set of known CVE version thresholds.

The scanner makes unauthenticated HTTP requests and does not attempt to exploit vulnerabilities or change appliance state. Use it only on systems you own or are explicitly authorized to assess.

![Example scan output](docs/sample-scan.png)

*The sample output was produced in a simulated test harness; the hostname is a placeholder.*

## What it checks

- **Firmware fingerprinting:** Uses the GZIP `MTIME` timestamp in `/vpn/js/rdx/core/lang/rdx_en.json.gz` as the primary build-identification method, then checks legacy `v=<md5>` hashes in page resources. The GZIP technique is generally more useful on modern builds; either fingerprint can be unavailable or absent from the lookup data.
- **Known CVEs:** Compares an identified build with the version thresholds listed below and reports all matching CVEs.
- **Additional signals:** Checks `/vpn/pluginlist.xml` for the Windows EPA plug-in version and examines the page title, known Citrix icons, HTML comments, and `Last-Modified` header. These signals can help identify an appliance or inform a lower-confidence result when an exact build is unavailable.
- **Optional IOC checks:** Checks known paths under `/vpn/themes/` for web-shell indicators associated with exploitation. A matching HTTP response is a lead for investigation, not proof of compromise.
- **Resilient scanning:** Retries transient HTTP failures and isolates individual targets so that an unreachable target does not stop a batch scan.

## Improvements

The scanner is designed to keep useful results flowing when targets or responses are unreliable:

- All requests use a shared HTTP session with up to five retries for connection/read failures and transient HTTP responses (`429`, `500`, `502`, `503`, and `504`), with exponential backoff.
- Each request has separate connection and read timeouts (10 and 20 seconds). If a request still fails, the scanner logs the error and skips that check instead of terminating the run.
- Checks that depend on optional or malformed responses, including the GZIP fingerprint, `pluginlist.xml`, page HTML, and `Last-Modified` header, degrade gracefully when the expected data is unavailable or invalid.
- During IOC checks, an unreachable IOC path is logged and skipped so the remaining paths can still be checked. In batch mode, failures are isolated per target so later URLs continue to be scanned.
- Target lists may include blank lines and `#` comments, and a short pause is added between targets.
- **Python compatibility:** Updated the pinned `cffi` dependency to `2.1.1` to support newer Python versions.

## CVE coverage

The checks below are based on the version thresholds encoded in the scanner. Fixed builds are shown for the main release tracks; FIPS/NDcPP tracks may have separate thresholds, noted where relevant.

| CVE(s) | Description | Fixed in |
|---|---|---|
| CVE-2023-3519 | Unauthenticated remote code execution (stack overflow) | 13.0-91.13; 13.1-49.13 |
| CVE-2025-5349, CVE-2025-5777 | “CitrixBleed 2” memory disclosure | 14.1-43.56; 13.1-58.32; FIPS 13.1-37.235; FIPS 12.1-55.328 |
| CVE-2025-6543 | Gateway memory overflow; exploited in the wild | 14.1-47.46; 13.1-59.19; FIPS 13.1-37.236 |
| CVE-2025-7775, CVE-2025-7776, CVE-2025-8424 | “CitrixBleed 3” memory disclosure / access control issues | 14.1-47.48; 13.1-59.22; FIPS 13.1-37.241; FIPS 12.1-55.330 |
| CVE-2026-8452 | Pre-auth SAML PrefixList heap overflow | 14.1-72.61; 13.1-63.18 |
| CVE-2026-88771, CVE-2026-88772 | Pre-auth command injection / DTLS memory overflow; listed in CISA KEV | 14.1-73.37; 13.1-64.23; FIPS 14.1-73.37; FIPS-NDcPP 13.1-37.279 |

Some CVEs depend on appliance configuration. In particular, CVE-2026-8452 requires a SAML SP or IdP policy bound to the virtual server. This scanner does not inspect authenticated configuration, so a version match alone does not establish that a configuration-dependent issue is exploitable. End-of-life releases may be reported vulnerable where the scanner has no fixed build threshold for that branch.

Only the CVEs represented in the scanner's version-check table are covered; this is not a complete assessment of every Citrix advisory or appliance configuration.

## Requirements

- Python 3
- Packages listed in [`requirements.txt`](requirements.txt)

## Installation

```bash
git clone https://github.com/dylvie/citrixInspector.git
cd citrixInspector
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate` instead.

## Usage

Check one authorized target:

```bash
python citrixInspector.py --url https://gateway.example.com
```

Check a list of targets (one URL per line). Blank lines and lines beginning with `#` are ignored:

```text
# gateways included in the authorized assessment
https://gateway-one.example.com
https://gateway-two.example.com
```

```bash
python citrixInspector.py --file targets.txt
```

Run the slower optional web-shell IOC checks as well:

```bash
python citrixInspector.py --url https://gateway.example.com --ioc-check
python citrixInspector.py --file targets.txt --ioc-check
```

Write scan details to a specific log file:

```bash
python citrixInspector.py --file targets.txt --log assessment.log
```

Show all command-line options:

```bash
python citrixInspector.py --help
```

`--url` and `--file` are mutually exclusive and one is required. The default log file is `citrixInspector.log`; each run replaces that file unless another path is supplied.

## Understanding results

| Output | Meaning |
|---|---|
| `[VULNERABLE] [CERTAIN] [CVE…] [version]` | A build was identified and falls below one or more listed fix thresholds. “Certain” describes the version-based result, not proof of exploitation or configuration applicability. |
| `[PATCHED] [CERTAIN] [version]` | A build was identified and is at or above the covered CVE thresholds. This does not mean the appliance is free of other vulnerabilities. |
| `[VULNERABLE] [FIRM]` | No exact build was identified; multiple legacy signals indicate possible CVE-2023-3519 exposure. |
| `[VULNERABLE] [TENTATIVE]` | Citrix indicators and the plug-in check suggest possible exposure, but an exact firmware build was not identified. |
| `[CITRIX DETECTED]` | Citrix indicators were found, but the available signals did not establish a vulnerability result. |
| `[CITRIX NOT DETECTED]` | The scanner did not find enough indicators to identify a Citrix appliance. This is not proof that the service is absent. |
| `[UNREACHABLE]` or `[ERROR]` | The target could not be checked successfully; review the console output and log. |
| `[COMPROMISE DETECTED]` | A known IOC path returned HTTP 200. Investigate the response and host; this result alone is not confirmation of compromise. |

An exact fingerprint is only as current and complete as the scanner's lookup tables. If no version is identified, the fallback heuristics are much less comprehensive and cover only limited CVE-2023-3519 signals; they do not assess the newer CVEs.

## Data sources and acknowledgements

- Fox-IT Security Research Team: GZIP-timestamp and vhash fingerprinting techniques and version data, adapted with attribution from [citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage) (Apache-2.0) and its [2022 research post](https://blog.fox-it.com/2022/12/28/cve-2022-27510-cve-2022-27518-measuring-citrix-adc-gateway-version-adoption-on-the-internet/).
- Citrix security bulletins: CTX561482, CTX693420, CTX694788, CTX694938, CTX696604, and CTX697096.
- watchTowr Labs: [CVE-2026-8452 analysis](https://labs.watchtowr.com/youre-back-in-the-room-citrix-netscaler-pre-auth-rce-cve-2026-8452/) and [CVE-2026-88771 analysis](https://labs.watchtowr.com/oh-look-the-foot-gun-went-off-again-citrix-netscaler-preauth-command-injection-cve-2026-88771/).
- BishopFox: [CVE-2026-8452 check](https://github.com/BishopFox/CVE-2026-8452-check).
- Deutsche Telekom CERT: [original CVE-2023-3519 scanner and header heuristic](https://github.com/telekom-security/cve-2023-3519-citrix-scanner).

## Legal notice

This project is intended for authorized security testing and research. Obtain permission before scanning any system. You are responsible for complying with applicable laws and rules of engagement. The software is provided “as is,” without warranty; see [LICENSE](LICENSE).

## Author

Bryan Smith (@securekomodo)
Improved by Dylvie Shwartz (@dylvie)

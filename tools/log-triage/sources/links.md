# Sources and References

No external data is downloaded or queried at runtime. The sample log was
generated locally by [`sample_input/generate_sample.py`](../sample_input/generate_sample.py).
These public references informed the detection logic, log formats, and the
synthetic data conventions.

## Detection techniques

- MITRE ATT&CK T1110 - Brute Force: https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1110.001 - Password Guessing: https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK T1110.003 - Password Spraying: https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK T1595 - Active Scanning: https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK T1595.002 - Vulnerability Scanning: https://attack.mitre.org/techniques/T1595/002/
- MITRE ATT&CK T1046 - Network Service Discovery: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1552.001 - Credentials In Files: https://attack.mitre.org/techniques/T1552/001/
- MITRE ATT&CK T1190 - Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/

## Log formats and safe data

- OpenSSH manual pages: https://www.openssh.com/manual.html
- Nginx access log module: https://nginx.org/en/docs/http/ngx_http_log_module.html
- Apache mod_log_config: https://httpd.apache.org/docs/2.4/mod/mod_log_config.html
- dnsmasq manual: https://thekelleys.org.uk/dnsmasq/doc.html
- UFW documentation: https://help.ubuntu.com/community/UFW
- RFC 5737 - IPv4 Address Blocks Reserved for Documentation:
  https://datatracker.ietf.org/doc/html/rfc5737
- RFC 1918 - Address Allocation for Private Internets:
  https://datatracker.ietf.org/doc/html/rfc1918
- RFC 2606 - Reserved Top Level DNS Names:
  https://datatracker.ietf.org/doc/html/rfc2606
- OWASP Logging Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

## Python standard library

- Python 3 documentation: https://docs.python.org/3/
- `hashlib`: https://docs.python.org/3/library/hashlib.html
- `ipaddress`: https://docs.python.org/3/library/ipaddress.html
- `argparse`: https://docs.python.org/3/library/argparse.html
- `json`: https://docs.python.org/3/library/json.html

## Public datasets considered but not used

These were reviewed as possible sources of real log data but were intentionally
not included, to avoid downloading data and to keep the sample fully synthetic
and reproducible:

- Loghub public log datasets: https://github.com/logpai/loghub
- SecRepo security data samples: https://www.secrepo.com/
- Malware-Traffic-Analysis.net public pcaps: https://www.malware-traffic-analysis.net/

## Notes

- `.example` is a reserved TLD and cannot resolve on the public Internet.
- All external sample addresses are documentation ranges and are not routed.
- The watchlist is synthetic and is not a threat-intelligence feed.

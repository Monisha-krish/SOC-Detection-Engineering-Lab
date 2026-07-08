# Successful SSH Logins Detection

## Objective

Detect successful SSH logins to Linux systems using public key authentication. Monitoring successful authentication events helps SOC analysts verify legitimate administrative access and identify potentially unauthorized logins.

---

## Detection Logic

This detection monitors the Linux authentication log (`/var/log/auth.log`) for successful SSH logins authenticated using public key authentication.

---

## SPL Query

```spl
source="/var/log/auth.log" "Accepted publickey"
| rex "Accepted publickey for (?<username>\S+)"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time host username src_ip
| sort - _time
```

---

## Sample Output

| Time | Host | Username | Source IP |
|------|------|----------|-----------|
| 2026-07-08 17:09:43 | splunk-server | monishamr27 | 35.235.241.113 |
| 2026-07-08 17:05:31 | splunk-server | monishamr27 | 35.235.241.113 |

---

## Why This Detection Matters

Successful SSH authentication events indicate that a user has successfully accessed the Linux system. Monitoring these events enables analysts to:

- Verify legitimate administrator logins.
- Detect unexpected or unauthorized remote access.
- Correlate successful logins with prior failed authentication attempts.
- Investigate suspicious login activity from unfamiliar IP addresses.
- Maintain an audit trail of remote administrative access.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Persistence | Valid Accounts | T1078 |
| Initial Access | External Remote Services | T1133 |

---

## Investigation Steps

1. Verify whether the authenticated user is authorized to access the system.
2. Review the source IP address and determine whether it belongs to a trusted location.
3. Correlate the login with previous failed authentication or brute-force attempts.
4. Review additional activities performed after login, such as command execution or privilege escalation.
5. Investigate any successful logins occurring outside normal business hours or from unusual locations.

---

## Expected Outcome

This detection provides visibility into successful SSH authentication events, allowing analysts to distinguish legitimate administrative access from potentially unauthorized logins and support auditing and incident investigations.

---

## Screenshot

Add a screenshot of the Splunk search results.

Example:

```
screenshots/linux/successful_logins_detection.png
```
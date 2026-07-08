# Invalid User SSH Alert

## Objective

Detect SSH authentication attempts targeting invalid or non-existent user accounts on Linux systems. This alert helps identify reconnaissance activity, automated scanning, and brute-force attacks against SSH services.

---

## Alert Logic

The alert monitors the Linux authentication log (`/var/log/auth.log`) for SSH events containing the **"Invalid user"** message. If one or more invalid user login attempts are detected within the scheduled search interval, the alert is triggered.

---

## SPL Query

```spl
source="/var/log/auth.log" "Invalid user"
| rex "Invalid user (?<username>\S+)"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time host username src_ip
```

---

## Alert Configuration

| Setting | Value |
|----------|-------|
| Alert Name | Invalid User SSH Alert |
| Alert Type | Scheduled |
| Schedule | Every 5 minutes |
| Cron Expression | `*/5 * * * *` |
| Time Range | Last 5 minutes |
| Trigger Condition | Number of Results > 0 |
| Trigger | Once |
| Severity | Medium |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | Brute Force | T1110 |
| Initial Access | External Remote Services | T1133 |

---

## Investigation Steps

1. Identify the source IP address generating the login attempt.
2. Review the targeted username.
3. Determine whether multiple usernames are being targeted from the same IP address.
4. Correlate with SSH brute-force detections or successful login events.
5. Investigate whether the IP address has generated repeated authentication attempts.
6. Block or restrict malicious IP addresses if necessary.

---

## Expected Outcome

The alert provides early visibility into unauthorized SSH authentication attempts targeting invalid user accounts, allowing analysts to investigate and respond before attackers gain access.

---

## Screenshot

Add a screenshot of the alert configuration.

Example:

```
screenshots/alerts/invalid_user_ssh_alert.png
```

Also include a screenshot of the triggered alert or search results if available.

Example:

```
screenshots/alerts/invalid_user_ssh_alert_results.png
```
# Detection Engineering — Microsoft Sentinel

Five custom analytics rules built in Microsoft Sentinel, each mapped to MITRE ATT&CK and **validated by executing the technique** (Atomic Red Team on a lab Windows Server VM) and confirming the detection fired.

## Lab architecture

```
vm-seclab-win01 (Windows Server, isolated Azure lab)
   │  Azure Monitor Agent
   ├── DCR: Windows Security Events (Common set) ──► SecurityEvent table
   └── DCR: Sysmon (SwiftOnSecurity config)       ──► Event table
                        │
                        ▼
        Log Analytics workspace (law-seclab)
                        │  KQL
                        ▼
        Microsoft Sentinel — scheduled analytics rules ──► incidents
```

Telemetry collected: Windows Security Events (curated "Common" set) and Sysmon (SwiftOnSecurity community config). Attacks simulated with Atomic Red Team.

## Detection rules

| # | Rule | Tactic | Technique | Data source | Key signal | Validated with | Severity |
|---|------|--------|-----------|-------------|-----------|----------------|----------|
| 1 | Local account created | Persistence | T1136.001 | SecurityEvent | EventID 4720 | Atomic `T1136.001-4` | Medium (tuned) |
| 2 | Scheduled task created | Persistence | T1053.005 | Sysmon | EventID 1 — `schtasks /create` | Atomic `T1053.005-1` | Medium |
| 3 | Registry Run key persistence | Persistence | T1547.001 | Sysmon | EventID 13 — `\CurrentVersion\Run` | Atomic `T1547.001-1` | Medium |
| 4 | Encoded PowerShell command | Execution | T1059.001 | Sysmon | EventID 1 — `-EncodedCommand` | Manual (child `powershell -enc`) | Medium |
| 5 | Security event log cleared | Defense Evasion | T1070.001 | SecurityEvent | EventID 1102 | `wevtutil cl Security` | High |

All rules: scheduled every 5 minutes, 5-minute lookback, alert on >0 results, with Account/Host entity mapping for investigation.

## Queries

**1 — Local account created (T1136.001), tuned:**
```kql
SecurityEvent
| where EventID == 4720
// Tuning: suppress expected, benign account creation (see Tuning notes)
| where TargetUserName !endswith "$"                        // machine accounts
| where TargetUserName !startswith "svc-"                   // approved service-account convention
| where TargetUserName !in ("DefaultAccount", "WDAGUtilityAccount", "defaultuser0")
| extend AccountCustomEntity = TargetAccount, HostCustomEntity = Computer
```

**2 — Scheduled task created (T1053.005):**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| where RenderedDescription has "schtasks" and RenderedDescription has "/create"
| extend HostCustomEntity = Computer
```

**3 — Registry Run key persistence (T1547.001):**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 13
| where RenderedDescription has @"\CurrentVersion\Run"
| extend HostCustomEntity = Computer
```

**4 — Encoded PowerShell command (T1059.001):**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| where RenderedDescription has_any ("-EncodedCommand", "-enc ", "-e ")
| extend HostCustomEntity = Computer
```

**5 — Security event log cleared (T1070.001):**
```kql
SecurityEvent
| where EventID == 1102
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
```

## Tuning notes (Rule 1)

The raw rule fires on every account creation (4720), which is noisy: IT provisioning, installers and Windows itself all create accounts, and alert fatigue is itself a risk. Exclusions added, each justified:

- `!endswith "$"` — machine/computer accounts, created constantly, never of interest here.
- `!in (...)` built-ins — `DefaultAccount`, `WDAGUtilityAccount`, `defaultuser0` are created by Windows.
- `!startswith "svc-"` — *illustrative only.* See the caveat below.

**Caveat — naming-convention allowlists are weak.** A name is not an identity: an attacker who learns the `svc-` convention (by enumerating accounts, reading a runbook, or reading these very rules) can name a backdoor `svc-update` and bypass the rule — a form of Masquerading (T1036). Service accounts are a prime target (over-privileged, non-expiring passwords, Kerberoastable), so suppressing `svc-*` risks silencing the exact category attackers most abuse. A stronger approach:
- Allowlist by **provenance** (created by the sanctioned IAM automation), not by name.
- Maintain a reviewed **watchlist** of exact known service accounts rather than an open wildcard.
- **Raise fidelity instead of suppressing:** correlate 4720 with 4732 (added to Administrators) and alert that at high severity.
- Treat every exclusion as a documented, periodically reviewed gap.

## Known limitations & future work

- **In-memory / fileless execution is invisible here.** Sysmon EventID 1 logs the *process* command line, not code run *inside* it. `Invoke-Mimikatz` (in-memory) and `Add-MpPreference` exclusions (T1562.001, run inside a script) produced no process-level signal. Mitigation: enable **PowerShell Script Block Logging (Event 4104)** and AMSI.
- **LSASS access (T1003.001)** needs Sysmon ProcessAccess (EventID 10), which the SwiftOnSecurity config disables by default.
- **Log-clearing of non-Security logs** (Event 104, System log) isn't collected by the current DCRs.
- **Planned:** export rules as ARM/Bicep and deploy via CI/CD (detection-as-code, Week 4); add the 4720→4732 correlation rule.

---
*Author: Theodora Obioma — security-engineering-lab*
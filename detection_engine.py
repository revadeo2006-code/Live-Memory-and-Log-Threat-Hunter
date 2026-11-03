"""Small, explainable, rule-based detection helpers for SentinelOps.

This module deliberately reports *potentially suspicious* activity. A normal
administration tool, remote connection, or high resource value is an indicator
only when it has supporting context.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Indicator:
    title: str
    score: int
    source_type: str
    source_id: str
    detail: str
    tactic: str
    confidence: str = "medium"
    rule_id: str = ""
    rule_name: str = ""


@dataclass
class Incident:
    title: str
    risk_score: int
    severity: str
    explanation: str
    evidence: list[Indicator] = field(default_factory=list)
    recommended_action: str = ""


OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


def severity(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _indicator(title: str, points: int, process: dict[str, Any], tactic: str, detail: str, rule_id: str) -> Indicator:
    return Indicator(title, points, "process", f"PID {process.get('pid')} {process.get('name')}", detail, tactic, "medium", rule_id, title)


def analyze_process(process: dict[str, Any]) -> list[Indicator]:
    """Return evidence points, not a verdict, for one live process."""
    name = str(process.get("name") or "").lower()
    parent = str(process.get("parent_name") or "unknown").lower()
    cmd = str(process.get("cmdline") or "")
    exe = str(process.get("exe") or "")
    remote_count = int(process.get("remote_count") or 0)
    indicators: list[Indicator] = []
    encoded = bool(re.search(r"(?:-|/)enc(?:odedcommand)?\b", cmd, re.I))
    download = bool(re.search(r"downloadstring|invoke-webrequest|\biwr\b|urlcache|frombase64string", cmd, re.I))
    temp_execution = bool(re.search(r"\\(?:appdata\\local\\temp|windows\\temp|temp|downloads)\\.*\.(?:ps1|vbs|js|hta|exe|dll|bat)\b", f"{cmd} {exe}", re.I))
    dangerous = bool(re.search(r"vssadmin\s+delete\s+shadows|shadowcopy\s+delete|recoveryenabled\s+no", cmd, re.I))
    persistence = bool(re.search(r"(?:reg\s+add\s+.*\\run|sc\s+create|new-service|schtasks\s+/create)", cmd, re.I))
    credential = bool(re.search(r"lsass\.exe|sekurlsa|privilege::debug", cmd, re.I))
    proxy = bool(re.search(r"(?:mshta\s+(?:https?://|javascript:)|regsvr32.*(?:scrobj|\.sct|https?://)|rundll32.*(?:javascript:|https?://))", cmd, re.I))
    if encoded: indicators.append(_indicator("Suspicious Command Execution: encoded command", 40, process, "Defense Evasion", "The command line contains an encoded-command switch.", "CTX-001"))
    if download: indicators.append(_indicator("Suspicious Command Execution: remote content request", 30, process, "Command and Control", "The command line requests or decodes remote content.", "CTX-002"))
    if temp_execution: indicators.append(_indicator("Execution from user-writable temporary path", 20, process, "Execution", "The executable or script path is in a temporary or Downloads location.", "CTX-003"))
    if dangerous: indicators.append(_indicator("Potential Ransomware-Related Behavior", 65, process, "Impact", "The command attempts to remove shadow copies or disable recovery.", "CTX-004"))
    if persistence: indicators.append(_indicator("Possible Persistence Activity", 35, process, "Persistence", "The command creates a service, scheduled task, or Run-key entry.", "CTX-005"))
    if credential: indicators.append(_indicator("Potential Credential Access Activity", 55, process, "Credential Access", "The command line references LSASS or credential-dumping keywords.", "CTX-006"))
    if proxy: indicators.append(_indicator("Suspicious signed-binary proxy execution", 45, process, "Defense Evasion", "The command uses a remote/script proxy pattern.", "CTX-007"))
    # explorer -> PowerShell is intentionally not an indicator. Office -> shell is context only.
    if name in SHELLS and parent in OFFICE_PARENTS:
        indicators.append(_indicator("Unusual parent process for command interpreter", 25, process, "Execution", f"{parent} started {name}.", "CTX-008"))
    if name in SHELLS and remote_count and (encoded or download or parent in OFFICE_PARENTS):
        indicators.append(_indicator("Suspicious Network Activity", 15, process, "Command and Control", f"{name} has {remote_count} remote connection(s) alongside other command context.", "CTX-009"))
    baseline = process.get("baseline") or {}
    cpu_baseline, mem_baseline = float(baseline.get("cpu_avg") or 0), float(baseline.get("memory_avg") or 0)
    cpu, memory = float(process.get("cpu_percent") or 0), float(process.get("memory_mb") or 0)
    if int(baseline.get("samples") or 0) >= 3 and ((cpu >= 25 and cpu > cpu_baseline * 2.5) or (memory >= 300 and memory > mem_baseline * 2.5)):
        detail = f"CPU {cpu}% vs recent {cpu_baseline:.1f}%; memory {memory:.1f} MB vs recent {mem_baseline:.1f} MB."
        indicators.append(_indicator("Usage significantly above recent baseline", 10, process, "Resource Anomaly", detail, "CTX-010"))
    return indicators


def analyze_log_line(line: str, source: str, line_number: int) -> list[Indicator]:
    """Extract modest log indicators; correlation handles frequency later."""
    source_id, data = f"{source}: line {line_number}", line[:500]
    rules = [(r"new service installed|service created|7045", "Possible Persistence Activity", 25, "Persistence", "LOG-002"), (r"scheduled task.*created|4698", "Possible Persistence Activity", 25, "Persistence", "LOG-003"), (r"event log.*cleared|1102", "Potential Defense Evasion Activity", 45, "Defense Evasion", "LOG-004"), (r"vssadmin delete shadows|encrypted files|ransom", "Potential Ransomware-Related Behavior", 55, "Impact", "LOG-005"), (r"4720|4732|admin added|privilege escalation", "Potential account or privilege change", 30, "Privilege Escalation", "LOG-006")]
    result: list[Indicator] = []
    if re.search(r"failed password|logon failed|failed login|4625", line, re.I): result.append(Indicator("Failed authentication event", 8, "log", source_id, data, "Authentication", "low", "LOG-001", "Failed authentication event"))
    if re.search(r"4624|successful logon|login successful", line, re.I): result.append(Indicator("Successful authentication event", 0, "log", source_id, data, "Authentication", "low", "LOG-007", "Successful authentication event"))
    for pattern, title, score, tactic, rule_id in rules:
        if re.search(pattern, line, re.I): result.append(Indicator(title, score, "log", source_id, data, tactic, "medium", rule_id, title))
    return result


def correlate(indicators: list[Indicator]) -> list[Incident]:
    if not indicators: return []
    incidents, by_source = [], {}
    for item in indicators:
        if item.tactic != "Authentication": by_source.setdefault(item.source_id, []).append(item)
    for items in by_source.values():
        risk = min(100, sum(item.score for item in items) + (10 if len(items) > 1 else 0))
        main = max(items, key=lambda item: item.score)
        incidents.append(Incident(main.title, risk, severity(risk), build_explanation(items, risk), items, recommend_action(risk, {item.tactic for item in items})))
    auth = [item for item in indicators if item.tactic == "Authentication"]
    failed, successful = [item for item in auth if item.rule_id == "LOG-001"], [item for item in auth if item.rule_id == "LOG-007"]
    if len(failed) >= 5 and successful:
        evidence, risk = failed[-5:] + successful[-1:], 55
        incidents.append(Incident("Possible Repeated Authentication / Brute-Force Activity", risk, severity(risk), build_explanation(evidence, risk), evidence, "Validate the account, source addresses, and whether the successful sign-in was expected. Do not treat failed sign-ins alone as a confirmed attack."))
    return sorted(incidents, key=lambda item: item.risk_score, reverse=True)


def build_explanation(items: list[Indicator], risk: int) -> str:
    parts = [f"{item.title} +{item.score}" for item in items if item.score]
    if len(items) > 1 and any(item.score for item in items): parts.append("Multiple indicators +10")
    evidence = "; ".join(item.detail for item in items[:3])
    return f"Rule-based risk score: {'; '.join(parts) or 'correlated authentication pattern'} = {risk}/100. Evidence: {evidence} This is an indicator-based priority score, not a probability of compromise."


def recommend_action(risk: int, tactics: set[str]) -> str:
    if risk >= 85: return "Immediately validate the process tree and command line, preserve the listed evidence, and follow local incident procedures if the activity is not authorised."
    if risk >= 45: return "Review the parent process, command line, user, remote destination, and related logs. Mark the investigation False Positive if the activity is authorised."
    return "Monitor this indicator and compare it with the recent baseline; no single indicator proves malicious activity."


def incident_to_dict(incident: Incident) -> dict[str, Any]:
    return {"title": incident.title, "risk_score": incident.risk_score, "severity": incident.severity, "explanation": incident.explanation, "recommended_action": incident.recommended_action, "evidence": [item.__dict__ for item in incident.evidence], "generated_at": datetime.now(timezone.utc).isoformat()}


def rule_catalog() -> list[dict[str, Any]]:
    return [{"rule_id": "CTX-001", "name": "Encoded command with context", "description": "Encoded commands are a review indicator; parent process and network context raise the final score.", "severity": "low", "tactic": "Defense Evasion", "confidence": "medium"}, {"rule_id": "CTX-004", "name": "Recovery disruption command", "description": "Shadow-copy deletion or recovery disabling is potentially ransomware-related behavior.", "severity": "high", "tactic": "Impact", "confidence": "medium"}, {"rule_id": "CTX-005", "name": "Persistence command", "description": "A Run key, service, or scheduled-task creation command needs context review.", "severity": "low", "tactic": "Persistence", "confidence": "medium"}, {"rule_id": "CTX-008", "name": "Office-to-shell process tree", "description": "An Office application starting a command interpreter is unusual context, not proof by itself.", "severity": "low", "tactic": "Execution", "confidence": "low"}, {"rule_id": "CTX-010", "name": "Recent baseline deviation", "description": "CPU or memory significantly above at least three observations is a low-weight indicator.", "severity": "low", "tactic": "Resource Anomaly", "confidence": "low"}, {"rule_id": "LOG-001", "name": "Repeated authentication correlation", "description": "Five failed sign-ins followed by a success are grouped into one investigation alert.", "severity": "medium", "tactic": "Authentication", "confidence": "medium"}]

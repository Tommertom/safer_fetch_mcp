"""
Python port of goose security patterns (from src/patterns.ts).
Security threat patterns for command injection detection.
Taken from patterns.rs from Goose.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class RiskLevel(Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"


class ThreatCategory(Enum):
    FileSystemDestruction = "FileSystemDestruction"
    RemoteCodeExecution = "RemoteCodeExecution"
    DataExfiltration = "DataExfiltration"
    SystemModification = "SystemModification"
    NetworkAccess = "NetworkAccess"
    ProcessManipulation = "ProcessManipulation"
    PrivilegeEscalation = "PrivilegeEscalation"
    CommandInjection = "CommandInjection"


@dataclass
class ThreatPattern:
    name: str
    pattern: str
    description: str
    risk_level: RiskLevel
    category: ThreatCategory


def confidence_score(risk_level: RiskLevel) -> float:
    if risk_level == RiskLevel.Critical:
        return 0.95
    if risk_level == RiskLevel.High:
        return 0.85
    if risk_level == RiskLevel.Medium:
        return 0.70
    return 0.55


THREAT_PATTERNS: List[ThreatPattern] = [
    ThreatPattern(
        name="rm_rf_root",
        pattern=r"rm\s+(-[rf]*[rf][rf]*|--recursive|--force).*[/\\]",
        description="Recursive file deletion with rm -rf",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.FileSystemDestruction,
    ),
    ThreatPattern(
        name="rm_rf_system",
        pattern=r"rm\s+(-[rf]*[rf][rf]*|--recursive|--force).*(bin|etc|usr|var|sys|proc|dev|boot|lib|opt|srv|tmp)",
        description="Recursive deletion of system directories",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.FileSystemDestruction,
    ),
    ThreatPattern(
        name="dd_destruction",
        pattern=r"dd\s+.*if=/dev/(zero|random|urandom).*of=/dev/[sh]d[a-z]",
        description="Disk destruction using dd command",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.FileSystemDestruction,
    ),
    ThreatPattern(
        name="format_drive",
        pattern=r"(format|mkfs\.[a-z]+)\s+[/\\]dev[/\\][sh]d[a-z]",
        description="Formatting system drives",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.FileSystemDestruction,
    ),

    ThreatPattern(
        name="curl_bash_execution",
        pattern=r"(curl|wget)\s+.*\|\s*(bash|sh|zsh|fish|csh|tcsh)",
        description="Remote script execution via curl/wget piped to shell",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.RemoteCodeExecution,
    ),
    ThreatPattern(
        name="bash_process_substitution",
        pattern=r"bash\s*<\s*\(\s*(curl|wget)",
        description="Bash process substitution with remote content",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.RemoteCodeExecution,
    ),
    ThreatPattern(
        name="python_remote_exec",
        pattern=r"python[23]?\s+-c\s+.*urllib|requests.*exec",
        description="Python remote code execution",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.RemoteCodeExecution,
    ),
    ThreatPattern(
        name="powershell_download_exec",
        pattern=r"powershell.*DownloadString.*Invoke-Expression",
        description="PowerShell remote script execution",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.RemoteCodeExecution,
    ),

    ThreatPattern(
        name="ssh_key_exfiltration",
        pattern=r"(curl|wget).*-d.*\.ssh/(id_rsa|id_ed25519|id_ecdsa)",
        description="SSH key exfiltration",
        risk_level=RiskLevel.High,
        category=ThreatCategory.DataExfiltration,
    ),
    ThreatPattern(
        name="password_file_access",
        pattern=r"(cat|grep|awk|sed).*(/etc/passwd|/etc/shadow|\.password|\.env)",
        description="Password file access",
        risk_level=RiskLevel.High,
        category=ThreatCategory.DataExfiltration,
    ),
    ThreatPattern(
        name="history_exfiltration",
        pattern=r"(curl|wget).*-d.*\.(bash_history|zsh_history|history)",
        description="Command history exfiltration",
        risk_level=RiskLevel.High,
        category=ThreatCategory.DataExfiltration,
    ),

    ThreatPattern(
        name="crontab_modification",
        pattern=r"(crontab\s+-e|echo.*>.*crontab|.*>\s*/var/spool/cron)",
        description="Crontab modification for persistence",
        risk_level=RiskLevel.High,
        category=ThreatCategory.SystemModification,
    ),
    ThreatPattern(
        name="systemd_service_creation",
        pattern=r"systemctl.*enable|.*\.service.*>/etc/systemd",
        description="Systemd service creation",
        risk_level=RiskLevel.High,
        category=ThreatCategory.SystemModification,
    ),
    ThreatPattern(
        name="hosts_file_modification",
        pattern=r"echo.*>.*(/etc/hosts|hosts\.txt)",
        description="Hosts file modification",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.SystemModification,
    ),

    ThreatPattern(
        name="netcat_listener",
        pattern=r"nc\s+(-l|-p)\s+\d+",
        description="Netcat listener creation",
        risk_level=RiskLevel.High,
        category=ThreatCategory.NetworkAccess,
    ),
    ThreatPattern(
        name="reverse_shell",
        pattern=r"(nc|netcat|bash|sh).*-e\s*(bash|sh|/bin/bash|/bin/sh)",
        description="Reverse shell creation",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.NetworkAccess,
    ),
    ThreatPattern(
        name="ssh_tunnel",
        pattern=r"ssh\s+.*-[LRD]\s+\d+:",
        description="SSH tunnel creation",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.NetworkAccess,
    ),

    ThreatPattern(
        name="kill_security_process",
        pattern=r"kill(all)?\s+.*\b(antivirus|firewall|defender|security|monitor)\b",
        description="Killing security processes",
        risk_level=RiskLevel.High,
        category=ThreatCategory.ProcessManipulation,
    ),
    ThreatPattern(
        name="process_injection",
        pattern=r"gdb\s+.*attach|ptrace.*PTRACE_POKETEXT",
        description="Process injection techniques",
        risk_level=RiskLevel.High,
        category=ThreatCategory.ProcessManipulation,
    ),

    ThreatPattern(
        name="sudo_without_password",
        pattern=r"echo.*NOPASSWD.*>.*sudoers",
        description="Sudo privilege escalation",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.PrivilegeEscalation,
    ),
    ThreatPattern(
        name="suid_binary_creation",
        pattern=r"chmod\s+[47][0-7][0-7][0-7]|chmod\s+\+s",
        description="SUID binary creation",
        risk_level=RiskLevel.High,
        category=ThreatCategory.PrivilegeEscalation,
    ),

    ThreatPattern(
        name="command_substitution",
        pattern=(r"\$\([^)]*[;&|><][^)]*\)|`[^`]*[;&|><][^`]*`"),
        description="Command substitution with shell operators",
        risk_level=RiskLevel.High,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="shell_metacharacters",
        pattern=r"[;&|`$(){}\[\\]\\]",
        description="Shell metacharacters in input",
        risk_level=RiskLevel.Low,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="encoded_commands",
        pattern=r"(base64|hex|url).*decode.*\|\s*(bash|sh)",
        description="Encoded command execution",
        risk_level=RiskLevel.High,
        category=ThreatCategory.CommandInjection,
    ),

    ThreatPattern(
        name="base64_encoded_shell",
        pattern=r"(echo|printf)\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|zsh)",
        description="Base64 encoded shell commands",
        risk_level=RiskLevel.High,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="hex_encoded_commands",
        pattern=r"(echo|printf)\s+[0-9a-fA-F\\x]{20,}\s*\|\s*(xxd|od).*\|\s*(bash|sh)",
        description="Hex encoded command execution",
        risk_level=RiskLevel.High,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="string_concatenation_obfuscation",
        pattern=r"(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*){3,}",
        description="String concatenation obfuscation",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="character_escaping",
        pattern=r"\\[x][0-9a-fA-F]{2}|\\[0-7]{3}|\\[nrtbfav\\]",
        description="Character escaping for obfuscation",
        risk_level=RiskLevel.Low,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="eval_with_variables",
        pattern=r"eval\s+\$[A-Za-z_][A-Za-z0-9_]*|\beval\s+.*\$\{",
        description="Eval with variable substitution",
        risk_level=RiskLevel.High,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="indirect_command_execution",
        pattern=(r"\$\([^)]*\$\([^)]*\)[^)]*\)|`[^`]*`[^`]*`"),
        description="Nested command substitution",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="environment_variable_abuse",
        pattern=r"(export|env)\s+[A-Z_]+=.*[;&|]|PATH=.*[;&|]",
        description="Environment variable manipulation",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.SystemModification,
    ),
    ThreatPattern(
        name="unicode_obfuscation",
        pattern=r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}",
        description="Unicode character obfuscation",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.CommandInjection,
    ),
    ThreatPattern(
        name="alternative_shell_invocation",
        pattern=r"(/bin/|/usr/bin/|\./)?(bash|sh|zsh|fish|csh|tcsh|dash)\s+-c\s+.*[;&|]",
        description="Alternative shell invocation patterns",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.CommandInjection,
    ),

    ThreatPattern(
        name="docker_privileged_exec",
        pattern=r"docker\s+(run|exec).*--privileged",
        description="Docker privileged container execution",
        risk_level=RiskLevel.High,
        category=ThreatCategory.PrivilegeEscalation,
    ),
    ThreatPattern(
        name="container_escape",
        pattern=r"(chroot|unshare|nsenter).*--mount|--pid|--net",
        description="Container escape techniques",
        risk_level=RiskLevel.High,
        category=ThreatCategory.PrivilegeEscalation,
    ),
    ThreatPattern(
        name="kernel_module_manipulation",
        pattern=r"(insmod|rmmod|modprobe).*\.ko",
        description="Kernel module manipulation",
        risk_level=RiskLevel.Critical,
        category=ThreatCategory.SystemModification,
    ),
    ThreatPattern(
        name="memory_dump",
        pattern=r"(gcore|gdb.*dump|/proc/[0-9]+/mem)",
        description="Memory dumping techniques",
        risk_level=RiskLevel.High,
        category=ThreatCategory.DataExfiltration,
    ),
    ThreatPattern(
        name="log_manipulation",
        pattern=r"(>\s*/dev/null|truncate.*log|rm.*\.log|echo\s*>\s*/var/log)",
        description="Log file manipulation or deletion",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.SystemModification,
    ),
    ThreatPattern(
        name="file_timestamp_manipulation",
        pattern=r"touch\s+-[amt]\s+|utimes|futimes",
        description="File timestamp manipulation",
        risk_level=RiskLevel.Low,
        category=ThreatCategory.SystemModification,
    ),
    ThreatPattern(
        name="steganography_tools",
        pattern=r"\b(steghide|outguess|jphide|steganos)\b",
        description="Steganography tools usage",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.DataExfiltration,
    ),
    ThreatPattern(
        name="network_scanning",
        pattern=r"\b(nmap|masscan|zmap|unicornscan)\b.*-[sS]",
        description="Network scanning tools",
        risk_level=RiskLevel.Medium,
        category=ThreatCategory.NetworkAccess,
    ),
    ThreatPattern(
        name="password_cracking_tools",
        pattern=r"\b(john|hashcat|hydra|medusa|brutespray)\b",
        description="Password cracking tools",
        risk_level=RiskLevel.High,
        category=ThreatCategory.PrivilegeEscalation,
    ),
]

# Compile patterns on module load
COMPILED_PATTERNS: Dict[str, re.Pattern] = {}
for threat in THREAT_PATTERNS:
    try:
        COMPILED_PATTERNS[threat.name] = re.compile(threat.pattern, re.IGNORECASE)
    except re.error as err:
        # Print to stderr-like output; avoid crashing import
        print(f"Failed to compile pattern {threat.name}: {err}")


@dataclass
class PatternMatch:
    threat: ThreatPattern
    matched_text: str
    start_pos: int
    end_pos: int


class PatternMatcher:
    def __init__(self) -> None:
        self.patterns = COMPILED_PATTERNS

    def scan_text(self, text: str) -> List[PatternMatch]:
        matches: List[PatternMatch] = []

        for threat in THREAT_PATTERNS:
            regex = self.patterns.get(threat.name)
            if regex is None:
                continue

            for m in regex.finditer(text):
                matches.append(
                    PatternMatch(
                        threat=threat,
                        matched_text=m.group(0),
                        start_pos=m.start(),
                        end_pos=m.end(),
                    )
                )

        # Sort by risk level (highest first), then by position in text
        risk_order = [RiskLevel.Critical, RiskLevel.High, RiskLevel.Medium, RiskLevel.Low]

        def sort_key(pm: PatternMatch):
            return (risk_order.index(pm.threat.risk_level), pm.start_pos)

        matches.sort(key=sort_key)
        return matches

    def get_max_risk_level(self, matches: List[PatternMatch]) -> Optional[RiskLevel]:
        if not matches:
            return None
        risk_order = [RiskLevel.Critical, RiskLevel.High, RiskLevel.Medium, RiskLevel.Low]
        max_risk: Optional[RiskLevel] = None
        max_index = len(risk_order)
        for m in matches:
            idx = risk_order.index(m.threat.risk_level)
            if idx < max_index:
                max_index = idx
                max_risk = m.threat.risk_level
        return max_risk

    def has_critical_threats(self, matches: List[PatternMatch]) -> bool:
        return any(m.threat.risk_level in (RiskLevel.Critical, RiskLevel.High) for m in matches)

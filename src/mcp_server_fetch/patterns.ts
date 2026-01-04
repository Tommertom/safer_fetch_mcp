/**
 * TypeScript port of goose security patterns
 * 
 * Original source: https://github.com/block/goose
 * Rust implementation: crates/goose/src/security/patterns.rs
 * 
 * Security threat patterns for command injection detection.
 * These patterns detect dangerous shell commands and injection attempts.
 */

export enum RiskLevel {
  Low = 'Low',           // Minor security issue
  Medium = 'Medium',     // Moderate security concern
  High = 'High',         // Significant security risk
  Critical = 'Critical', // Immediate system compromise risk
}

export enum ThreatCategory {
  FileSystemDestruction = 'FileSystemDestruction',
  RemoteCodeExecution = 'RemoteCodeExecution',
  DataExfiltration = 'DataExfiltration',
  SystemModification = 'SystemModification',
  NetworkAccess = 'NetworkAccess',
  ProcessManipulation = 'ProcessManipulation',
  PrivilegeEscalation = 'PrivilegeEscalation',
  CommandInjection = 'CommandInjection',
}

export interface ThreatPattern {
  name: string;
  pattern: string;
  description: string;
  riskLevel: RiskLevel;
  category: ThreatCategory;
}

export function confidenceScore(riskLevel: RiskLevel): number {
  switch (riskLevel) {
    case RiskLevel.Critical:
      return 0.95;
    case RiskLevel.High:
      return 0.85;
    case RiskLevel.Medium:
      return 0.70;
    case RiskLevel.Low:
      return 0.55;
  }
}

export const THREAT_PATTERNS: ThreatPattern[] = [
  // Critical filesystem destruction patterns
  {
    name: 'rm_rf_root',
    pattern: String.raw`rm\s+(-[rf]*[rf][rf]*|--recursive|--force).*[/\\]`,
    description: 'Recursive file deletion with rm -rf',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.FileSystemDestruction,
  },
  {
    name: 'rm_rf_system',
    pattern: String.raw`rm\s+(-[rf]*[rf][rf]*|--recursive|--force).*(bin|etc|usr|var|sys|proc|dev|boot|lib|opt|srv|tmp)`,
    description: 'Recursive deletion of system directories',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.FileSystemDestruction,
  },
  {
    name: 'dd_destruction',
    pattern: String.raw`dd\s+.*if=/dev/(zero|random|urandom).*of=/dev/[sh]d[a-z]`,
    description: 'Disk destruction using dd command',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.FileSystemDestruction,
  },
  {
    name: 'format_drive',
    pattern: String.raw`(format|mkfs\.[a-z]+)\s+[/\\]dev[/\\][sh]d[a-z]`,
    description: 'Formatting system drives',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.FileSystemDestruction,
  },
  // Remote code execution patterns
  {
    name: 'curl_bash_execution',
    pattern: String.raw`(curl|wget)\s+.*\|\s*(bash|sh|zsh|fish|csh|tcsh)`,
    description: 'Remote script execution via curl/wget piped to shell',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.RemoteCodeExecution,
  },
  {
    name: 'bash_process_substitution',
    pattern: String.raw`bash\s*<\s*\(\s*(curl|wget)`,
    description: 'Bash process substitution with remote content',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.RemoteCodeExecution,
  },
  {
    name: 'python_remote_exec',
    pattern: String.raw`python[23]?\s+-c\s+.*urllib|requests.*exec`,
    description: 'Python remote code execution',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.RemoteCodeExecution,
  },
  {
    name: 'powershell_download_exec',
    pattern: String.raw`powershell.*DownloadString.*Invoke-Expression`,
    description: 'PowerShell remote script execution',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.RemoteCodeExecution,
  },
  // Data exfiltration patterns
  {
    name: 'ssh_key_exfiltration',
    pattern: String.raw`(curl|wget).*-d.*\.ssh/(id_rsa|id_ed25519|id_ecdsa)`,
    description: 'SSH key exfiltration',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.DataExfiltration,
  },
  {
    name: 'password_file_access',
    pattern: String.raw`(cat|grep|awk|sed).*(/etc/passwd|/etc/shadow|\.password|\.env)`,
    description: 'Password file access',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.DataExfiltration,
  },
  {
    name: 'history_exfiltration',
    pattern: String.raw`(curl|wget).*-d.*\.(bash_history|zsh_history|history)`,
    description: 'Command history exfiltration',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.DataExfiltration,
  },
  // System modification patterns
  {
    name: 'crontab_modification',
    pattern: String.raw`(crontab\s+-e|echo.*>.*crontab|.*>\s*/var/spool/cron)`,
    description: 'Crontab modification for persistence',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.SystemModification,
  },
  {
    name: 'systemd_service_creation',
    pattern: String.raw`systemctl.*enable|.*\.service.*>/etc/systemd`,
    description: 'Systemd service creation',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.SystemModification,
  },
  {
    name: 'hosts_file_modification',
    pattern: String.raw`echo.*>.*(/etc/hosts|hosts\.txt)`,
    description: 'Hosts file modification',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.SystemModification,
  },
  // Network access patterns
  {
    name: 'netcat_listener',
    pattern: String.raw`nc\s+(-l|-p)\s+\d+`,
    description: 'Netcat listener creation',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.NetworkAccess,
  },
  {
    name: 'reverse_shell',
    pattern: String.raw`(nc|netcat|bash|sh).*-e\s*(bash|sh|/bin/bash|/bin/sh)`,
    description: 'Reverse shell creation',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.NetworkAccess,
  },
  {
    name: 'ssh_tunnel',
    pattern: String.raw`ssh\s+.*-[LRD]\s+\d+:`,
    description: 'SSH tunnel creation',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.NetworkAccess,
  },
  // Process manipulation patterns
  {
    name: 'kill_security_process',
    pattern: String.raw`kill(all)?\s+.*\b(antivirus|firewall|defender|security|monitor)\b`,
    description: 'Killing security processes',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.ProcessManipulation,
  },
  {
    name: 'process_injection',
    pattern: String.raw`gdb\s+.*attach|ptrace.*PTRACE_POKETEXT`,
    description: 'Process injection techniques',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.ProcessManipulation,
  },
  // Privilege escalation patterns
  {
    name: 'sudo_without_password',
    pattern: String.raw`echo.*NOPASSWD.*>.*sudoers`,
    description: 'Sudo privilege escalation',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.PrivilegeEscalation,
  },
  {
    name: 'suid_binary_creation',
    pattern: String.raw`chmod\s+[47][0-7][0-7][0-7]|chmod\s+\+s`,
    description: 'SUID binary creation',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.PrivilegeEscalation,
  },
  // Command injection patterns
  {
    name: 'command_substitution',
    pattern: String.raw`\$\([^)]*[;&|><][^)]*\)|` + '`[^`]*[;&|><][^`]*`',
    description: 'Command substitution with shell operators',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'shell_metacharacters',
    pattern: String.raw`[;&|` + '`$(){}[\\]\\\\]',
    description: 'Shell metacharacters in input',
    riskLevel: RiskLevel.Low,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'encoded_commands',
    pattern: String.raw`(base64|hex|url).*decode.*\|\s*(bash|sh)`,
    description: 'Encoded command execution',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.CommandInjection,
  },
  // Obfuscation and evasion patterns
  {
    name: 'base64_encoded_shell',
    pattern: String.raw`(echo|printf)\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|zsh)`,
    description: 'Base64 encoded shell commands',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'hex_encoded_commands',
    pattern: String.raw`(echo|printf)\s+[0-9a-fA-F\\x]{20,}\s*\|\s*(xxd|od).*\|\s*(bash|sh)`,
    description: 'Hex encoded command execution',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'string_concatenation_obfuscation',
    pattern: String.raw`(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*){3,}`,
    description: 'String concatenation obfuscation',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'character_escaping',
    pattern: String.raw`\\[x][0-9a-fA-F]{2}|\\[0-7]{3}|\\[nrtbfav\\]`,
    description: 'Character escaping for obfuscation',
    riskLevel: RiskLevel.Low,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'eval_with_variables',
    pattern: String.raw`eval\s+\$[A-Za-z_][A-Za-z0-9_]*|\beval\s+.*\$\{`,
    description: 'Eval with variable substitution',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'indirect_command_execution',
    pattern: String.raw`\$\([^)]*\$\([^)]*\)[^)]*\)|` + '`[^`]*`[^`]*`',
    description: 'Nested command substitution',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'environment_variable_abuse',
    pattern: String.raw`(export|env)\s+[A-Z_]+=.*[;&|]|PATH=.*[;&|]`,
    description: 'Environment variable manipulation',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.SystemModification,
  },
  {
    name: 'unicode_obfuscation',
    pattern: String.raw`\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}`,
    description: 'Unicode character obfuscation',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.CommandInjection,
  },
  {
    name: 'alternative_shell_invocation',
    pattern: String.raw`(/bin/|/usr/bin/|\./)?(bash|sh|zsh|fish|csh|tcsh|dash)\s+-c\s+.*[;&|]`,
    description: 'Alternative shell invocation patterns',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.CommandInjection,
  },
  // Additional dangerous commands
  {
    name: 'docker_privileged_exec',
    pattern: String.raw`docker\s+(run|exec).*--privileged`,
    description: 'Docker privileged container execution',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.PrivilegeEscalation,
  },
  {
    name: 'container_escape',
    pattern: String.raw`(chroot|unshare|nsenter).*--mount|--pid|--net`,
    description: 'Container escape techniques',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.PrivilegeEscalation,
  },
  {
    name: 'kernel_module_manipulation',
    pattern: String.raw`(insmod|rmmod|modprobe).*\.ko`,
    description: 'Kernel module manipulation',
    riskLevel: RiskLevel.Critical,
    category: ThreatCategory.SystemModification,
  },
  {
    name: 'memory_dump',
    pattern: String.raw`(gcore|gdb.*dump|/proc/[0-9]+/mem)`,
    description: 'Memory dumping techniques',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.DataExfiltration,
  },
  {
    name: 'log_manipulation',
    pattern: String.raw`(>\s*/dev/null|truncate.*log|rm.*\.log|echo\s*>\s*/var/log)`,
    description: 'Log file manipulation or deletion',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.SystemModification,
  },
  {
    name: 'file_timestamp_manipulation',
    pattern: String.raw`touch\s+-[amt]\s+|utimes|futimes`,
    description: 'File timestamp manipulation',
    riskLevel: RiskLevel.Low,
    category: ThreatCategory.SystemModification,
  },
  {
    name: 'steganography_tools',
    pattern: String.raw`\b(steghide|outguess|jphide|steganos)\b`,
    description: 'Steganography tools usage',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.DataExfiltration,
  },
  {
    name: 'network_scanning',
    pattern: String.raw`\b(nmap|masscan|zmap|unicornscan)\b.*-[sS]`,
    description: 'Network scanning tools',
    riskLevel: RiskLevel.Medium,
    category: ThreatCategory.NetworkAccess,
  },
  {
    name: 'password_cracking_tools',
    pattern: String.raw`\b(john|hashcat|hydra|medusa|brutespray)\b`,
    description: 'Password cracking tools',
    riskLevel: RiskLevel.High,
    category: ThreatCategory.PrivilegeEscalation,
  },
];

// Compile patterns on module load
const COMPILED_PATTERNS = new Map<string, RegExp>();
for (const threat of THREAT_PATTERNS) {
  try {
    COMPILED_PATTERNS.set(threat.name, new RegExp(threat.pattern, 'i'));
  } catch (error) {
    console.error(`Failed to compile pattern ${threat.name}:`, error);
  }
}

export interface PatternMatch {
  threat: ThreatPattern;
  matchedText: string;
  startPos: number;
  endPos: number;
}

export class PatternMatcher {
  private patterns: Map<string, RegExp>;

  constructor() {
    this.patterns = COMPILED_PATTERNS;
  }

  /**
   * Scan text for security threat patterns
   */
  scanText(text: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const threat of THREAT_PATTERNS) {
      const regex = this.patterns.get(threat.name);
      if (!regex) continue;

      let match: RegExpExecArray | null;
      // Reset regex state
      regex.lastIndex = 0;
      
      while ((match = regex.exec(text)) !== null) {
        matches.push({
          threat,
          matchedText: match[0],
          startPos: match.index,
          endPos: match.index + match[0].length,
        });
        
        // Prevent infinite loops on zero-width matches
        if (match.index === regex.lastIndex) {
          regex.lastIndex++;
        }
      }
    }

    // Sort by risk level (highest first), then by position in text
    matches.sort((a, b) => {
      const riskOrder = [RiskLevel.Critical, RiskLevel.High, RiskLevel.Medium, RiskLevel.Low];
      const riskA = riskOrder.indexOf(a.threat.riskLevel);
      const riskB = riskOrder.indexOf(b.threat.riskLevel);
      
      if (riskA !== riskB) {
        return riskA - riskB;
      }
      return a.startPos - b.startPos;
    });

    return matches;
  }

  /**
   * Get the highest risk level from matches
   */
  getMaxRiskLevel(matches: PatternMatch[]): RiskLevel | null {
    if (matches.length === 0) return null;

    const riskOrder = [RiskLevel.Critical, RiskLevel.High, RiskLevel.Medium, RiskLevel.Low];
    let maxRisk: RiskLevel | null = null;
    let maxRiskIndex = riskOrder.length;

    for (const match of matches) {
      const index = riskOrder.indexOf(match.threat.riskLevel);
      if (index < maxRiskIndex) {
        maxRiskIndex = index;
        maxRisk = match.threat.riskLevel;
      }
    }

    return maxRisk;
  }

  /**
   * Check if any critical or high-risk patterns are detected
   */
  hasCriticalThreats(matches: PatternMatch[]): boolean {
    return matches.some(
      (m) => m.threat.riskLevel === RiskLevel.Critical || m.threat.riskLevel === RiskLevel.High
    );
  }
}


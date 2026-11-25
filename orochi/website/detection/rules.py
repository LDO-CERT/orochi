import re
from datetime import UTC, datetime
from typing import Any


class DetectionResult:
    """Represents a single behavioral detection result."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        category: str,
        severity: str,
        score: int,
        mitre_technique: str,
        description: str,
        evidence_snippet: str,
        entity: str = "",
        raw_data: dict[str, Any] = None,
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.category = category
        self.severity = severity
        self.score = score
        self.mitre_technique = mitre_technique
        self.description = description
        self.evidence_snippet = evidence_snippet
        self.entity = entity
        self.raw_data = raw_data or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialize the detection result for storage in TriageFinding / JSON."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "score": self.score,
            "mitre_technique": self.mitre_technique,
            "description": self.description,
            "evidence_snippet": self.evidence_snippet,
            "entity": self.entity,
            "raw_data": self.raw_data,
        }


# =====================================================================
# 1. Parent-Process Incoherence Rule
# =====================================================================
def evaluate_parent_child_incoherence(
    processes: list[dict[str, Any]],
) -> list[DetectionResult]:
    """
    Validates Windows process lineage constraints (svchost, lsass, services, smss).
    """
    findings = []
    # Windows XP / 2003 have no wininit.exe: lsass.exe and services.exe are started by winlogon.exe there
    has_wininit = any((p.get("ImageFileName") or p.get("Process") or "").lower() == "wininit.exe" for p in processes)
    session_parents = {"wininit.exe"} if has_wininit else {"wininit.exe", "winlogon.exe"}
    # Index processes by PID -> process dict
    proc_by_pid = {}
    for p in processes:
        pid = p.get("PID")
        if pid is not None:
            proc_by_pid[pid] = p

    for p in processes:
        name = (p.get("ImageFileName") or p.get("Process") or "").lower()
        pid = p.get("PID")
        ppid = p.get("PPID")
        parent = proc_by_pid.get(ppid)
        parent_name = (
            (parent.get("ImageFileName") or parent.get("Process") or "Unknown").lower()
            if parent
            else f"Dead or Unlinked PID {ppid}"
        )

        # Rule: svchost.exe parent MUST be services.exe
        if name == "svchost.exe":
            if parent and parent_name != "services.exe":
                findings.append(
                    DetectionResult(
                        rule_id="PROC_INCOHERENT_PARENT_SVCHOST",
                        rule_name="Abnormal Parent Process for svchost.exe",
                        category="Process Tree",
                        severity="Critical",
                        score=40,
                        mitre_technique="T1036.005 - Masquerading: Match Legitimate Name",
                        description=(
                            "svchost.exe should exclusively be spawned by the Service Control Manager (services.exe). "
                            f"Detected svchost.exe (PID {pid}) spawned by {parent_name} (PID {ppid})."
                        ),
                        evidence_snippet=f"Process: svchost.exe (PID {pid}) | Parent: {parent_name} (PPID {ppid})",
                        entity=f"svchost.exe (PID {pid})",
                        raw_data=p,
                    )
                )

        # Rule: lsass.exe parent MUST be wininit.exe (winlogon.exe on systems without wininit)
        elif name == "lsass.exe":
            if parent and parent_name not in session_parents:
                findings.append(
                    DetectionResult(
                        rule_id="PROC_INCOHERENT_PARENT_LSASS",
                        rule_name="Abnormal Parent Process for lsass.exe",
                        category="Process Tree",
                        severity="Critical",
                        score=45,
                        mitre_technique="T1003.001 - OS Credential Dumping: LSASS Memory",
                        description=(
                            "lsass.exe must be launched by wininit.exe during system initialization. "
                            f"Detected lsass.exe (PID {pid}) spawned by {parent_name} (PID {ppid}), indicating possible credential theft or masquerading."
                        ),
                        evidence_snippet=f"Process: lsass.exe (PID {pid}) | Parent: {parent_name} (PPID {ppid})",
                        entity=f"lsass.exe (PID {pid})",
                        raw_data=p,
                    )
                )

        # Rule: services.exe parent MUST be wininit.exe (winlogon.exe on systems without wininit)
        elif name == "services.exe":
            if parent and parent_name not in session_parents:
                findings.append(
                    DetectionResult(
                        rule_id="PROC_INCOHERENT_PARENT_SERVICES",
                        rule_name="Abnormal Parent Process for services.exe",
                        category="Process Tree",
                        severity="High",
                        score=30,
                        mitre_technique="T1036.005 - Masquerading: Match Legitimate Name",
                        description=(
                            f"services.exe (PID {pid}) was spawned by {parent_name} (PID {ppid}) instead of wininit.exe."
                        ),
                        evidence_snippet=f"Process: services.exe (PID {pid}) | Parent: {parent_name} (PPID {ppid})",
                        entity=f"services.exe (PID {pid})",
                        raw_data=p,
                    )
                )

        # Rule: smss.exe parent must be System (PID 4) or smss.exe
        elif name == "smss.exe":
            if parent and ppid != 4 and parent_name != "smss.exe":
                findings.append(
                    DetectionResult(
                        rule_id="PROC_INCOHERENT_PARENT_SMSS",
                        rule_name="Abnormal Parent Process for smss.exe",
                        category="Process Tree",
                        severity="High",
                        score=30,
                        mitre_technique="T1036.005 - Masquerading: Match Legitimate Name",
                        description=(
                            f"smss.exe (PID {pid}) was spawned by {parent_name} (PID {ppid}) instead of System (PID 4)."
                        ),
                        evidence_snippet=f"Process: smss.exe (PID {pid}) | Parent: {parent_name} (PPID {ppid})",
                        entity=f"smss.exe (PID {pid})",
                        raw_data=p,
                    )
                )

    return findings


# =====================================================================
# 2. Process Masquerading & Path Anomalies Rule
# =====================================================================
SUSPICIOUS_PATHS = [
    r"c:\users",
    r"c:\temp",
    r"c:\windows\temp",
    r"\appdata",
    r"c:\programdata",
    r"/tmp",
    r"/var/tmp",
    r"/dev/shm",
]

SYSTEM_BINARIES = {
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "winlogon.exe",
    "wininit.exe",
}

TYPOSQUAT_NAMES = {
    "scvhost.exe",
    "svch0st.exe",
    "svhost.exe",
    "lssas.exe",
    "lsas.exe",
    "csrsss.exe",
    "explorerr.exe",
    "taskmngr.exe",
    "iexplore.exe",
}


def evaluate_process_masquerading(
    processes: list[dict[str, Any]], cmdlines: list[dict[str, Any]]
) -> list[DetectionResult]:
    """
    Detects system binaries executing from user/temporary directories or typosquatted names.
    """
    findings = []
    pid_to_args = {c.get("PID"): (c.get("Args") or c.get("CommandLine") or "") for c in cmdlines if c.get("PID")}

    for p in processes:
        raw_name = p.get("ImageFileName") or p.get("Process") or ""
        name = raw_name.lower()
        pid = p.get("PID")
        args = pid_to_args.get(pid, "").lower()
        proc_path = (p.get("Path") or p.get("ImagePath") or args).lower()

        # Check typosquatting
        if name in TYPOSQUAT_NAMES:
            findings.append(
                DetectionResult(
                    rule_id="PROC_TYPOSQUAT_MASQUERADE",
                    rule_name="Typosquatted / Masqueraded Process Name",
                    category="Masquerading & Path Anomaly",
                    severity="Critical",
                    score=45,
                    mitre_technique="T1036.005 - Masquerading: Match Legitimate Name",
                    description=(
                        f"Detected process '{raw_name}' (PID {pid}) mimicking legitimate Windows system binaries."
                    ),
                    evidence_snippet=f"ImageFileName: {raw_name} | PID: {pid}",
                    entity=f"{raw_name} (PID {pid})",
                    raw_data=p,
                )
            )

        # Check system binary path anomaly in cmdline args or process path
        if name in SYSTEM_BINARIES and proc_path:
            for s_path in SUSPICIOUS_PATHS:
                if s_path in proc_path:
                    findings.append(
                        DetectionResult(
                            rule_id="PROC_SUSPICIOUS_PATH",
                            rule_name="System Critical Binary Executing from User/Temp Path",
                            category="Masquerading & Path Anomaly",
                            severity="Critical",
                            score=40,
                            mitre_technique="T1036.005 - Masquerading: Match Legitimate Name",
                            description=(
                                f"System binary '{raw_name}' (PID {pid}) executed from suspicious path: {proc_path[:120]}"
                            ),
                            evidence_snippet=f"Process: {raw_name} | Path: {proc_path}",
                            entity=f"{raw_name} (PID {pid})",
                            raw_data={"process": p, "path": proc_path},
                        )
                    )
                    break

    return findings


# =====================================================================
# 3. DKOM Stealth / Unlinked Process Rule
# =====================================================================
def _parse_create_time(value: Any) -> datetime | None:
    """Parse a plugin CreateTime (ISO string or datetime) as an aware datetime; invalid values give None."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace(" UTC", ""))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def evaluate_dkom_unlinked(pslist: list[dict[str, Any]], psscan: list[dict[str, Any]]) -> list[DetectionResult]:
    """
    Identifies hidden / unlinked processes discovered in memory pool scan (psscan) but missing from pslist.

    Exited processes and processes created before the current boot (stale EPROCESS structures left in RAM by
    a previous session) are not reported: only a live process missing from the active list is suspicious.
    """
    findings = []
    active_pids = {p.get("PID") for p in pslist if p.get("PID") is not None}
    active_created = [t for t in (_parse_create_time(p.get("CreateTime")) for p in pslist) if t is not None]
    boot_time = min(active_created) if active_created else None

    for p in psscan:
        pid = p.get("PID")
        exit_time = p.get("ExitTime")
        name = p.get("ImageFileName") or p.get("Process") or "Unknown"

        created = _parse_create_time(p.get("CreateTime"))
        if boot_time and created and created < boot_time:
            continue
        # If process was NOT exited and is missing from active pslist -> DKOM rootkit unlinking
        if pid and pid not in active_pids and (not exit_time or str(exit_time).strip() in {"-", "N/A", ""}):
            findings.append(
                DetectionResult(
                    rule_id="STEALTH_DKOM_UNLINKED",
                    rule_name="Hidden Process Unlinked via DKOM",
                    category="Stealth / DKOM",
                    severity="Critical",
                    score=50,
                    mitre_technique="T1014 - Rootkit: Direct Kernel Object Manipulation",
                    description=(
                        f"Process '{name}' (PID {pid}) was found by physical memory tag scanning (psscan) "
                        "but is unlinked from the active process doubly-linked list (pslist/ActiveProcessLinks). "
                        "Strong indicator of rootkit or DKOM evasion."
                    ),
                    evidence_snippet=f"Hidden PID: {pid} | ImageFileName: {name} | Offset: {p.get('Offset', '-')}",
                    entity=f"{name} (PID {pid})",
                    raw_data=p,
                )
            )

    return findings


# =====================================================================
# 4. Suspicious Command Lines & LOLBins Rule
# =====================================================================
POWERSHELL_SUSPICIOUS = [
    "-enc",
    "-encodedcommand",
    "downloadstring",
    "frombase64string",
    "invoke-expression",
    "iex(",
    "iex ",
    "-w hidden",
    "-windowstyle hidden",
    "-nop -noni",
]

LOLBINS_SUSPICIOUS = [
    (r"certutil(\.exe)?.*-urlcache", "Certutil Remote File Download", "T1105"),
    (r"bitsadmin(\.exe)?.*\/transfer", "Bitsadmin Background Transfer", "T1197"),
    (r"mshta(\.exe)?.*http", "Mshta Remote Script Execution", "T1218.005"),
    (
        r"regsvr32(\.exe)?.*\/[uisn]+.*http",
        "Regsvr32 Remote Scriptlet (Squiblydoo)",
        "T1218.010",
    ),
    (r"rundll32(\.exe)?.*javascript:", "Rundll32 Inline Script Protocol", "T1218.011"),
    (r"wmic(\.exe)?.*process call create", "WMIC Remote Process Invocation", "T1047"),
]


def evaluate_suspicious_cmdlines(
    cmdlines: list[dict[str, Any]],
) -> list[DetectionResult]:
    """
    Evaluates command lines for encoded PowerShell and LOLBin abuse.
    """
    findings = []

    for c in cmdlines:
        args = c.get("Args") or c.get("CommandLine") or c.get("Command") or ""
        pid = c.get("PID")
        proc = c.get("Process") or "cmdline"
        args_lower = args.lower()

        # Check PowerShell obfuscation / bypass
        if "powershell" in proc.lower() or "pwsh" in proc.lower() or "powershell" in args_lower:
            for indicator in POWERSHELL_SUSPICIOUS:
                if indicator in args_lower:
                    findings.append(
                        DetectionResult(
                            rule_id="CMD_POWERSHELL_OBFUSCATED",
                            rule_name="Suspicious Obfuscated PowerShell Execution",
                            category="Command Line & LOLBins",
                            severity="High",
                            score=30,
                            mitre_technique="T1059.001 - Command and Scripting Interpreter: PowerShell",
                            description=(
                                f"PowerShell command line contains obfuscation or execution bypass indicator ('{indicator}')."
                            ),
                            evidence_snippet=f"PID: {pid} | Args: {args[:160]}",
                            entity=f"{proc} (PID {pid})",
                            raw_data=c,
                        )
                    )
                    break

        # Check LOLBins
        for pattern, label, mitre_id in LOLBINS_SUSPICIOUS:
            if re.search(pattern, args, re.IGNORECASE):
                findings.append(
                    DetectionResult(
                        rule_id="CMD_LOLBIN_EXECUTION",
                        rule_name=f"LOLBin Abuse: {label}",
                        category="Command Line & LOLBins",
                        severity="High",
                        score=30,
                        mitre_technique=f"{mitre_id} - Living Off The Land Binary Abuse",
                        description=f"Living-off-the-land binary execution detected matching signature: {label}.",
                        evidence_snippet=f"PID: {pid} | Command: {args[:160]}",
                        entity=f"{proc} (PID {pid})",
                        raw_data=c,
                    )
                )
                break

    return findings


# =====================================================================
# 5. Suspicious Network Sockets & C2 Ports Rule
# =====================================================================
C2_PORTS = {4444, 1337, 5555, 8888, 9001, 31337, 4443, 6667}
NON_NETWORK_PROCESSES = {"notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe"}


def evaluate_suspicious_network(netscan: list[dict[str, Any]]) -> list[DetectionResult]:
    """
    Evaluates netscan sockets for known C2 ports and unexpected network-enabled binaries.
    """
    findings = []

    for net in netscan:
        f_port = net.get("ForeignPort")
        l_port = net.get("LocalPort")
        pid = net.get("PID")
        owner = (net.get("Owner") or net.get("Process") or "").lower()
        state = net.get("State") or ""
        proto = net.get("Proto") or "TCP"
        l_addr = net.get("LocalAddr") or ""
        f_addr = net.get("ForeignAddr") or ""

        # Check non-network binary with open socket
        if owner in NON_NETWORK_PROCESSES:
            findings.append(
                DetectionResult(
                    rule_id="NET_INCONGRUOUS_PROCESS",
                    rule_name="Incongruous Network Connection from Non-Network Binary",
                    category="Network & C2",
                    severity="Critical",
                    score=40,
                    mitre_technique="T1071 - Application Layer Protocol",
                    description=(
                        f"Non-network process '{owner}' (PID {pid}) has an active network socket ({state}). "
                        "Indicates process injection or covert channel backdoor."
                    ),
                    evidence_snippet=f"{proto} {l_addr}:{l_port} -> {f_addr}:{f_port} | Owner: {owner} (PID {pid}) | State: {state}",
                    entity=f"{owner} (PID {pid})",
                    raw_data=net,
                )
            )

        # Check C2 ports
        port_to_check = f_port if (f_port and str(f_port).isdigit()) else l_port
        if port_to_check and int(port_to_check) in C2_PORTS:
            findings.append(
                DetectionResult(
                    rule_id="NET_SUSPICIOUS_C2_PORT",
                    rule_name=f"Network Connection on Suspicious C2 Port ({port_to_check})",
                    category="Network & C2",
                    severity="High",
                    score=35,
                    mitre_technique="T1071 - Application Layer Protocol",
                    description=f"Detected socket communicating over known reverse shell / C2 port {port_to_check} associated with {owner or f'PID {str(pid)}'}.",
                    evidence_snippet=f"{proto} {l_addr}:{l_port} -> {f_addr}:{f_port} | Owner: {owner} (PID {pid})",
                    entity=f"{owner or f'PID {str(pid)}'}",
                    raw_data=net,
                )
            )

    return findings


# =====================================================================
# 6. Code Injection Rule (Malfind)
# =====================================================================
def evaluate_code_injection(malfind: list[dict[str, Any]]) -> list[DetectionResult]:
    """
    Evaluate malfind hits (private executable memory) with a severity that matches the evidence.

    - Critical: the region starts with a PE (``MZ``) or ELF header, i.e. an injected executable image.
    - High: writable and executable (RWX) region without an executable header.
    - Medium: executable, non-writable region without header (heaps and shared sections often look like this).
    """
    findings = []

    for m in malfind:
        pid = m.get("PID")
        proc = m.get("Process") or "Unknown"
        protection = m.get("Protection") or "PAGE_EXECUTE_READWRITE"
        start = m.get("Start VPN") or m.get("CommitCharge") or m.get("Tag") or "0x0"
        start_vpn = hex(start) if isinstance(start, int) and not isinstance(start, bool) else str(start)
        hexdump = (m.get("Hexdump") or "").lower().lstrip()

        # Only evaluate executable regions (Windows: PAGE_EXECUTE... or Linux: rwx / r-x)
        prot_upper = protection.upper()
        if "EXECUTE" not in prot_upper and "X" not in prot_upper:
            continue

        # Executable header at the start of the region
        has_mz = hexdump.startswith("4d 5a")
        has_elf = hexdump.startswith("7f 45 4c 46")
        hdr_desc = "PE / MZ" if has_mz else ("ELF" if has_elf else "")
        writable = any(k in prot_upper for k in ("READWRITE", "WRITECOPY")) or "w" in protection.lower().replace(
            "page_", ""
        )
        if hdr_desc:
            rule_name, severity, score = f"Injected Executable Image ({hdr_desc} header)", "Critical", 40
        elif writable:
            rule_name, severity, score = "Executable Private Memory (RWX)", "High", 25
        else:
            rule_name, severity, score = "Executable Private Memory", "Medium", 10

        findings.append(
            DetectionResult(
                rule_id="INJ_MALFIND_EXEC_REGION",
                rule_name=rule_name,
                category="Code Injection",
                severity=severity,
                score=score,
                mitre_technique="T1055 - Process Injection",
                description=(
                    f"malfind found private memory with {protection} permissions in '{proc}' (PID {pid}) at {start_vpn}"
                    + (
                        f", starting with a {hdr_desc} executable header."
                        if hdr_desc
                        else ", without executable header."
                    )
                ),
                evidence_snippet=f"PID: {pid} ({proc}) | Region: {start_vpn} | Protection: {protection}",
                entity=f"{proc} (PID {pid})",
                raw_data=m,
            )
        )

    return findings


# =====================================================================
# 7. Linux Threats (check_syscall & bash history)
# =====================================================================
BASH_SUSPICIOUS_PATTERNS = [
    (r"curl.*\|\s*(ba)?sh", "Remote Script Download & Pipe to Shell"),
    (r"wget.*\|\s*(ba)?sh", "Remote Script Download & Pipe to Shell"),
    (r"/dev/tcp/\d+\.\d+\.\d+\.\d+", "Bash Direct TCP Reverse Shell"),
    (r"nc\s+.*-e\s+/bin/(ba)?sh", "Netcat Traditional Reverse Shell"),
    (r"chmod\s+(\+x|777)\s+/tmp/", "Executable Permissions in Temporary Directory"),
]


def evaluate_linux_threats(
    check_syscall: list[dict[str, Any]], bash_history: list[dict[str, Any]]
) -> list[DetectionResult]:
    """
    Evaluates Linux syscall table hooks and suspicious bash history commands.
    """
    findings = []

    # Syscall hooks
    for sys in check_syscall:
        handler = str(sys.get("Handler") or sys.get("Symbol") or "")
        name = sys.get("Syscall") or sys.get("Table") or "syscall"
        is_hooked = sys.get("Hooked") is True or "unknown" in handler.lower() or "hook" in handler.lower()
        if is_hooked:
            findings.append(
                DetectionResult(
                    rule_id="LINUX_HOOKED_SYSCALL",
                    rule_name="Kernel Rootkit Syscall Table Hook",
                    category="Linux Threats",
                    severity="Critical",
                    score=45,
                    mitre_technique="T1014 - Rootkit",
                    description=(
                        f"System call '{name}' handler does not resolve to a clean kernel symbol. Pointing to {handler}."
                    ),
                    evidence_snippet=f"Syscall: {name} | Handler: {handler}",
                    entity=f"Syscall {name}",
                    raw_data=sys,
                )
            )

    # Bash history
    for b in bash_history:
        cmd = b.get("Command") or ""
        pid = b.get("PID")
        for pattern, label in BASH_SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                findings.append(
                    DetectionResult(
                        rule_id="LINUX_BASH_ANOMALY",
                        rule_name=f"Suspicious Linux Shell Command: {label}",
                        category="Linux Threats",
                        severity="High",
                        score=30,
                        mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
                        description=f"Detected high-risk interactive command in shell history: {cmd[:140]}.",
                        evidence_snippet=f"PID: {pid} | Command: {cmd}",
                        entity=f"PID {pid}" if pid else "Shell History",
                        raw_data=b,
                    )
                )
                break

    return findings

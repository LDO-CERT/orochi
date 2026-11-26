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
                        mitre_technique="T1036.005 - Masquerading: Match Legitimate Name",
                        description=(
                            "lsass.exe must be launched by wininit.exe (or winlogon.exe on Windows XP/2003) during system initialization. "
                            f"Detected lsass.exe (PID {pid}) spawned by {parent_name} (PID {ppid}), indicating possible masquerading."
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


_TERMINATED_LINUX_STATES = {
    "EXIT_DEAD",
    "EXIT_ZOMBIE",
    "EXIT_TRACE",
    "TASK_DEAD",
    "DEAD",
    "ZOMBIE",
}


def _is_terminated_process(row: dict[str, Any]) -> bool:
    """Return True if a psscan row represents a terminated/exited/zombie task."""
    exit_time = row.get("ExitTime")
    if exit_time and str(exit_time).strip() not in {"-", "N/A", "None", ""}:
        return True
    for state_key in ("EXIT_STATE", "ExitState", "exit_state", "State", "STATE", "state"):
        raw_state = row.get(state_key)
        if raw_state is None:
            continue
        state_upper = str(raw_state).strip().upper()
        if not state_upper or state_upper in {"-", "N/A", "NONE", "0"}:
            continue
        if any(term in state_upper for term in _TERMINATED_LINUX_STATES):
            return True
    return False


def _is_non_leader_thread(row: dict[str, Any]) -> bool:
    """Return True if a Linux psscan row is a thread whose TID differs from its PID."""
    pid = row.get("PID") if row.get("PID") is not None else row.get("pid")
    tid = row.get("TID") if row.get("TID") is not None else row.get("tid")
    if pid is None or tid is None:
        return False
    try:
        return int(tid) != int(pid)
    except (TypeError, ValueError):
        return str(tid).strip() != str(pid).strip()


def _has_kernel_object_evidence(row: dict[str, Any]) -> bool:
    """Return True only when the row carries explicit kernel-object linkage/offset evidence."""
    for key in ("Offset", "Offset(V)", "Offset(P)", "OFFSET (P)", "OFFSET (V)"):
        val = row.get(key)
        if val is not None and str(val).strip() not in {"", "-", "N/A", "None", "0", "0x0"}:
            return True
    return False


def evaluate_dkom_unlinked(pslist: list[dict[str, Any]], psscan: list[dict[str, Any]]) -> list[DetectionResult]:
    """
    Identifies hidden / unlinked processes discovered in memory pool scan (psscan) but missing from pslist.

    Exited/terminated/zombie processes, non-leader threads (TID != PID), and processes created before the
    current boot (stale EPROCESS structures left in RAM by a previous session) are excluded.
    """
    findings = []
    active_pids = {p.get("PID") for p in pslist if p.get("PID") is not None}
    active_created = [t for t in (_parse_create_time(p.get("CreateTime")) for p in pslist) if t is not None]
    boot_time = min(active_created) if active_created else None

    for p in psscan:
        pid = p.get("PID")
        if not pid or pid in active_pids:
            continue
        if _is_non_leader_thread(p) or _is_terminated_process(p):
            continue

        created = _parse_create_time(p.get("CreateTime"))
        if boot_time and created and created < boot_time:
            continue

        name = p.get("ImageFileName") or p.get("COMM") or p.get("Comm") or p.get("Process") or "Unknown"
        mitre = (
            "T1014 - Rootkit: Direct Kernel Object Manipulation"
            if _has_kernel_object_evidence(p)
            else "T1564 - Hide Artifacts"
        )
        offset_display = p.get("Offset") or p.get("Offset(V)") or p.get("Offset(P)") or p.get("OFFSET (P)") or "-"
        findings.append(
            DetectionResult(
                rule_id="STEALTH_DKOM_UNLINKED",
                rule_name="Hidden Process Unlinked via DKOM",
                category="Stealth / DKOM",
                severity="Critical",
                score=50,
                mitre_technique=mitre,
                description=(
                    f"Process '{name}' (PID {pid}) was found by physical memory scan (psscan) "
                    "while alive, but is absent from the active process list (pslist)."
                ),
                evidence_snippet=f"Hidden PID: {pid} | Process: {name} | Offset: {offset_display}",
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
        hexdump = (m.get("Hexdump") or m.get("HexDump") or "").lower().lstrip()

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


# =====================================================================
# 8. Unexpected DLL / Shared Library Path Rule (Issue #1543)
# =====================================================================
SUSPICIOUS_DLL_PATH_MARKERS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
)


def evaluate_suspicious_dlls(dll_rows: list[dict[str, Any]]) -> list[DetectionResult]:
    """Flag DLLs/shared libraries loaded from user-writable or temporary directories (Issue #1543)."""
    findings: list[DetectionResult] = []
    seen: set[tuple[Any, str]] = set()

    for row in dll_rows:
        path = str(row.get("Path") or row.get("FullDllName") or row.get("MappedPath") or "").strip()
        if not path:
            continue
        low_path = path.lower()
        if not any(marker in low_path for marker in SUSPICIOUS_DLL_PATH_MARKERS):
            continue
        # Microsoft components (Windows Defender platform, ...) legitimately load from ProgramData\Microsoft
        if "\\programdata\\microsoft\\" in low_path and "\\temp\\" not in low_path:
            continue
        # Exclude known legitimate browser / system updater DLLs if not in temp/public
        if low_path.endswith((".ttf", ".otf", ".nls", ".mui")):
            continue

        pid = row.get("PID") or row.get("Pid")
        proc = row.get("Process") or row.get("ImageFileName") or "Unknown"
        key = (pid, low_path)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            DetectionResult(
                rule_id="DLL_SUSPICIOUS_PATH",
                rule_name="Library Loaded from Unexpected Path",
                category="Persistence / Hijacking",
                severity="High",
                score=30,
                mitre_technique="T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking",
                description=(
                    f"Process '{proc}' (PID {pid}) loaded module '{path}' from a user-writable or temporary location."
                ),
                evidence_snippet=f"PID: {pid} | Process: {proc} | Path: {path}",
                entity=f"{proc} (PID {pid})" if pid else path,
                raw_data=row,
            )
        )

    return findings


# =====================================================================
# 9. YARA Hits, Extracted Files & Known-Bad Reputation Hashes (Issue #1543)
# =====================================================================
def evaluate_yara_and_extracted_files(
    yara_rows: list[dict[str, Any]],
    dumpfiles_rows: list[dict[str, Any]],
    malicious_iocs: list[Any] | None = None,
) -> list[DetectionResult]:
    """Score YARA matches, malicious extracted files (ClamAV), and known-bad hashes (VT/MISP/IOCs)."""
    findings: list[DetectionResult] = []

    # 1. Group YARA hits by (rule, pid/process) so 1000+ hits surface cleanly in triage
    yara_groups: dict[tuple[str, Any, str], list[dict[str, Any]]] = {}
    for row in yara_rows:
        rule_name = str(row.get("Rule") or row.get("rule") or "").strip()
        if not rule_name:
            continue
        pid = row.get("PID") or row.get("Pid")
        proc = str(row.get("Process") or row.get("ImageFileName") or "Memory").strip()
        yara_groups.setdefault((rule_name, pid, proc), []).append(row)

    for (rule_name, pid, proc), group_rows in yara_groups.items():
        count = len(group_rows)
        sample = group_rows[0]
        offset = sample.get("Offset") or sample.get("offset") or "-"
        entity = f"{proc} (PID {pid})" if pid else f"YARA: {rule_name}"
        findings.append(
            DetectionResult(
                rule_id="YARA_RULE_MATCH",
                rule_name=f"YARA Match: {rule_name}",
                category="YARA / Signatures",
                # A YARA hit says what matched, not which technique: no ATT&CK technique is inferred,
                # and the rule's own severity is unknown, so many hits do not escalate it to Critical
                severity="High",
                score=35,
                mitre_technique="",
                description=(f"YARA rule '{rule_name}' matched {count} time(s) in {entity} (first offset: {offset})."),
                evidence_snippet=f"Rule: {rule_name} | Matches: {count} | Entity: {entity} | Offset: {offset}",
                entity=entity,
                raw_data={"rule": rule_name, "count": count, "sample": sample},
            )
        )

    # 2. Extracted files flagged by ClamAV or reputation
    seen_files: set[str] = set()
    for row in dumpfiles_rows:
        clamav = str(row.get("clamav") or "").strip()
        sha256 = str(row.get("sha256") or "").strip()
        filename = str(row.get("FileName") or row.get("File output") or row.get("Cache") or "extracted_file").strip()
        if clamav and clamav not in {"-", "N/A", "OK", "None"}:
            key = sha256 or filename
            if key in seen_files:
                continue
            seen_files.add(key)
            findings.append(
                DetectionResult(
                    rule_id="EXTRACTED_FILE_MALICIOUS",
                    rule_name=f"Malicious Extracted File ({clamav})",
                    category="Extracted Files",
                    severity="Critical",
                    score=45,
                    mitre_technique="T1204 - User Execution",
                    description=f"Extracted file '{filename}' (SHA-256: {sha256 or 'N/A'}) matched ClamAV signature '{clamav}'.",
                    evidence_snippet=f"File: {filename} | ClamAV: {clamav} | SHA256: {sha256 or '-'}",
                    entity=filename,
                    raw_data=row,
                )
            )

    # 3. Known-bad hashes from enriched DumpIOC (VT / MISP / OTX)
    for ioc in malicious_iocs or []:
        if getattr(ioc, "ioc_type", None) not in {"hash_sha256", "hash_md5"}:
            continue
        if not getattr(ioc, "is_malicious", False):
            continue
        val = str(ioc.value)
        if val in seen_files:
            continue
        seen_files.add(val)
        ctx = ioc.context if isinstance(ioc.context, dict) else {}
        fname = ctx.get("filename") or val[:16]
        findings.append(
            DetectionResult(
                rule_id="KNOWN_BAD_HASH_REPUTATION",
                rule_name="Known-Bad File Hash (Threat Intel)",
                category="Threat Intelligence",
                severity="Critical",
                score=50,
                mitre_technique="T1204 - User Execution",
                description=(
                    f"Extracted file '{fname}' hash {val} is flagged malicious by threat intelligence "
                    f"(score: {ioc.threat_score})."
                ),
                evidence_snippet=f"Hash: {val} | File: {fname} | Score: {ioc.threat_score}",
                entity=f"{fname} ({val[:12]}...)",
                raw_data={"ioc_type": ioc.ioc_type, "value": val, "enrichment": ioc.enrichment},
            )
        )

    return findings


# =====================================================================
# 10. Unexpected / Unlinked Kernel Drivers (Issue #1543, optional signal)
# =====================================================================
# Prefixes the kernel uses for the Windows directory in module paths (``\SystemRoot\``, ``\??\C:\Windows\``, ...)
_WINDIR_PREFIX_RE = re.compile(
    r"^(?:\\systemroot\\"
    r"|(?:\\\?\?\\|\\\\\?\\|\\device\\harddiskvolume\d+\\|[a-z]:\\|\\)?(?:[a-z]:\\)?(?:windows|winnt)\\)",
    re.IGNORECASE,
)
# Locations under the Windows directory that are user-writable and never hold a legitimate driver
_WINDIR_WRITABLE_SUBDIRS = ("temp\\", "tasks\\", "debug\\", "tracing\\")


def _to_int(value: Any) -> int | None:
    """Plugin rows store addresses as int (JSON) or hex/decimal strings; return None when absent or zero-like."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text or text in {"-", "N/A"}:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _is_expected_driver_path(path: str) -> bool:
    """True for a kernel module path inside the Windows directory (``\\SystemRoot\\System32\\drivers\\``, ...)."""
    # The boot loader records boot-start drivers (ACPI.sys, Ntfs.sys, ...) by file name alone; it only loads
    # them from System32\\drivers
    if "\\" not in path and "/" not in path:
        return True
    # Microsoft Defender loads its signed kernel driver from its definition updates folder
    if "\\programdata\\microsoft\\windows defender\\" in path.lower():
        return True
    match = _WINDIR_PREFIX_RE.match(path)
    if not match:
        return False
    rest = path[match.end() :].lower()
    return bool(rest) and not rest.startswith(_WINDIR_WRITABLE_SUBDIRS)


# A driver object's name (``\\Driver\\Tcpip``); pool-scan hits on freed memory carry garbage instead
_DRIVER_OBJECT_NAME_RE = re.compile(r"^\\(?:Driver|FileSystem)\\[\x21-\x7e]+$")


def _driver_short_name(value: Any) -> str:
    """``\\Driver\\Tcpip`` / ``\\FileSystem\\Ntfs`` / ``tcpip.sys`` -> ``tcpip`` / ``ntfs`` for name matching."""
    name = str(value or "").strip().replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return name.rsplit(".", 1)[0] if name.endswith((".sys", ".dll", ".exe")) else name


def evaluate_unexpected_drivers(
    driver_rows: list[dict[str, Any]], module_rows: list[dict[str, Any]]
) -> list[DetectionResult]:
    """
    Flag kernel drivers that a clean Windows system does not have (Issue #1543).

    - ``windows.modules.Modules`` entry loaded from outside the Windows directory, from a writable folder inside it
      (``\\Windows\\Temp\\``), or with no path at all (T1543.003).
    - ``windows.driverscan.DriverScan`` driver object whose code does not lie inside any module of the loaded
      module list, i.e. a driver hidden from ``PsLoadedModuleList`` (T1014). Driver objects without a start
      address (built-in pseudo drivers such as ``\\Driver\\PnpManager``), objects without a readable
      ``\\Driver\\`` / ``\\FileSystem\\`` name (stale pool-scan hits) and drivers whose name matches a listed
      module are not flagged. Needs both plugins: without the module list every driver would look unlinked.
    """
    findings: list[DetectionResult] = []
    seen_paths: set[str] = set()

    ranges: list[tuple[int, int]] = []
    module_names: set[str] = set()
    for mod in module_rows:
        name = str(mod.get("Name") or "").strip()
        path = str(mod.get("Path") or "").strip()
        base = _to_int(mod.get("Base"))
        size = _to_int(mod.get("Size")) or 0
        if base:
            ranges.append((base, base + max(size, 1)))
        if name:
            module_names.add(_driver_short_name(name))
        if path:
            module_names.add(_driver_short_name(path))

        if path and _is_expected_driver_path(path):
            continue
        key = (path or name or str(base)).lower()
        if not key or key in seen_paths:
            continue
        seen_paths.add(key)
        label = name or path or (hex(base) if base else "unknown")
        reason = f"from '{path}', outside the Windows directory" if path else "without a backing file path"
        findings.append(
            DetectionResult(
                rule_id="DRIVER_UNEXPECTED_PATH",
                rule_name="Kernel Driver from Unexpected Location",
                category="Rootkit / Kernel",
                severity="High",
                score=30,
                mitre_technique="T1543.003 - Create or Modify System Process: Windows Service",
                description=f"Kernel module '{label}' is loaded {reason}.",
                evidence_snippet=(f"Module: {label} | Base: {hex(base) if base else '-'} | Path: {path or '(none)'}"),
                entity=f"Driver {label}",
                raw_data=mod,
            )
        )

    if not ranges:
        return findings

    seen_drivers: set[tuple[int, str]] = set()
    for drv in driver_rows:
        start = _to_int(drv.get("Start"))
        if not start:
            continue
        if any(lo <= start < hi for lo, hi in ranges):
            continue
        # Without a readable object name the scan hit is a stale structure in freed pool, not a live driver
        if not _DRIVER_OBJECT_NAME_RE.match(str(drv.get("Name") or "").strip()):
            continue
        drv_name = str(drv.get("Name") or drv.get("Driver Name") or drv.get("Service Key") or "").strip()
        candidates = {_driver_short_name(drv.get(k)) for k in ("Driver Name", "Service Key", "Name")} - {""}
        if candidates & module_names:
            continue
        key = (start, drv_name.lower())
        if key in seen_drivers:
            continue
        seen_drivers.add(key)
        label = drv_name or hex(start)
        findings.append(
            DetectionResult(
                rule_id="DRIVER_UNLINKED",
                rule_name="Kernel Driver Hidden from Module List",
                category="Rootkit / Kernel",
                severity="High",
                score=35,
                mitre_technique="T1014 - Rootkit",
                description=(
                    f"driverscan found driver object '{label}' starting at {hex(start)}, but no module of the "
                    "loaded module list covers that address: the module was unlinked or loaded without the loader."
                ),
                evidence_snippet=(
                    f"Driver: {label} | Start: {hex(start)} | Service Key: {drv.get('Service Key') or '-'}"
                ),
                entity=f"Driver {label}",
                raw_data=drv,
            )
        )

    return findings


# =====================================================================
# 11. Executable-Writable Image Not Backed by a File (Issue #1543, optional signal)
# =====================================================================
_NO_FILE_VALUES = {"", "-", "n/a", "none", "null", "disabled"}


def _region_key(row: dict[str, Any]) -> tuple[Any, int | None]:
    return (row.get("PID"), _to_int(row.get("Start VPN")))


def _is_exec_writable(protection: str) -> bool:
    prot = protection.upper()
    return "EXECUTE" in prot and ("READWRITE" in prot or "WRITECOPY" in prot)


def _starts_with_pe(row: dict[str, Any]) -> bool:
    hexdump = str(row.get("Hexdump") or row.get("HexDump") or "").lower().split()
    if hexdump:
        return hexdump[:2] == ["4d", "5a"]
    # Rows without a hexdump: capstone decodes "MZ" as "dec ebp; pop edx"
    lines = str(row.get("Disasm") or "").strip().strip('"').splitlines()
    instructions = [" ".join(ln.split(":", 1)[-1].split()).lower() for ln in lines if ln.strip()]
    return instructions[:2] == ["dec ebp", "pop edx"]


def evaluate_unbacked_exec_images(
    malfind_rows: list[dict[str, Any]], vad_rows: list[dict[str, Any]]
) -> list[DetectionResult]:
    """
    Flag process regions holding a PE image that the loader did not map from a file (Issue #1543).

    A region is reported when malfind shows it starts with an ``MZ`` header, its protection is executable and
    writable (``PAGE_EXECUTE_READWRITE`` / ``PAGE_EXECUTE_WRITECOPY``), and ``windows.vadinfo.VadInfo`` (when it
    ran) shows no mapped file for the same PID and start address. The engine drops the generic malfind finding
    for a region reported here, so one region gives one finding.
    """
    vad_by_region: dict[tuple[Any, int | None], dict[str, Any]] = {}
    for vad in vad_rows:
        vad_by_region.setdefault(_region_key(vad), vad)

    findings: list[DetectionResult] = []
    seen: set[tuple[Any, int | None]] = set()
    for row in malfind_rows:
        key = _region_key(row)
        if key[1] is None or key in seen:
            continue
        vad = vad_by_region.get(key)
        protection = str((vad or {}).get("Protection") or row.get("Protection") or "")
        if not _is_exec_writable(protection) or not _starts_with_pe(row):
            continue
        mapped_file = str((vad or {}).get("File") or "").strip()
        if mapped_file.lower() not in _NO_FILE_VALUES:
            continue
        seen.add(key)

        pid, start = key
        proc = row.get("Process") or (vad or {}).get("Process") or "Unknown"
        vad_note = "VadInfo shows no mapped file" if vad else "VadInfo was not run; malfind reports private memory"
        findings.append(
            DetectionResult(
                rule_id="MEM_UNBACKED_EXEC_IMAGE",
                rule_name="Unbacked Executable Image in Writable Memory",
                category="Code Injection",
                severity="Critical",
                score=40,
                mitre_technique="T1055.001 - Process Injection: Dynamic-link Library Injection",
                description=(
                    f"'{proc}' (PID {pid}) holds a PE image at {hex(start)} in {protection} memory that is not "
                    f"backed by a file on disk ({vad_note}): a reflectively loaded or manually mapped module."
                ),
                evidence_snippet=f"PID: {pid} ({proc}) | Region: {hex(start)} | Protection: {protection} | File: none",
                entity=f"{proc} (PID {pid})",
                raw_data={"malfind": row, "vad": vad or {}},
            )
        )

    return findings

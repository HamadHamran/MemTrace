import ipaddress
from collections import Counter, defaultdict

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}

KNOWN_SYSTEM_NAMES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "lsm.exe", "svchost.exe", "spoolsv.exe", "explorer.exe", "taskhost.exe",
    "taskhostw.exe", "conhost.exe", "dllhost.exe", "rundll32.exe", "userinit.exe",
    "dwm.exe", "taskmgr.exe", "searchindexer.exe", "alg.exe", "wuauclt.exe",
}

EXPECTED_PARENTS = {
    "smss.exe": {"system", "smss.exe"},
    "wininit.exe": {"smss.exe"},
    "services.exe": {"wininit.exe", "winlogon.exe"},
    "lsass.exe": {"wininit.exe", "winlogon.exe"},
    "lsm.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe", "svchost.exe"},
    "spoolsv.exe": {"services.exe"},
    "taskhost.exe": {"services.exe", "svchost.exe"},
}

SINGLE_INSTANCE = {"lsass.exe", "services.exe", "wininit.exe", "lsm.exe"}

SYSTEM32_ONLY = {
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "smss.exe",
    "wininit.exe", "winlogon.exe", "spoolsv.exe", "lsm.exe", "taskhost.exe",
}

DOCUMENT_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe",
    "acrobat.exe", "iexplore.exe", "chrome.exe", "firefox.exe", "msedge.exe",
    "wmplayer.exe", "mspaint.exe", "notepad.exe",
}

SHELL_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
}

UNEXPECTED_NETWORK_OWNERS = {
    "explorer.exe", "notepad.exe", "calc.exe", "mspaint.exe", "lsass.exe",
    "csrss.exe", "smss.exe", "winlogon.exe", "wininit.exe", "services.exe",
    "cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "wscript.exe", "cscript.exe",
}

SUSPICIOUS_PORTS = {4444, 1337, 6666, 6667, 6668, 6669, 31337, 9001, 9050, 5555, 12345, 1234, 8888}

SUSPICIOUS_PATH_MARKERS = ["\\temp\\", "\\appdata\\", "\\downloads\\", "\\recycle", "\\users\\public\\", "\\programdata\\"]

SUSPICIOUS_CMDLINE_MARKERS = [
    "-enc ", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile",
    "invoke-expression", "iex(", "iex (", "-nop", "-w hidden", "-windowstyle hidden",
    "bypass", "certutil -urlcache", "bitsadmin /transfer",
]


KNOWN_DLLS = {
    "acgenral.dll", "activeds.dll", "actxprxy.dll", "adsldpc.dll", "advapi32.dll", "advpack.dll", "apphelp.dll",
    "atl.dll", "audiosrv.dll", "authz.dll", "basesrv.dll", "batmeter.dll", "bcrypt.dll", "bcryptprimitives.dll",
    "browser.dll", "browseui.dll", "cabinet.dll", "certcli.dll", "cfgmgr32.dll", "clbcatq.dll", "clusapi.dll",
    "colbact.dll", "combase.dll", "comctl32.dll", "comdlg32.dll", "comres.dll", "comsvcs.dll", "credui.dll",
    "crypt32.dll", "cryptbase.dll", "cryptdll.dll", "cryptsp.dll", "cryptsvc.dll", "cryptui.dll", "cscdll.dll",
    "cscui.dll", "csrsrv.dll", "d3d9.dll", "d3d11.dll", "dbghelp.dll", "dhcpcsvc.dll", "dnsapi.dll", "dnsrslvr.dll",
    "dpapi.dll", "dssenh.dll", "dwmapi.dll", "dxgi.dll", "ersvc.dll", "es.dll", "esent.dll", "esscli.dll",
    "eventlog.dll", "fastprox.dll", "gdi32.dll", "gdi32full.dll", "gdiplus.dll", "hnetcfg.dll", "icaapi.dll",
    "imagehlp.dll", "imm32.dll", "inetpp.dll", "iphlpapi.dll", "ipnathlp.dll", "ipsecsvc.dll", "kerberos.dll",
    "kernel32.dll", "kernelbase.dll", "lmhsvc.dll", "localspl.dll", "lpk.dll", "lsasrv.dll", "mfc42.dll",
    "mfc42u.dll", "mfc80.dll", "mfc80u.dll", "mfc80enu.dll", "midimap.dll", "mpr.dll", "mprapi.dll", "msacm32.dll",
    "msasn1.dll", "msctf.dll", "msgina.dll", "msi.dll", "msidle.dll", "msimg32.dll", "mspatcha.dll", "msprivs.dll",
    "mstlsapi.dll", "msv1_0.dll", "msvcp60.dll", "msvcp80.dll", "msvcp140.dll", "msvcr80.dll", "msvcrt.dll",
    "mswsock.dll", "mtxclu.dll", "ncobjapi.dll", "ncprov.dll", "nddeapi.dll", "netapi32.dll", "netcfgx.dll",
    "netlogon.dll", "netman.dll", "netrap.dll", "netshell.dll", "nsi.dll", "ntdll.dll", "ntdsapi.dll",
    "ntmarta.dll", "oakley.dll", "odbc32.dll", "odbcint.dll", "ole32.dll", "oleacc.dll", "oleaut32.dll",
    "pchsvc.dll", "perfdisk.dll", "perfos.dll", "perfproc.dll", "powrprof.dll", "profapi.dll", "profmap.dll",
    "propsys.dll", "psapi.dll", "psbase.dll", "pstorsvc.dll", "rasadhlp.dll", "rasapi32.dll", "raschap.dll",
    "rasdlg.dll", "rasman.dll", "rastls.dll", "regapi.dll", "regsvc.dll", "repdrvfs.dll", "resutils.dll",
    "rpcrt4.dll", "rpcss.dll", "rsaenh.dll", "rtutils.dll", "samlib.dll", "samsrv.dll", "scecli.dll", "scesrv.dll",
    "schannel.dll", "schedsvc.dll", "sechost.dll", "seclogon.dll", "secur32.dll", "sens.dll", "setupapi.dll",
    "sfc.dll", "sfc_os.dll", "shcore.dll", "shdocvw.dll", "shell32.dll", "shfolder.dll", "shimeng.dll",
    "shlwapi.dll", "shsvcs.dll", "snmpapi.dll", "spoolss.dll", "srsvc.dll", "srvsvc.dll", "ssdpapi.dll",
    "ssdpsrv.dll", "sspicli.dll", "stobject.dll", "sxs.dll", "tapi32.dll", "tcpmon.dll", "termsrv.dll",
    "themeui.dll", "trkwks.dll", "ucrtbase.dll", "umpnpmgr.dll", "upnp.dll", "urlmon.dll", "usbmon.dll",
    "user32.dll", "userenv.dll", "usp10.dll", "uxtheme.dll", "vcruntime140.dll", "version.dll", "vssapi.dll",
    "w32time.dll", "wbemcomn.dll", "wbemcons.dll", "wbemcore.dll", "wbemess.dll", "wdigest.dll", "webcheck.dll",
    "webclnt.dll", "win32spl.dll", "win32u.dll", "winhttp.dll", "wininet.dll", "winipsec.dll", "winmm.dll",
    "winrnr.dll", "winscard.dll", "winsrv.dll", "winsta.dll", "wintrust.dll", "wkssvc.dll", "wldap32.dll",
    "wlnotify.dll", "wmi.dll", "wmiprvsd.dll", "wmisvc.dll", "wmiutils.dll", "ws2_32.dll", "ws2help.dll",
    "wscsvc.dll", "wshtcpip.dll", "wsock32.dll", "wtsapi32.dll", "wuapi.dll", "wuaueng.dll", "wuauserv.dll",
    "wups.dll", "wzcsapi.dll", "wzcsvc.dll", "xpsp2res.dll",
}


ACQUISITION_TOOLS = {
    "dumpit.exe", "winpmem.exe", "winpmem_mini_x64.exe", "winpmem_mini_x86.exe", "ramcapture.exe",
    "ramcapture64.exe", "magnetramcapture.exe", "ftk imager.exe", "ftkimager.exe", "belkasoftlivercapturer.exe",
    "rcapture.exe", "memoryze.exe", "mdd.exe", "win32dd.exe", "win64dd.exe",
}

JIT_HOSTS = {
    "msmpeng.exe", "nissrv.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
    "brave.exe", "java.exe", "javaw.exe", "node.exe", "powershell.exe", "pwsh.exe", "w3wp.exe", "teams.exe",
    "slack.exe", "code.exe", "discord.exe", "acrord32.exe", "acrobat.exe",
}
JIT_SERVICE_GROUPS = {"secsvcs"}

HOMOGLYPHS = {("0", "o"), ("1", "l"), ("1", "i"), ("l", "i"), ("5", "s"), ("3", "e"), ("v", "u")}


def _is_lookalike(name, known):
    if name == known:
        return False
    if len(name) == len(known):
        diffs = [(a, b) for a, b in zip(name, known) if a != b]
        if len(diffs) == 1 and (diffs[0] in HOMOGLYPHS or diffs[0][::-1] in HOMOGLYPHS):
            return True
        if len(diffs) == 2:
            i = next(k for k in range(len(name)) if name[k] != known[k])
            if i + 1 < len(name) and name[i] == known[i + 1] and name[i + 1] == known[i]:
                return True
        return False
    if len(name) == len(known) + 1:
        return any(name[:k] + name[k + 1:] == known for k in range(len(name)))
    return False


def _name(value):
    return (value or "").strip().lower()


def _levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _is_public(address):
    try:
        ip = ipaddress.ip_address((address or "").split("%")[0])
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved)


class FindingCollector:
    def __init__(self):
        self.items = []

    def add(self, rule, severity, category, title, description, recommendation, mitre=None, pid=None, process=None, evidence=None):
        self.items.append({
            "rule": rule,
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "mitre": mitre or [],
            "pid": pid,
            "process": process,
            "evidence": {k: "" if v is None else str(v) for k, v in (evidence or {}).items()},
        })


def build_process_table(data):
    pslist = data.get("pslist") or []
    psscan = data.get("psscan") or []
    pstree = {row.get("PID"): row for row in data.get("pstree") or []}
    cmdlines = {row.get("PID"): row.get("Args") for row in data.get("cmdline") or []}

    listed = {(row.get("PID"), row.get("CreateTime")) for row in pslist}
    listed_pids = {row.get("PID") for row in pslist}

    processes = {}
    for row in pslist:
        processes[(row.get("PID"), row.get("CreateTime"))] = _process_record(row, "pslist")

    for row in psscan:
        key = (row.get("PID"), row.get("CreateTime"))
        if key in listed:
            continue
        record = _process_record(row, "psscan")
        record["hidden"] = row.get("ExitTime") is None and row.get("PID") not in listed_pids
        record["terminated"] = row.get("ExitTime") is not None
        processes[key] = record

    for record in processes.values():
        tree_row = pstree.get(record["pid"]) or {}
        record["path"] = tree_row.get("Path") or ""
        record["cmdline"] = cmdlines.get(record["pid"]) or tree_row.get("Cmd") or ""

    return sorted(processes.values(), key=lambda p: (p["pid"] or 0))


def _process_record(row, source):
    return {
        "pid": row.get("PID"),
        "ppid": row.get("PPID"),
        "name": row.get("ImageFileName") or "",
        "threads": row.get("Threads"),
        "handles": row.get("Handles"),
        "session": row.get("SessionId"),
        "wow64": row.get("Wow64"),
        "create_time": row.get("CreateTime"),
        "exit_time": row.get("ExitTime"),
        "offset": row.get("Offset(V)") or row.get("Offset(P)"),
        "source": source,
        "hidden": False,
        "terminated": row.get("ExitTime") is not None,
        "flags": [],
    }


def detect_hidden_processes(processes, findings):
    for proc in processes:
        if proc["hidden"]:
            proc["flags"].append("hidden")
            findings.add(
                "HIDDEN_PROCESS", "high", "Process",
                f"Hidden process: {proc['name']} (PID {proc['pid']})",
                "This process was recovered by pool scanning (psscan) but is missing from the kernel's active "
                "process list (pslist) and has no exit time. Rootkits unlink processes from that list to hide them "
                "from Task Manager and standard tools.",
                "Dump the process memory and executable for malware analysis and check for a kernel-level rootkit.",
                ["T1014", "T1564"], proc["pid"], proc["name"],
                {"PPID": proc["ppid"], "Create Time": proc["create_time"], "Offset": proc["offset"]},
            )


def detect_process_anomalies(processes, findings):
    active = [p for p in processes if not p["terminated"]]
    by_pid = {p["pid"]: p for p in active}
    counts = Counter(_name(p["name"]) for p in active)

    for name in SINGLE_INSTANCE:
        if counts[name] > 1:
            pids = ", ".join(str(p["pid"]) for p in active if _name(p["name"]) == name)
            findings.add(
                "MULTIPLE_INSTANCES", "high", "Process",
                f"Multiple instances of {name}",
                f"{name} should run only once on a healthy system. Additional instances are a common sign of "
                "malware masquerading as a critical Windows process.",
                "Compare the path, parent and command line of each instance to identify the impostor.",
                ["T1036.005"], None, name, {"PIDs": pids, "Count": counts[name]},
            )

    for proc in active:
        name = _name(proc["name"])
        parent = by_pid.get(proc["ppid"])
        parent_name = _name(parent["name"]) if parent else ""

        if name and name not in KNOWN_SYSTEM_NAMES and name.endswith(".exe"):
            for known in KNOWN_SYSTEM_NAMES:
                if known.endswith(".exe") and len(known) > 6 and _is_lookalike(name, known):
                    proc["flags"].append("masquerading")
                    findings.add(
                        "NAME_MASQUERADING", "high", "Process",
                        f"Possible masquerading: {proc['name']} resembles {known}",
                        f"The process name '{proc['name']}' is a near-copy of the legitimate Windows binary "
                        f"'{known}'. Attackers use look-alike names so the process blends in during triage.",
                        "Verify the executable path and digital signature; dump and analyze the binary.",
                        ["T1036.005"], proc["pid"], proc["name"],
                        {"Resembles": known, "PPID": proc["ppid"], "Command Line": proc["cmdline"]},
                    )
                    break

        if name in EXPECTED_PARENTS and parent and parent_name not in EXPECTED_PARENTS[name]:
            proc["flags"].append("bad-parent")
            findings.add(
                "UNEXPECTED_PARENT", "high", "Process",
                f"{proc['name']} (PID {proc['pid']}) has unexpected parent {parent['name']}",
                f"On Windows, {proc['name']} is normally started by "
                f"{' or '.join(sorted(EXPECTED_PARENTS[name]))}. A different parent suggests the process was "
                "launched by malware rather than by the operating system.",
                "Investigate the parent process and the binary path of this process.",
                ["T1036"], proc["pid"], proc["name"],
                {"Parent PID": proc["ppid"], "Parent": parent["name"], "Command Line": proc["cmdline"]},
            )

        if parent_name in DOCUMENT_PARENTS and name in SHELL_CHILDREN:
            proc["flags"].append("suspicious-child")
            findings.add(
                "SUSPICIOUS_CHILD", "high", "Process",
                f"{parent['name']} spawned {proc['name']}",
                "A document viewer, browser or desktop application launched a command interpreter or script host. "
                "This pattern is typical of malicious documents, exploits and drive-by downloads.",
                "Review the command line and identify the file or URL that was opened in the parent process.",
                ["T1204", "T1059"], proc["pid"], proc["name"],
                {"Parent PID": proc["ppid"], "Parent": parent["name"], "Command Line": proc["cmdline"]},
            )

        location = _name(proc["path"] or proc["cmdline"]).strip('"')
        if name in SYSTEM32_ONLY and location and "\\" in location and "\\system32\\" not in location and not location.startswith("\\systemroot\\"):
            proc["flags"].append("bad-path")
            findings.add(
                "SYSTEM_BINARY_WRONG_PATH", "high", "Process",
                f"{proc['name']} running from unexpected location",
                f"{proc['name']} is a core Windows binary that should only run from C:\\Windows\\System32. "
                "Running from another directory is a strong masquerading indicator.",
                "Acquire the binary from disk and compare its hash with a known-good copy.",
                ["T1036.005"], proc["pid"], proc["name"],
                {"Path": proc["path"] or proc["cmdline"]},
            )
        elif name in ACQUISITION_TOOLS:
            proc["flags"].append("acquisition-tool")
            findings.add(
                "ACQUISITION_TOOL", "info", "Process",
                f"Memory acquisition tool running: {proc['name']}",
                "A known memory acquisition tool was running when the image was captured. This is normally the tool "
                "the responder used to create this memory image and is expected.",
                "Confirm with the responder that this tool was used for the acquisition.",
                [], proc["pid"], proc["name"],
                {"Path": proc["path"] or proc["cmdline"], "Create Time": proc["create_time"]},
            )
        elif location and any(marker in location for marker in SUSPICIOUS_PATH_MARKERS):
            proc["flags"].append("user-writable-path")
            findings.add(
                "USER_WRITABLE_PATH", "medium", "Process",
                f"{proc['name']} executed from a user-writable directory",
                "The executable runs from a temporary, profile or public directory. Malware droppers commonly "
                "place payloads in these locations because they do not require administrator rights.",
                "Confirm whether this software is expected on the host and collect the file for analysis.",
                ["T1204.002"], proc["pid"], proc["name"],
                {"Path": proc["path"] or proc["cmdline"]},
            )

        cmdline = _name(proc["cmdline"])
        hits = [marker.strip() for marker in SUSPICIOUS_CMDLINE_MARKERS if marker in cmdline]
        if hits:
            proc["flags"].append("suspicious-cmdline")
            findings.add(
                "SUSPICIOUS_CMDLINE", "high", "Process",
                f"Suspicious command line in {proc['name']} (PID {proc['pid']})",
                "The command line contains obfuscation, download or execution-policy bypass patterns frequently "
                "used by attackers to run payloads in memory.",
                "Decode any encoded content and block the referenced URLs or files.",
                ["T1059.001", "T1027"], proc["pid"], proc["name"],
                {"Indicators": ", ".join(hits), "Command Line": proc["cmdline"]},
            )


def build_modules(data):
    modules = defaultdict(lambda: {"paths": set(), "pids": set(), "processes": set()})
    for row in data.get("dlllist") or []:
        name = _name(row.get("Name"))
        if not name:
            continue
        entry = modules[name]
        entry["paths"].add(row.get("Path") or "")
        entry["pids"].add(row.get("PID"))
        entry["processes"].add(row.get("Process") or "")
    return modules


def _strip_digits(value):
    return "".join(c for c in value if not c.isdigit())


def _mark(processes, pids, flag):
    for proc in processes:
        if proc["pid"] in pids and flag not in proc["flags"]:
            proc["flags"].append(flag)


def _pid_list(pids):
    ordered = sorted(p for p in pids if p is not None)
    text = ", ".join(str(p) for p in ordered[:20])
    return text + (f" (+{len(ordered) - 20} more)" if len(ordered) > 20 else "")


def detect_appinit(data, modules, processes, findings):
    for key in ("appinit", "appinit_wow64"):
        rows = data.get(key) or []
        values = {(row.get("Name") or ""): row for row in rows}
        row = values.get("AppInit_DLLs")
        if not row:
            continue
        raw = (row.get("Data") or "").strip().strip('"')
        dlls = [d.strip() for d in raw.replace(",", " ").split() if d.strip()]
        if not dlls:
            continue
        load_flag = values.get("LoadAppInit_DLLs", {}).get("Data")
        findings.add(
            "APPINIT_DLLS", "high", "Persistence",
            f"AppInit_DLLs registry value configured: {raw}",
            "The AppInit_DLLs registry value forces Windows to load the listed DLLs into every process that loads "
            "user32.dll. It is rarely used by legitimate software and is a well-known malware persistence and "
            "injection technique.",
            "Acquire the listed DLLs from disk, verify them against known-good hashes and remove the registry value.",
            ["T1546.010"], None, ", ".join(dlls),
            {
                "Registry Key": row.get("Key"),
                "Value": raw,
                "LoadAppInit_DLLs": load_flag if load_flag is not None else "not present",
                "Last Write Time": row.get("Last Write Time"),
            },
        )
        for dll in dlls:
            base = _name(dll.replace("/", "\\").split("\\")[-1])
            module = modules.get(base)
            if not module:
                continue
            _mark(processes, module["pids"], "appinit-dll")
            findings.add(
                "APPINIT_DLL_LOADED", "critical", "Injection",
                f"AppInit DLL {base} loaded into {len(module['pids'])} processes",
                "The DLL configured in AppInit_DLLs is mapped into running processes, so its code is executing inside "
                "them. Malware uses this to run in every interactive and service process at once.",
                "Isolate the host, dump the DLL from memory for analysis and identify how the registry value was set.",
                ["T1546.010", "T1055.001"], None, base,
                {
                    "Path": ", ".join(sorted(module["paths"])),
                    "Process Count": len(module["pids"]),
                    "PIDs": _pid_list(module["pids"]),
                },
            )


def detect_module_masquerading(modules, processes, findings):
    for name, module in modules.items():
        if not name.endswith(".dll") or name in KNOWN_DLLS:
            continue
        for known in KNOWN_DLLS:
            if len(known) <= 7 or _strip_digits(name) == _strip_digits(known):
                continue
            if _is_lookalike(name, known):
                _mark(processes, module["pids"], "masquerading-dll")
                findings.add(
                    "DLL_MASQUERADING", "high", "Module",
                    f"Look-alike DLL {name} resembles {known}",
                    f"A loaded module named '{name}' is a near-copy of the legitimate Windows library '{known}'. "
                    "Attackers give malicious DLLs look-alike names so they blend in with system libraries.",
                    "Acquire the DLL, compare it with the legitimate library and check its digital signature.",
                    ["T1036.005"], None, name,
                    {
                        "Resembles": known,
                        "Path": ", ".join(sorted(module["paths"])),
                        "Process Count": len(module["pids"]),
                        "PIDs": _pid_list(module["pids"]),
                    },
                )
                break


def build_connections(data):
    connections = []
    for row in data.get("netscan") or []:
        connections.append({
            "proto": row.get("Proto") or "",
            "local_addr": row.get("LocalAddr") or "",
            "local_port": row.get("LocalPort"),
            "foreign_addr": row.get("ForeignAddr") or "",
            "foreign_port": row.get("ForeignPort"),
            "state": row.get("State") or "",
            "pid": row.get("PID"),
            "owner": row.get("Owner") or "",
            "created": row.get("Created"),
            "flags": [],
        })
    return connections


def detect_network(connections, findings):
    for conn in connections:
        owner = _name(conn["owner"])
        remote = conn["foreign_addr"]
        public = _is_public(remote)
        endpoint = f"{remote}:{conn['foreign_port']}"
        evidence = {
            "Protocol": conn["proto"], "Local": f"{conn['local_addr']}:{conn['local_port']}",
            "Remote": endpoint, "State": conn["state"], "Created": conn["created"],
        }

        if public and owner in UNEXPECTED_NETWORK_OWNERS:
            conn["flags"].append("unexpected-owner")
            findings.add(
                "UNEXPECTED_NETWORK_PROCESS", "high", "Network",
                f"{conn['owner']} (PID {conn['pid']}) connected to {endpoint}",
                f"{conn['owner']} does not normally communicate with Internet hosts. Outbound traffic from this "
                "process often means malicious code is running inside it, for example after code injection.",
                "Block the remote address, check threat intelligence for it and inspect the process for injected code.",
                ["T1071", "T1055"], conn["pid"], conn["owner"], evidence,
            )

        if conn["foreign_port"] in SUSPICIOUS_PORTS or (conn["local_port"] in SUSPICIOUS_PORTS and "LISTEN" in conn["state"].upper()):
            conn["flags"].append("suspicious-port")
            findings.add(
                "SUSPICIOUS_PORT", "medium", "Network",
                f"Connection on suspicious port by {conn['owner'] or 'unknown'} (PID {conn['pid']})",
                "The connection uses a port commonly associated with backdoors, IRC botnets, Metasploit or Tor.",
                "Verify whether the service is legitimate and review firewall logs for the same endpoint.",
                ["T1571"], conn["pid"], conn["owner"], evidence,
            )


def build_injections(data):
    injections = []
    for row in data.get("malfind") or []:
        hexdump = (row.get("Hexdump") or "").strip()
        injections.append({
            "pid": row.get("PID"),
            "process": row.get("Process") or "",
            "start": row.get("Start VPN"),
            "end": row.get("End VPN"),
            "tag": row.get("Tag") or "",
            "protection": row.get("Protection") or "",
            "private": row.get("PrivateMemory"),
            "has_pe_header": hexdump.lower().startswith("4d 5a"),
            "hexdump": hexdump[:191],
            "disasm": (row.get("Disasm") or "")[:400],
        })
    return injections


def _hex(value):
    return hex(value) if isinstance(value, int) else str(value)


def _classify_region(hexdump):
    data = hexdump.lower().split()
    if data[:2] == ["4d", "5a"]:
        return "pe"
    if data and all(b == "00" for b in data[:32]):
        return "empty"
    if data[8:12] == ["ff", "ee", "ff", "ee"] or data[16:20] == ["ee", "ff", "ee", "ff"]:
        return "heap"
    if data[:2] == ["41", "ba"] and data[6:8] == ["48", "b8"] and data[16:19] == ["48", "ff", "20"]:
        return "thunk"
    sample = data[:64]
    if sample and sum(b == "00" for b in sample) / len(sample) >= 0.4:
        return "data"
    return "code"


def _jit_hosts(processes):
    hosts = set()
    for proc in processes:
        name = _name(proc["name"])
        cmdline = _name(proc["cmdline"])
        if name in JIT_HOSTS or (name == "svchost.exe" and any(f"-k {g}" in cmdline for g in JIT_SERVICE_GROUPS)):
            hosts.add(proc["pid"])
    return hosts


def detect_injection(injections, findings, processes=()):
    jit = _jit_hosts(processes)
    grouped = defaultdict(lambda: {"code": [], "benign": []})
    names = {}
    for item in injections:
        item["kind"] = _classify_region(item["hexdump"])
        names[item["pid"]] = item["process"]
        region = f"{_hex(item['start'])} - {_hex(item['end'])}"
        if item["kind"] == "pe":
            findings.add(
                "INJECTED_PE", "critical", "Injection",
                f"Injected executable in {item['process']} (PID {item['pid']})",
                "A private memory region with execute and write permissions contains a PE header (MZ). Legitimate "
                "modules are mapped from disk, so an executable image in private memory is a strong indicator of "
                "reflective DLL injection or process hollowing.",
                "Dump the region with windows.malware.malfind --dump and analyze it in a sandbox; isolate the host.",
                ["T1055.001", "T1620"], item["pid"], item["process"],
                {"Region": region, "Protection": item["protection"], "VAD Tag": item["tag"], "First bytes": item["hexdump"][:47]},
            )
        elif item["kind"] == "code" and item["pid"] in jit:
            item["kind"] = "jit"
            grouped[item["pid"]]["benign"].append(item)
        elif item["kind"] == "code":
            grouped[item["pid"]]["code"].append(item)
        else:
            grouped[item["pid"]]["benign"].append(item)

    for pid, groups in grouped.items():
        if groups["code"]:
            first = groups["code"][0]
            findings.add(
                "RWX_MEMORY", "medium", "Injection",
                f"Executable writable memory with code in {names[pid]} (PID {pid})",
                "Private memory regions are both writable and executable and contain non-empty data. This is how "
                "injected shellcode is usually staged, although JIT engines in browsers and .NET can also produce it.",
                "Review the disassembly; if the process is not a JIT host, dump the regions for analysis.",
                ["T1055"], pid, names[pid],
                {
                    "Regions": len(groups["code"]),
                    "Addresses": ", ".join(_hex(x["start"]) for x in groups["code"][:8]),
                    "Protection": first["protection"],
                    "First bytes": first["hexdump"][:47],
                },
            )
        if groups["benign"]:
            kinds = Counter(x["kind"] for x in groups["benign"])
            findings.add(
                "RWX_MEMORY_LOW_CONFIDENCE", "low", "Injection",
                f"Low-confidence executable memory in {names[pid]} (PID {pid})",
                "Executable regions were flagged by malfind but contain empty memory, a Windows heap header, sparse data, "
                "the x64 call-forwarding thunks that Windows creates for RPC and COM, or code generated by a known "
                "just-in-time compiler (browsers, .NET, Java, antimalware engines). These are common on clean "
                "systems and rarely indicate injection on their own.",
                "No action needed unless other findings involve this process.",
                ["T1055"], pid, names[pid],
                {
                    "Regions": len(groups["benign"]),
                    "Empty regions": kinds.get("empty", 0),
                    "Heap regions": kinds.get("heap", 0),
                    "Thunk regions": kinds.get("thunk", 0),
                    "Data regions": kinds.get("data", 0),
                    "JIT code regions": kinds.get("jit", 0),
                    "Addresses": ", ".join(_hex(x["start"]) for x in groups["benign"][:8]),
                },
            )


def correlate(findings):
    by_pid = defaultdict(set)
    names = {}
    for finding in findings.items:
        if finding["pid"] is not None and finding["severity"] in ("critical", "high", "medium"):
            by_pid[finding["pid"]].add(finding["category"])
            names[finding["pid"]] = finding["process"]
    for pid, categories in by_pid.items():
        if {"Injection", "Network"} <= categories:
            findings.add(
                "INJECTION_WITH_NETWORK", "critical", "Correlation",
                f"Injected process with network activity: {names[pid]} (PID {pid})",
                "The same process shows signs of code injection and suspicious network communication. This "
                "combination matches the behavior of banking trojans and remote-access implants that hide inside "
                "trusted processes to reach their command-and-control server.",
                "Treat the host as compromised: isolate it, block the remote endpoints and start incident response.",
                ["T1055", "T1071"], pid, names[pid], {"Categories": ", ".join(sorted(categories))},
            )


SCORE_BANDS = {"critical": (90, 100), "high": (70, 89), "medium": (40, 69), "low": (10, 39), "info": (0, 9)}
VERDICTS = {
    "critical": "Compromised",
    "high": "Likely Compromised",
    "medium": "Suspicious",
    "low": "No Significant Findings",
    "info": "No Significant Findings",
}


def risk_summary(findings):
    counts = Counter(f["severity"] for f in findings)
    top = next((s for s in SEVERITY_ORDER if counts[s]), None)
    if top is None:
        score, verdict = 0, VERDICTS["info"]
    else:
        low, high = SCORE_BANDS[top]
        extra = sum(SEVERITY_WEIGHT[s] * counts[s] for s in SEVERITY_ORDER) - SEVERITY_WEIGHT[top]
        score = min(high, low + extra // 4)
        verdict = VERDICTS[top]
    return {
        "score": score,
        "verdict": verdict,
        "counts": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
        "total": len(findings),
    }


def analyze(data):
    findings = FindingCollector()
    processes = build_process_table(data)
    connections = build_connections(data)
    injections = build_injections(data)
    modules = build_modules(data)

    detect_hidden_processes(processes, findings)
    detect_process_anomalies(processes, findings)
    detect_appinit(data, modules, processes, findings)
    detect_module_masquerading(modules, processes, findings)
    detect_network(connections, findings)
    detect_injection(injections, findings, processes)
    correlate(findings)

    flagged_pids = {f["pid"] for f in findings.items if f["pid"] is not None}
    for proc in processes:
        proc["suspicious"] = proc["pid"] in flagged_pids or bool(proc["flags"])

    ordered = sorted(findings.items, key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["pid"] or 0))
    for index, finding in enumerate(ordered, 1):
        finding["id"] = f"F-{index:03d}"

    return {
        "processes": processes,
        "connections": connections,
        "injections": injections,
        "findings": ordered,
        "summary": risk_summary(ordered),
    }

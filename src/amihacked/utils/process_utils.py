OFFICE_PROCESS_NAMES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELL_PROCESS_NAMES = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
LOLBIN_PROCESS_NAMES = {
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "powershell.exe",
    "pwsh.exe",
}


def has_remote_url(command_line: str | None) -> bool:
    if not command_line:
        return False
    lowered = command_line.lower()
    return "http://" in lowered or "https://" in lowered


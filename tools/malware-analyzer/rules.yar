import "pe"
import "math"

rule Common_PE_Behaviors
{
    meta:
        author = "assistant"
        description = "Common suspicious behaviors that may appear in legitimate software"
        score = 15
        severity = "low"
        low_trust = true
        date = "2025-10-02"
    strings:
        // Common APIs that might be suspicious
        $api1 = "LoadLibraryA" ascii wide
        $api2 = "GetProcAddress" ascii wide
        $api3 = "VirtualAlloc" ascii wide
        $api4 = "WriteProcessMemory" ascii wide
        
        // Common network APIs
        $net1 = "WinINet" ascii wide
        $net2 = "InternetOpen" ascii wide
        $net3 = "WSAStartup" ascii wide
        
        // File operations
        $file1 = "CreateFileA" ascii wide
        $file2 = "WriteFile" ascii wide
        $file3 = "CopyFileA" ascii wide
        
    condition:
        pe.is_pe and (
            3 of ($api*) or
            2 of ($net*) or
            3 of ($file*)
        )
}

rule Medium_Suspicious_Behavior
{
    meta:
        author = "assistant"
        description = "Moderately suspicious behaviors that warrant investigation"
        score = 50
        severity = "medium"
        date = "2025-10-02"
    strings:
        // Process manipulation
        $proc1 = "CreateRemoteThread" ascii wide
        $proc2 = "Process32Next" ascii wide
        $proc3 = "VirtualAllocEx" ascii wide
        
        // Registry manipulation
        $reg1 = "RegSetValueExA" ascii wide
        $reg2 = "RegCreateKeyExA" ascii wide
        
        // Suspicious COM objects
        $com1 = "Shell.Application" ascii wide
        $com2 = "WScript.Shell" ascii wide
        
        // Command execution
        $cmd1 = "cmd.exe /c" ascii wide
        $cmd2 = "powershell.exe" ascii wide
        
    condition:
        pe.is_pe and (
            2 of ($proc*) or
            (any of ($reg*) and any of ($cmd*)) or
            (any of ($com*) and any of ($cmd*))
        )
}

rule High_Risk_Indicators
{
    meta:
        author = "assistant"
        description = "High-risk behaviors commonly associated with malware"
        score = 75
        severity = "high"
        date = "2025-10-02"
    strings:
        // Anti-analysis
        $anti1 = "IsDebuggerPresent" ascii wide
        $anti2 = "CheckRemoteDebuggerPresent" ascii wide
        $anti3 = "QueryPerformanceCounter" ascii wide
        $anti4 = { 0F 31 }  // RDTSC
        
        // Code injection
        $inject1 = { 68 ?? ?? ?? ?? FF 55 }  // PUSH addr; CALL [EBP+x]
        $inject2 = { 83 EC ?? 53 56 57 }     // Stack setup for injection
        
        // Process hollowing
        $hollow1 = "NtUnmapViewOfSection" ascii wide
        $hollow2 = "ZwUnmapViewOfSection" ascii wide
        
        // Memory patterns
        $mem1 = { 90 90 90 90 90 }  // NOP sled
        $mem2 = { E9 ?? ?? ?? ?? }  // JMP
        
    condition:
        pe.is_pe and (
            (2 of ($anti*) and any of ($inject*)) or
            (any of ($hollow*) and any of ($mem*)) or
            (2 of ($inject*) and any of ($mem*))
        ) and (
            math.entropy(0, filesize) >= 6.5
        )
}

rule Critical_Malware_Indicators
{
    meta:
        author = "assistant"
        description = "Critical malicious behaviors - high confidence malware indicators"
        score = 95
        severity = "critical"
        date = "2025-10-02"
    strings:
        // Known shellcode patterns
        $shell1 = { 31 C0 50 68 ?? ?? ?? ?? 89 E3 50 53 89 E1 B0 0B CD 80 }  // Linux shellcode
        $shell2 = { FC E8 ?? ?? ?? ?? 60 89 E5 31 }  // Common shellcode header
        
        // Ransomware indicators
        $ransom1 = "vssadmin delete shadows" ascii wide nocase
        $ransom2 = "bcdedit /set {default}" ascii wide nocase
        $ransom3 = ".encrypted" ascii wide
        $ransom4 = "your files have been" ascii wide nocase
        
        // Banking trojan patterns
        $bank1 = { 68 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? E8 }  // Form grabbing code
        $bank2 = "login.php" ascii wide
        $bank3 = "money" ascii wide
        $bank4 = "account" ascii wide
        
        // Advanced persistence
        $persist1 = "CurrentVersion\\Run" ascii wide
        $persist2 = "Schedule\\" ascii wide
        $persist3 = "\\startup\\" ascii wide nocase
        
        // C2 communication
        $c2_1 = { 68 74 74 70 3A 2F 2F [1-20] 2E [1-20] 00 }  // http:// pattern
        $c2_2 = { 68 74 74 70 73 3A 2F 2F [1-20] 2E [1-20] 00 }  // https:// pattern
        
    condition:
        pe.is_pe and (
            any of ($shell*) or
            2 of ($ransom*) or
            (2 of ($bank*) and any of ($c2_*)) or
            (2 of ($persist*) and (any of ($c2_*) or any of ($bank*)))
        ) and (
            math.entropy(0, filesize) >= 7.0 or
            pe.number_of_sections > 8
        )
}

rule Embedded_Malicious_Content
{
    meta:
        author = "assistant"
        description = "Detects embedded executables or scripts in non-executable files"
        score = 85
        severity = "high"
        date = "2025-10-02"
    strings:
        $mz = "MZ" ascii
        $pdf = "%PDF" ascii
        $script1 = "<script>" ascii nocase
        $script2 = "function" ascii
        $shell = "shell" ascii nocase
        $exe = ".exe" ascii nocase
        $dll = ".dll" ascii nocase
        
    condition:
        // Look for executable content in non-executable files
        not pe.is_pe and (
            $mz at 0 or
            ($pdf at 0 and any of ($script*)) or
            (any of ($script*) and ($shell or $exe or $dll))
        )
}

rule DNS_Tunneling_Advanced
{
    meta:
        author = "assistant"
        description = "Advanced DNS tunneling and data exfiltration detection"
        score = 80
        severity = "high"
        date = "2025-10-02"
    strings:
        // DNS API usage
        $dns1 = "DnsQuery" ascii wide
        $dns2 = "GetAddrInfo" ascii wide
        $dns3 = "gethostbyname" ascii wide
        
        // Suspicious DNS patterns
        $susp1 = /[A-Za-z0-9+\/=]{30,}\.([a-z0-9-]+\.)*[a-z]{2,6}/ ascii wide
        $susp2 = /[0-9a-f]{32,}\.([a-z0-9-]+\.)*[a-z]{2,6}/ ascii wide
        
        // Encoding functions
        $enc1 = { 83 E0 3F } // Base64 bitmask
        $enc2 = { 83 E0 1F } // Base32 bitmask
        
        // Network packet crafting
        $pkt1 = { 53 05 00 00 } // DNS header
        $pkt2 = { 00 01 00 00 00 00 00 } // DNS query
        
    condition:
        pe.is_pe and (
            ((any of ($dns*)) and any of ($susp*)) or
            (any of ($enc*) and any of ($pkt*)) or
            (2 of ($dns*) and any of ($enc*))
        ) and (
            math.entropy(0, filesize) >= 6.0
        )
}

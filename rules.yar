rule Deteccion_Ciberataques {
    meta:
        autor = "Hacker Ético"
        descripcion = "Regla YARA para detectar varios tipos de ciberataques"
        version = "1.0"
        fecha = "2025-02-13"
        referencia = "Basado en firmas de malware conocidas"

    strings:
        // Firmas de malware comunes
        $malware1 = "malicious_code"
        $malware2 = { E8 ?? ?? ?? ?? 68 61 63 6B 65 72 }  // "hacker" en hex
        $malware3 = "cmd.exe /c powershell"

        // Ransomware
        $ransom1 = "encrypt_all_files"
        $ransom2 = "AES-256-CBC"
        $ransom3 = "delete_shadow_copies"

        // Exploits
        $exploit1 = "MS17-010"
        $exploit2 = "heap spray"
        $exploit3 = { 90 90 90 90 }  // NOP Sled

        // Comunicaciones maliciosas
        $c2_1 = "http://malicious-site.com"
        $c2_2 = "suspicious-domain.xyz"
        $c2_3 = { 68 74 74 70 3A 2F 2F }  // "http://"

        // Persistencia
        $persistence1 = "run registry persistence"
        $persistence2 = "schtasks /create"
        $persistence3 = "startup folder backdoor"

    condition:
        5 of ($malware*, $ransom*, $exploit*, $c2_*, $persistence*) 
}

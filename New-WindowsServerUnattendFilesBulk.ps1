Begin {
    [PSCredential]$LocalAdministrator_Credential = Get-Credential -Message "Local Administrator Credentials"
    [PSCredential]$AD_JoinDomain_Credential = Get-Credential -Message "AD Domain Join Credentials"

    <# - Expected Values per Server
        [string]$Hostname = ""
        [string]$IPv4_Address = ""
        [int]$IPv4_PrefixLength = ""
        [string]$IPv4_DefaultGateway = ""
        [string]$IPv4_DNSServers = ""
        [pscredential]$Local_Administrator_Credentials = ""
        [string]$AD_JoinDomain = ""
        [pscredential]$AD_JoinDomain_Credentials = ""
        [string]$AD_JoinDomain_OU = ""
        [string]$Timezone = "US Eastern Standard Time"
        [string]$OrganizationName = "ACME"
        [string]$Owner = "ACME"
        [string]$Path = ""
        [switch]$OverwriteExistingFile = $False
        [switch]$CopyToClipboard = $False
    #>

    [hashtable]$Systems = @{
    0 = [ordered]@{
        Hostname = "Server1"
        IPv4_Address = "192.168.212.33"
        IPv4_PrefixLength = "24"
        IPv4_DefaultGateway = "192.168.212.1"
        IPv4_DNSServers = "192.168.207.22,192.168.207.23"
        Local_Administrator_Credentials = $LocalAdministrator_Credential
        AD_JoinDomain = "child.domain.tld"
        AD_JoinDomain_Credentials = $AD_JoinDomain_Credential
        AD_JoinDomain_OU = "OU=T2,OU=2016,OU=Windows,OU=Microsoft,OU=Servers,DC=child,DC=domain,DC=tld"
        Timezone = "US Eastern Standard Time"
        OrganizationName = "ACME"
        Owner = "ACME"
        Path = "C:\temp\Microsoft\UnattendFiles\"
        OverwriteExistingFile = $True
        CopyToClipboard = $False
    }

    1 = [ordered]@{
        Hostname = "Server2"
        IPv4_Address = "192.168.212.34"
        IPv4_PrefixLength = "24"
        IPv4_DefaultGateway = "192.168.212.1"
        IPv4_DNSServers = "192.168.207.22,192.168.207.23"
        Local_Administrator_Credentials = $LocalAdministrator_Credential
        AD_JoinDomain = "child.domain.tld"
        AD_JoinDomain_Credentials = $AD_JoinDomain_Credential
        AD_JoinDomain_OU = "OU=T2,OU=2016,OU=Windows,OU=Microsoft,OU=Servers,DC=child,DC=domain,DC=tld"
        Timezone = "US Eastern Standard Time"
        OrganizationName = "ACME"
        Owner = "ACME"
        Path = "C:\temp\Microsoft\UnattendFiles\"
        OverwriteExistingFile = $True
        CopyToClipboard = $False
    }

    2 = [ordered]@{
        Hostname = "Server3"
        IPv4_Address = "192.168.212.35"
        IPv4_PrefixLength = "24"
        IPv4_DefaultGateway = "192.168.212.1"
        IPv4_DNSServers = "192.168.207.22,192.168.207.23"
        Local_Administrator_Credentials = $LocalAdministrator_Credential
        AD_JoinDomain = "child.domain.tld"
        AD_JoinDomain_Credentials = $AD_JoinDomain_Credential
        AD_JoinDomain_OU = "OU=T2,OU=2016,OU=Windows,OU=Microsoft,OU=Servers,DC=child,DC=domain,DC=tld"
        Timezone = "US Eastern Standard Time"
        OrganizationName = "ACME"
        Owner = "ACME"
        Path = "C:\temp\Microsoft\UnattendFiles\"
        OverwriteExistingFile = $True
        CopyToClipboard = $False
    }
}
} Process {
    ForEach ($System in ($Systems.GetEnumerator() | Sort-Object -Property Name)) {
        [hashtable]$Values = [ordered]@{}
        $Values = $System.Value

        Try {
            & ".\New-WindowsServerUnattendFile.ps1" @Values -ErrorAction Stop
        } Catch {
            Write-Warning -Message $PsItem
        }

        If ($Values.CopyToClipboard) {
            Write-Host -ForegroundColor Yellow "Unattend.xml has been copied to the clipboard; processing has paused while contents are pasted."
            Write-Host -ForegroundColor Yellow "Continuing may overwrite the Clipboard content."
            pause
        }
    }
} End {

}
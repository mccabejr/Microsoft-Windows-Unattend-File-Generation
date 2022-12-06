[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
param(
    [Parameter(Mandatory = $True, ParameterSetName = "Default", Position = 0, HelpMessage = "The 'Hostname' for the Guest Operating System.")]
    [ValidatePattern("^[A-Za-z0-9-_]{3,15}$")]
    [string]$Hostname,

    [Parameter(Mandatory = $True, ParameterSetName = "Default", Position = 1, HelpMessage = "The 'IPv4 Address' for the Guest Operating System.")]
    [ValidatePattern("\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b")]
    [string]$IPv4_Address,

    [Parameter(Mandatory = $True, ParameterSetName = "Default", Position = 2, HelpMessage = "The 'IPv4 Address Prefix Length' for the Guest Operating System.")]
    [ValidateRange(8,30)]
    [int]$IPv4_PrefixLength,

    [Parameter(Mandatory = $True, ParameterSetName = "Default", Position = 3, HelpMessage = "The 'IPv4 Default Gateway' for the Guest Operating System.")]
    [ValidatePattern("^\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b$")]
    [string]$IPv4_DefaultGateway,

    [Parameter(Mandatory = $True, ParameterSetName = "Default", Position = 4, HelpMessage = "The 'DNS Servers in IPv4 Address format' for the Guest Operating System.")]
    [ValidatePattern("^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?),)*((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")]
    [string]$IPv4_DNSServers,

    [Parameter(Mandatory = $False, ParameterSetName = "Default", Position = 5, HelpMessage = "The 'Local Administrator Credentials' for the Guest Operating System.")]
    [pscredential]$Local_Administrator_Credentials,

    [Parameter(Mandatory = $True, ParameterSetName = "Default", Position = 6, HelpMessage = "The 'Active Directory Domain Name' for the Guest Operating System to join.")]
    [ValidatePattern("^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,5})$")]
    [string]$AD_JoinDomain,

    [Parameter(Mandatory = $False, ParameterSetName = "Default", Position = 7, HelpMessage = "The 'Active Directory Credentials' for the Guest Operating System to join the Active Directory Domain.")]
    [pscredential]$AD_JoinDomain_Credentials,

    [Parameter(Mandatory = $True, ParameterSetName = "Default", Position = 8, HelpMessage = "The 'Active Directory Organizataion Unit' to join the Guest Operating System to for the 'Active Directory Domain Name.'")]
    [ValidatePattern("^(?:(?:CN|OU|DC)\=[a-zA-Z0-9_ ]+,)+(?:CN|OU|DC)\=\w+$")]
    [string]$AD_JoinDomain_OU,

    [Parameter(Mandatory = $False, ParameterSetName = "Default", Position = 9, HelpMessage = "The 'Time Zone' to use for the Guest Operating System.'")]
    [ValidateSet("US Eastern Standard Time", "US Pacific Standard Time")]
    [string]$Timezone = "US Eastern Standard Time",

    [Parameter(Mandatory = $False, ParameterSetName = "Default", Position = 10, HelpMessage = "The 'Organization Name' to use for the Guest Operating System.'")]
    [string]$OrganizationName = "PMO",

    [Parameter(Mandatory = $False, ParameterSetName = "Default", Position = 11, HelpMessage = "The 'Owner Name' to use for the Guest Operating System.'")]
    [string]$Owner = "PMO",

    [Parameter(Mandatory = $False, ParameterSetName = "Default", Position = 12, HelpMessage = "The file 'Path' to output the Unattend.xml to.'")]
    [ValidateScript({ Test-Path -LiteralPath $_ -IsValid ; Test-Path -LiteralPath $_ })]
    [string]$Path,

    [Parameter(Mandatory = $False, ParameterSetName = "Default", Position = 13, HelpMessage = "An option to automatically overwrite a previous Unattend.xml file.")]
    [switch]$OverwriteExistingFile,

    [Parameter(Mandatory = $False, ParameterSetName = "Default", Position = 14, HelpMessage = "An option to automatically copy the contents of the Unattend.xml to the Clipboard.")]
    [switch]$CopyToClipboard
)

Begin {
    Set-StrictMode -Version Latest

    [bool]$UnattendFileGenerated = $False

    If (-Not ($Local_Administrator_Credentials)) {
        [PSCredential]$LocalAdministrator_Credential = Get-Credential -Message "Local Administrator Credentials"
    } Else {
        [PSCredential]$LocalAdministrator_Credential = $Local_Administrator_Credentials
    }

    If (-Not ($AD_JoinDomain_Credentials)) {
        [PSCredential]$AD_JoinDomain_Credential = Get-Credential -Message "AD Domain Join Credentials"
    } Else {
        [PSCredential]$AD_JoinDomain_Credential = $AD_JoinDomain_Credentials
    }

} Process {
    # Password Processing - Local Administrator Account
    If ($LocalAdministrator_Credential.UserName -and $LocalAdministrator_Credential.Password) {
        [IntPtr]$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($LocalAdministrator_Credential.Password)
        [string]$administratorPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
        $encodedAdministratorPassword = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(('{0}AdministratorPassword' -f $administratorPassword)))
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    } Else {
        Write-Warning -Message "Missing Local Administrator Credentials; unable to proceed."
        Return
    }

    # Password Processing - Local Auto Logon Account
    If ($LocalAdministrator_Credential.UserName -and $LocalAdministrator_Credential.Password) {
        [IntPtr]$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($LocalAdministrator_Credential.Password)
        [string]$autoLogonPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
        $encodedAutoLogonPassword = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(('{0}Password' -f $autoLogonPassword)))
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    } Else {
        Write-Warning -Message "Missing Local Auto Logon Account Credentials; unable to proceed."
        Return
    }

    # Password Processing - Active Directory Domain Join Account
    If ($AD_JoinDomain_Credential.UserName -and $AD_JoinDomain_Credential.Password) {
        [IntPtr]$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AD_JoinDomain_Credential.Password)
        [string]$unsecuredomainjoinPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    } Else {
        Write-Warning -Message "Missing AD Join Domain Credentials; unable to proceed."
        Return
    }

[string]$UnattendFile = @"
<?xml version="1.0" encoding="UTF-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <ComputerName>$Hostname</ComputerName>
        <RegisteredOrganization>$OrganizationName</RegisteredOrganization>
        <RegisteredOwner>$Owner</RegisteredOwner>
        <TimeZone>$Timezone</TimeZone>
        </component>
        <component xmlns="" name="Microsoft-Windows-TerminalServices-LocalSessionManager" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
        <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <FirewallGroups>
            <FirewallGroup wcm:action="add" wcm:keyValue="RemoteDesktop">
                <Active>true</Active>
                <Profile>all</Profile>
                <Group>@FirewallAPI.dll,-28752</Group>
            </FirewallGroup>
        </FirewallGroups>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <UserAccounts>
            <AdministratorPassword>
                <Value>$encodedAdministratorPassword</Value>
                <PlainText>false</PlainText>
            </AdministratorPassword>
        </UserAccounts>
        <AutoLogon>
            <Password>
                <Value>$encodedAutoLogonPassword</Value>
                <PlainText>false</PlainText>
            </Password>
            <Enabled>true</Enabled>
            <Username>Administrator</Username>
        </AutoLogon>
        <FirstLogonCommands>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c netsh firewall add portopening TCP 5985 "PowerShell Remoting - TCP/5985"</CommandLine>
                <Description>PS-Remoting Firewall Allow Rule (DEPRECATED)</Description>
                <Order>1</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>powershell -Command "Enable-PSRemoting -SkipNetworkProfileCheck -Force"</CommandLine>
                <Description>Enable PS-Remoting</Description>
                <Order>2</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned"</CommandLine>
                <Description>Set Execution Policy 64 Bit</Description>
                <Order>3</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>C:\Windows\SysWOW64\cmd.exe /c powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force"</CommandLine>
                <Description>Set Execution Policy 32 Bit</Description>
                <Order>4</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c winrm quickconfig -q</CommandLine>
                <Description>winrm quickconfig -q</Description>
                <Order>5</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c winrm set winrm/config @{MaxTimeoutms="1800000"}</CommandLine>
                <Description>Win RM MaxTimoutms</Description>
                <Order>6</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c winrm set winrm/config/winrs @{MaxMemoryPerShellMB="800"}</CommandLine>
                <Description>Win RM MaxMemoryPerShellMB</Description>
                <Order>7</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c winrm set winrm/config/service @{AllowUnencrypted="true"}</CommandLine>
                <Description>Win RM AllowUnencrypted</Description>
                <Order>8</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c winrm set winrm/config/service/auth @{Basic="true"}</CommandLine>
                <Description>Win RM auth Basic</Description>
                <Order>9</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c winrm set winrm/config/client/auth @{Basic="true"}</CommandLine>
                <Description>Win RM client auth Basic</Description>
                <Order>10</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c winrm set winrm/config/listener?Address=*+Transport=HTTP @{Port="5985"} </CommandLine>
                <Description>Win RM listener Address/Port</Description>
                <Order>11</Order>
                <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>powershell -Command "New-NetIPAddress -InterfaceIndex `$((Get-NetAdapter | Sort-Object -Property ifIndex | Select-Object -First 1).ifIndex) -IPAddress $($IPv4_Address) -PrefixLength $($IPv4_PrefixLength) -DefaultGateway $($IPv4_DefaultGateway)"</CommandLine>
                <Description>Static IP Address Assignment via PWSH</Description>
                <Order>12</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>powershell -Command "Set-DnsClientServerAddress -InterfaceIndex `$((Get-NetAdapter | Sort-Object -Property ifIndex | Select-Object -First 1).ifIndex) -ServerAddresses $($IPv4_DNSServers)"</CommandLine>
                <Description>Static Network Adapter DNS Server Assignment via PowerShell</Description>
                <Order>13</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>powershell -Command "Set-NetConnectionProfile -InterfaceIndex `$((Get-NetAdapter | Sort-Object -Property ifIndex | Select-Object -First 1).ifIndex) -NetworkCategory Private"</CommandLine>
                <Description>Static Network Connection Profile to 'Private' via PowerShell</Description>
                <Order>14</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd.exe /c netdom join $Hostname /Domain:"$AD_JoinDomain" /OU:"$AD_JoinDomain_OU" /UserD:"$($AD_JoinDomain_Credential.UserName)" /PasswordD:"$unsecuredomainjoinPassword" /Reboot:1</CommandLine>
                <Description>Active Directory Domain Joining via NETDOM</Description>
                <Order>15</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
        </FirstLogonCommands>
        <OOBE>
            <HideEULAPage>true</HideEULAPage>
            <HideLocalAccountScreen>true</HideLocalAccountScreen>
            <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
            <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
            <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
            <NetworkLocation>Home</NetworkLocation>
            <ProtectYourPC>3</ProtectYourPC>
            <SkipMachineOOBE>true</SkipMachineOOBE>
            <SkipUserOOBE>true</SkipUserOOBE>
        </OOBE>
        </component>
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <InputLocale>en-US</InputLocale>
        <SystemLocale>en-US</SystemLocale>
        <UILanguageFallback>en-us</UILanguageFallback>
        <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
    </settings>
</unattend>
"@

    Try {
        Remove-Variable -Name administratorPassword -Confirm:$False -Force:$True
        Remove-Variable -Name autoLogonPassword -Confirm:$False -Force:$True
        Remove-Variable -Name BSTR -Confirm:$False -Force:$True
        Remove-Variable -Name encodedAdministratorPassword -Confirm:$False -Force:$True
        Remove-Variable -Name encodedAutoLogonPassword -Confirm:$False -Force:$True
        Remove-Variable -Name unsecuredomainjoinPassword -Confirm:$False -Force:$True

        [System.GC]::Collect()
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    } Catch {
        Write-Warning -Message $PsItem
    }

    $UnattendFileGenerated = $True
} End {
    If ($UnattendFileGenerated) {
        [string]$UnattendFilePath = "{0}\{1}_{2}" -f $Path, $Hostname.ToUpper(), "unattend.xml"

        If ($Path) {
            [bool]$GenerateUnattendFile = $False

            If (-Not (Test-Path -LiteralPath $UnattendFilePath -IsValid)) {
                Write-Warning -Message $("The Unattend.xml File Path is INVALID! The Unattend.xml File Path is set to '{0}'." -f $UnattendFilePath)
            }

            If (Test-Path -LiteralPath $UnattendFilePath) {
                If ($OverwriteExistingFile) {
                    Try {
                        Remove-Item -LiteralPath $UnattendFilePath -Confirm:$False -Force:$True -ErrorAction Stop
                    } Catch {
                        Write-Warning -Message $PsItem
                        Return
                    }
                }

                If (-Not (Test-Path -LiteralPath $UnattendFilePath)) {
                    $GenerateUnattendFile = $True
                }
            } Else {
                $GenerateUnattendFile = $True
            }

            If ($GenerateUnattendFile) {
                Try {
                    Add-Content -LiteralPath $UnattendFilePath -Value $UnattendFile -ErrorAction Stop
                } Catch {
                    Write-Warning -Message $PsItem
                }
            } Else {
                Write-Warning -Message "Unable to proceed with the generation of the Unattend.xml."
            }
        }

        If ($CopyToClipboard) {
            Try {
                Set-Clipboard -Value $UnattendFile -ErrorAction Stop
            } Catch {
                Write-Warning -Message $PsItem
            }
        }
    }
}
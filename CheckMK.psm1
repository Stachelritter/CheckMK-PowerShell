<#
.SYNOPSIS
	Funktionssammlung für CheckMK

.DESCRIPTION
    Dieses Modul soll mit der Zeit wachsen. Es sollen nicht unbedingt alle Funktionen der
    CheckMK API abgebildet werden, allerdings die am häufigsten verwendeten.
    Wenn jemand einen Schnittstelle der API anspricht, welche das Modul noch nicht abdeckt,
    kann er das Modul gerne ergänzen.

    -Verbose hilft Fehler zu finden. HTTP Error Codes lassen sich so anzeigen.
    In der Dokumentation zur API ist je Endpunkt aufgelistet, was welcher Code bedeutet.
    Lassen sich Fehler nicht erklären, kann die interaktive Dokumentation genutzt werden. Diese enthält
    bei falscher Syntax recht genaue Fehlerbeschreibungen.

.LINK
    Dokumentation
    https://<CheckMK-Host>/<sitename>/check_mk/openapi/
.LINK
    Interaktive Dokumentation
    https://<CheckMK-Host>/<sitename>/check_mk/api/1.0/ui/

#>
#region Connection
function Set-CertificateValidationPolicy {
    # Alternative zu invoke-webRequest -SkipCertificateCheck, welches es nur in PowerShell 7 gibt
    # Die Änderung soll nur in PS5 erfolgen. Ab PS7 bitte den Schalter an Invoke-Webrequest nutzen
    If ($PSVersionTable.PSVersion -like '5.*') {
        If ([System.Net.ServicePointManager]::CertificatePolicy.GetType().Name -eq 'DefaultCertPolicy') {
            class TrustAllCertsPolicy : System.Net.ICertificatePolicy {
                [bool] CheckValidationResult (
                    [System.Net.ServicePoint]$srvPoint,
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$certificate,
                    [System.Net.WebRequest]$request,
                    [int]$certificateProblem
                ) {
                    return $true
                }
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
        }
    }
}
function Get-CMKConnection {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, HelpMessage = 'DNS-Name des CheckMK-Servers')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Hostname,
        [parameter(Mandatory, HelpMessage = 'Instanz auf dem CheckMK-Server')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Sitename,
        [parameter(HelpMessage = 'Benutzer mit genügend Rechten in CheckMK. Per Standard wird der Skriptausführende Benutzer gewählt.')]
        [string]
        $Username,
        [parameter(HelpMessage = 'Wenn bestehende Objekte bearbeitet werden sollen, muss das ETag des Objektes zuvor abgerufen und bei der Änderungsanfrage in den Header eingefügt werden.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IfMatch
    )
    If (-not $PSBoundParameters.ContainsKey('Username')) {
        $PSBoundParameters.Username = [System.Environment]::UserName
    }
    $Connection = @{
        hostname = $Hostname
        sitename = $Sitename
        username = $PSBoundParameters.Username
        APIUrl   = "https://$hostname/$sitename/check_mk/api/1.0"
        Header   = Get-CMKHeader @PSBoundParameters
    }
    return $Connection
}
function Get-CMKHeader {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, HelpMessage = 'DNS-Name des CheckMK-Servers')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Hostname,
        [parameter(Mandatory, HelpMessage = 'Instanz auf dem CheckMK-Server')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Sitename,
        [parameter(Mandatory, HelpMessage = 'Benutzer mit genügend API-Rechten in CheckMK.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username,
        [parameter(HelpMessage = 'Wenn bestehende Objekte bearbeitet werden sollen, muss das ETag des Objektes zuvor abgerufen und bei der Änderungsanfrage in den Header eingefügt werden.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IfMatch
    )

    $pwdpath = "$($env:USERPROFILE)\Documents\$($username)-$($Hostname)-$($Sitename).pwd"

    If (($env:username -like '*$') -or ($Username -eq 'automation')) { 
        # Wenn das Skript als System läuft oder der User automation genutzt wird soll das gespeicherte Kennwort nicht ablaufen
    }
    else {
        If (Test-Path -Path $pwdpath) {
            $Passwortdatei = Get-Item -Path $pwdpath
            If ($Passwortdatei.LastWriteTime -lt (Get-Date).AddDays(-185)) {
                Remove-Item -Path $pwdpath
                Write-Verbose 'Alte Passwortdatei gelöscht'
            }
        }
    }
    if (-not(Test-Path $pwdpath)) {
        Write-Host 'Es existiert keine Passwortdatei für ihren Benutzer oder sie war zu alt. Diese muss in Ihrem Profil nun generiert werden!' -BackgroundColor Red
        Read-Host -AsSecureString "Bitte Passwort des Benutzers `"$($username)`" eingeben" | ConvertFrom-SecureString | Out-File $pwdpath
    }
    $password = Get-Content $pwdpath | ConvertTo-SecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $header = New-Object -TypeName 'System.Collections.Generic.Dictionary[[string],[string]]'
    $header.Add('Authorization', "Bearer $username $password")
    $header.Add('Accept', 'application/json')
    $header.Add('Content-Type', 'application/json')
    if ($IfMatch) {
        $header.Add('If-Match', $IfMatch)
    }
    return $header
}
function Invoke-CustomWebRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method,
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,
        [parameter(Mandatory)]
        [Object]
        $Headers,
        [parameter()]
        [object]
        $Body
    )
    # Diese Funktion ist notwendig, da Invoke-WebRequest bei Statuscodes -ne 200 einen Fehler wirft.
    # Mit Powershell 7 erhält Invoke-Webrequest einen neuen Parameter: -SkipHttpErrorCheck. Damit wäre das hier vermutlich überflüssig.
    Set-CertificateValidationPolicy

    $BaseResponse = try {
        $PrimaryResponse = Invoke-WebRequest @PSBoundParameters
        $PrimaryResponse.BaseResponse
    }
    catch [System.Net.WebException] {
        Write-Verbose "An exception was caught: $($_.Exception.Message)"
        $_.Exception.Response # Nur BaseResponse bei Exceptions möglich
    }
    $ResponseHash = @{
        BaseResponse = $BaseResponse
        Response     = $PrimaryResponse
    }
    $ResponseObject = New-Object -TypeName psobject -Property $ResponseHash
    return $ResponseObject
}
function Invoke-CMKApiCall {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method,
        [parameter(Mandatory, HelpMessage = 'Sub-URI der API Funktion (mit / ab der Versionsangabe)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,
        [parameter(Mandatory)]
        [object]
        $Connection,
        [parameter()]
        [object]
        $Body,
        [Parameter()]
        [switch]
        $EndpointReturnsList
    )
    # Wandelt das Ergebnis einer CustomWebRequest zu einem Objekt.
    # Schlägt der Aufruf fehl, wird nur $false zurückgegeben.

    If (-not (Test-Connection -ComputerName $Connection.Hostname -Count 1 -Quiet)) {
        Write-Verbose "$($Connection.Hostname) ist nicht erreichbar (icmp ping)"
        return $false #todo (Fehler werfen!, nicht false)
    }

    $PSBoundParameters.Headers = $Connection.Header
    $PSBoundParameters.Uri = "$($Connection.APIUrl)$($Uri)"
    $PSBoundParameters.Remove('Connection') | Out-Null
    $PSBoundParameters.Remove('EndpointReturnsList') | Out-Null

    $Response = Invoke-CustomWebRequest @PSBoundParameters
    Write-Verbose "$([int]($Response.BaseResponse.StatusCode)) $($Response.BaseResponse.StatusDescription)"
    if ([int]($Response.BaseResponse.StatusCode) -eq 200) {
        # 200 Ok
        $CheckKMObject = ($Response.Response.Content | ConvertFrom-Json)
        $CheckKMObject | Add-Member -MemberType NoteProperty -Name ETag -Value $Response.Response.Headers.ETag

        if ($EndpointReturnsList.IsPresent) {
            return $CheckKMObject.Value
        }
        else {
            return $CheckKMObject
        }
    }
    elseif ((@('Post', 'Delete') -contains $Method) -and ([int]($Response.BaseResponse.StatusCode) -eq 204)) {
        # 204 No Content
    }
    else {
        # Nicht OK. Error Code lässt sich mit -verbose anzeigen.
        return $false  #todo (Fehler werfen!, nicht false)
    }
}
#endregion Connection
#region Main
function Get-CMKServerInfo {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [object]
        $Connection
    )
    return Invoke-CMKApiCall -Method Get -Uri '/version' -Connection $Connection
}
function Get-CMKPendingChanges {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $Connection
    )
    return Invoke-CMKApiCall -Method Get -Uri '/domain-types/activation_run/collections/pending_changes' -Connection $Connection
}
function Invoke-CMKChangeActivation {
    [CmdletBinding()]
    param(
	    [Parameter(Mandatory, HelpMessage = 'Abgerufen mit Get-CMKPendingChanges')]
        [object]
        $PendingChanges,
        [parameter(HelpMessage = 'Sollen durch andere Nutzer durchgeführte Änderungen mit Aktiviert werden? Pflicht, wenn es welche gibt.')]
        [switch]
        $ForceForeignChanges,
        [parameter(Mandatory)]
        [object]
        $Connection
    )
    $activateChanges = @{
        force_foreign_changes = $ForceForeignChanges.IsPresent
        redirect              = $false
        sites                 = [array]$Connection.sitename
    } | ConvertTo-Json
    $oneTimeConnection = Get-CMKConnection -Hostname $Connection.hostname -Sitename $Connection.sitename -Username $Connection.username -IfMatch $PendingChanges.Etag
    $CheckMKActivationObject = Invoke-CMKApiCall -Method Post -Uri '/domain-types/activation_run/actions/activate-changes/invoke' -Body $activateChanges -Connection $oneTimeConnection
    if (-not $CheckMKActivationObject) {
        return $false
    }
    $AttemptForCompletion = 0
    $maximumAttemptsForCompletion = 14 # Den Wert ggf. noch anpassen. Vielleicht dauern Aktivierungen ja regelmäßig länger.
    do {
        Start-Sleep -Seconds 3
        $AttemptForCompletion++
        $activationStatus = Invoke-CMKApiCall -Method Get -Uri "/objects/activation_run/$($CheckMKActivationObject.id)" -Connection $Connection
        $result = [string]($activationStatus.title).split(' ')[-1].replace('.', '')
    }
    until (($result -eq 'completed') -or ($AttemptForCompletion -gt $maximumAttemptsForCompletion))
    If (($result -ne 'completed')) {
        Write-Verbose "Die Aktivierung der Änderungen konnte nicht innerhalb von $maximumAttemptsForCompletion abgeschlossen werden. Result: $Result"
        return $false
    }
}
#endregion Main
#region Hosts
function Get-CMKHost {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Spezifisch')]
        [ValidateNotNullOrEmpty()]
        [string]
        $HostName,
        [Parameter(Mandatory, ParameterSetName = 'Spezifisch')]
        [Parameter(Mandatory, ParameterSetName = 'Liste')]
        $Connection
    )
    If ($PSCmdlet.ParameterSetName -eq 'Spezifisch') {
        return Invoke-CMKApiCall -Method Get -Uri "/objects/host_config/$($HostName)" -Connection $Connection
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Liste') {
        return Invoke-CMKApiCall -Method Get -Uri '/domain-types/host_config/collections/all' -Connection $Connection -EndpointReturnsList

    }
}
function New-CMKHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $HostName,
        [Parameter(Mandatory, HelpMessage = 'Pfad zum Ordner. Anstelle von Slash bitte Tilde ~ benutzen. Case-Sensitive. Entspricht dem Attribut id im Objekt von Get-CheckMKFolder.')]
        [string]
        $FolderPath,
        [parameter(Mandatory)]
        [object]
        $Connection
    )
    $newHost = @{
        folder    = "$FolderPath"
        host_name = "$($HostName)"
    } | ConvertTo-Json
    return Invoke-CMKApiCall -Method Post -Uri '/domain-types/host_config/collections/all' -Body $newHost -Connection $Connection

}
function Rename-CMKHost {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, HelpMessage = 'Mit Get-CMKHost abgerufen')]
        [object]
        $HostObject,
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $newHostName,
        [parameter(Mandatory)]
        [object]
        $Connection
    )
    # Ist langsam. Behindert den Betrieb von CheckMK (Server steht während der Zeit). Dauer: ca 30 Sekunden
    # Im Anschluss: Invoke-CMKChangeActivation
    $oneTimeConnection = Get-CMKConnection -Hostname $Connection.hostname -Sitename $Connection.sitename -Username $Connection.username -IfMatch $HostObject.Etag
    $newName = @{
        new_name = $newHostName
    } | ConvertTo-Json
    return Invoke-CMKApiCall -Method Put -Uri "/objects/host_config/$($HostObject.id)/actions/rename/invoke" -Body $newName -Connection $oneTimeConnection
}
function Update-CMKHost {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, HelpMessage = 'Mit Get-CMKHost abgerufen')]
        [object]
        $HostObject,
        [parameter(Mandatory, HelpMessage = 'Lies die Doku! https://<CheckMK-Host>/<sitename>/check_mk/api/1.0/ui/#/Hosts/cmk.gui.plugins.openapi.endpoints.host_config.update_host')]
        $Changeset,
        [parameter(Mandatory)]
        [object]
        $Connection
    )
    # https://<CheckMK-Host>/<sitename>/check_mk/api/1.0/ui/#/Hosts/cmk.gui.plugins.openapi.endpoints.host_config.update_host
    $oneTimeConnection = Get-CMKConnection -Hostname $Connection.hostname -Sitename $Connection.sitename -Username $Connection.username -IfMatch $HostObject.Etag
    return Invoke-CMKApiCall -Method Put -Uri "/objects/host_config/$($HostObject.id)" -Body $Changeset -Connection $oneTimeConnection
}
function Remove-CMKHost {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HostName,
        [parameter(Mandatory)]
        [object]
        $Connection
    )
    return Invoke-CMKApiCall -Method Delete -Uri "/objects/host_config/$HostName" -Connection $Connection
}
#endregion Hosts
#region Hosts Hilfsfunktionen
function Set-CMKHostAttribute {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, HelpMessage = 'Mit Get-CMKHost abgerufen', ParameterSetName = 'Update')]
        [parameter(Mandatory, HelpMessage = 'Mit Get-CMKHost abgerufen', ParameterSetName = 'Remove')]
        [object]
        $HostObject,
        [parameter(Mandatory, ParameterSetName = 'Update')]
        [Alias('SetAttribute')]
        [string]
        $UpdateAttribute,
        [parameter(Mandatory, ParameterSetName = 'Update')]
        $Value,
        [parameter(Mandatory, ParameterSetName = 'Remove')]
        [string]
        $RemoveAttribute,
        [parameter(Mandatory, ParameterSetName = 'Update')]
        [parameter(Mandatory, ParameterSetName = 'Remove')]
        [object]
        $Connection
    )
    #Hinweis zu Custom Host Attributes: Diese lassen sich anlegen und bearbeiten, aber nicht löschen. Da ist die API noch fehlerhaft.
    $Changeset = @{}
    If ($PSCmdlet.ParameterSetName -eq 'Update') {
        $Changeset.update_attributes = @{
            $UpdateAttribute = $Value
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Remove') {
        $Changeset.remove_attributes = [array]("$RemoveAttribute")
    }
    $Changeset = $Changeset | ConvertTo-Json
    return Update-CMKHost -HostObject $HostObject -Changeset $Changeset -Connection $Connection
}
function Add-CMKHostLabel {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [object]
        $HostObject,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Key,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Value,
        [Parameter(Mandatory)]
        [object]
        $Connection
    )
    $Labels = @{}
    If ($HostObject.extensions.attributes.labels) {
        Foreach ($Pair in ($HostObject.extensions.attributes.labels.PSObject.Members | Where-Object -FilterScript { $_.MemberType -eq 'NoteProperty' })) {
            $Labels.add($Pair.Name, $Pair.Value)
        }
    }
    If ($Labels.$Key) {
        Write-Verbose "Der Schlüssel $Key ist auf $($HostObject.id) bereits vorhanden"
        return $false
    }
    else {
        $Labels.Add($Key, $Value)
        return Set-CMKHostAttribute -HostObject $HostObject -UpdateAttribute 'labels' -Value $Labels -Connection $Connection
    }
}
function Remove-CMKHostLabel {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [object]
        $HostObject,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Key,
        [Parameter(Mandatory)]
        [object]
        $Connection
    )
    If ($HostObject.extensions.attributes.labels) {
        $Labels = @{}
        Foreach ($Pair in ($HostObject.extensions.attributes.labels.PSObject.Members | Where-Object -FilterScript { $_.MemberType -eq 'NoteProperty' })) {
            $Labels.add($Pair.Name, $Pair.Value)
        }
        $Labels.Remove($Key)
        If ($Labels.Count -gt 0) {
            return Set-CMKHostAttribute -HostObject $HostObject -UpdateAttribute 'labels' -Value $Labels -Connection $Connection
        }
        else {
            return Set-CMKHostAttribute -HostObject $HostObject -RemoveAttribute 'labels' -Connection $Connection
        }
    }
    else {
        Write-Verbose "Auf Host $($HostObject.id) sind keine Labels vorhanden"
        return $false
    }
}
#endregion Hosts Hilfsfunktionen
#region Folders
function Get-CMKFolder {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'Pfad zum Ordner. Anstelle von Slash bitte Tilde ~ benutzen. Case-Sensitive. Entspricht dem Attribut id im zurückerhaltenen Objekt.', ParameterSetName = 'Spezifisch')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ If ( ($_ -notmatch '^~.*$') -or ($_.ToCharArray() -contains @('/', '\')) ) { throw 'Der Ordnerpfad ist nicht wohlgeformt.' } $true })]
        [string]
        $FolderPath,
        [parameter(HelpMessage = 'Liste der Hosts im Ordner einschließen', ParameterSetName = 'Spezifisch')]
        [switch]
        $ShowHosts,
        [parameter(Mandatory, ParameterSetName = 'Spezifisch')]
        [parameter(Mandatory, ParameterSetName = 'Liste')]
        $Connection
    )
    If ($PSCmdlet.ParameterSetName -eq 'Spezifisch') {
        If ($ShowHosts.IsPresent) {
            $ShowHosts_bool = 'true'
        }
        else {
            $ShowHosts_bool = 'false'
        }
        return Invoke-CMKApiCall -Method Get -Uri "/objects/folder_config/$($FolderPath)?show_hosts=$($ShowHosts_bool)" -Connection $Connection
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Liste') {
        return Invoke-CMKApiCall -Method Get -Uri '/domain-types/folder_config/collections/all?recursive=true&show_hosts=false' -Connection $Connection -EndpointReturnsList

    }
}
#endregion Folders
#region Downtimes
function Get-CMKDowntime {
    [CmdletBinding()]
    param(
        [parameter(HelpMessage = 'Downtimes nur dieses Hosts abfragen')]
        [string]
        $HostName,
        <#[parameter(HelpMessage = 'Downtimes nur dieses Service abfragen. Case-Sensitive')]
        [string]
        $ServiceDescription,#>
        [parameter(Mandatory)]
        [object]
        $Connection
    )
    $QueryExtension = ''
    If ($HostName -or $ServiceDescription) {
        $QueryExtension += '?'
    }
    <#If ($ServiceDescription) {
        $QueryExtension += "service_description=$($ServiceDescription)"
    }
    If ($HostName -and $ServiceDescription) {
        $QueryExtension += '&'
    }#>
    If ($HostName) {
        $QueryExtension += "host_name=$($HostName)"
    }
    return Invoke-CMKApiCall -Method Get -Uri "/domain-types/downtime/collections/all$($QueryExtension)" -Connection $Connection -EndpointReturnsList
}
function New-CMKDowntime {
    [CmdletBinding()]
    param(
        [parameter(
            Mandatory,
            ParameterSetName = 'onHost',
            HelpMessage = 'Die Downtime wird für den genannten Host gesetzt'
        )]
        [parameter(
            Mandatory,
            ParameterSetName = 'onService',
            HelpMessage = 'Die Downtime wird für die genannten Services dieses Hosts gesetzt'
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $HostName,
        [parameter(
            Mandatory,
            ParameterSetName = 'onService',
            HelpMessage = 'Die Downtime wird nur für angegebene Services gesetzt (Case Sensitive)'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ServiceDescriptions,
        [parameter(
            ParameterSetName = 'onHost'
        )]
        [parameter(
            ParameterSetName = 'onService'
        )]
        [datetime]
        $StartTime = (Get-Date),
        [parameter(
            Mandatory,
            ParameterSetName = 'onHost'
        )]
        [parameter(
            Mandatory,
            ParameterSetName = 'onService'
        )]
        [datetime]
        $EndTime,
        [parameter(
            ParameterSetName = 'onHost'
        )]
        [parameter(
            ParameterSetName = 'onService'
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $Comment,
        [parameter(
            Mandatory,
            ParameterSetName = 'onHost'
        )]
        [parameter(
            Mandatory,
            ParameterSetName = 'onService'
        )]
        [object]
        $Connection
    )
    $Downtime = @{
        start_time = ($StartTime | Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz') #Format ISO 8601 für CheckMK erforderlich
        end_time   = ($EndTime | Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')
        host_name  = "$($HostName)"
    }
    If ($Comment) {
        $Downtime.comment = $Comment
    }
    If ($PSCmdlet.ParameterSetName -eq 'onHost') {
        $Downtime.downtime_type = 'host'
        $Downtime = $Downtime | ConvertTo-Json
        return Invoke-CMKApiCall -Method Post -Uri '/domain-types/downtime/collections/host' -Body $Downtime -Connection $Connection
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'onService') {
        $Downtime.downtime_type = 'service'
        $Downtime.service_descriptions = [array]$ServiceDescriptions
        $Downtime = $Downtime | ConvertTo-Json
        return Invoke-CMKApiCall -Method Post -Uri '/domain-types/downtime/collections/service' -Body $Downtime -Connection $Connection
    }
}
function Remove-CMKDowntime {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ParameterSetName = 'byID')]
        [int]
        $ID,
        [parameter(Mandatory, ParameterSetName = 'byHostName')]
        [parameter(Mandatory, ParameterSetName = 'byHostNameAndServiceDescriptions')]
        [string]
        $HostName,
        [parameter(Mandatory, ParameterSetName = 'byHostNameAndServiceDescriptions')]
        [string[]]
        $ServiceDescriptions,
        [parameter(Mandatory, ParameterSetName = 'byHostName')]
        [parameter(Mandatory, ParameterSetName = 'byID')]
        [parameter(Mandatory, ParameterSetName = 'byHostNameAndServiceDescriptions')]
        [object]
        $Connection
    )
    $Delete = @{}
    If ($PSCmdlet.ParameterSetName -eq 'byID') {
        $Delete.delete_type = 'by_id'
        $Delete.downtime_id = "$ID"
		$Delete.site_id = "$($Connection.sitename)"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'byHostName') {
        $Delete.delete_type = 'params'
        $Delete.host_name = "$($HostName)"

    }
    elseif ($PSCmdlet.ParameterSetName -eq 'byHostNameAndServiceDescriptions') {
        $Delete.delete_type = 'params'
        $Delete.host_name = "$($HostName)"
        $Delete.service_descriptions = [array]$ServiceDescriptions

    }
    $Delete = $Delete | ConvertTo-Json
    return Invoke-CMKApiCall -Method Post -Uri '/domain-types/downtime/actions/delete/invoke' -Body $Delete -Connection $Connection
}
#endregion Downtimes
$ExportableFunctions = @(
    'Get-CMKConnection'
    'Invoke-CMKApiCall'
    'Get-CMKServerInfo'
    'Invoke-CMKChangeActivation'
    'Get-CMKHost'
    'New-CMKHost'
    'Rename-CMKHost'
    'Update-CMKHost'
    'Remove-CMKHost'
    'Set-CMKHostAttribute'
    'Add-CMKHostLabel'
    'Remove-CMKHostLabel'
    'Get-CMKFolder'
    'Get-CMKDowntime'
    'New-CMKDowntime'
    'Remove-CMKDowntime'
	'Get-CMKPendingChanges'
)
Export-ModuleMember -Function $ExportableFunctions

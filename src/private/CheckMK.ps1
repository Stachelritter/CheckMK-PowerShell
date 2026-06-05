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
function EscapeNonAscii([Parameter(Mandatory,ValueFromPipeline)][string] $s) {
    # Ab Powershell 7 soll stattdessen an ConvertTo-Json der Parameter -EscapeHandling EscapeNonAscii verwendet werden.
    Process {
        $sb = New-Object System.Text.StringBuilder
        for ([int] $i = 0; $i -lt $s.Length; $i++) {
            $c = $s[$i]
            if ($c -gt 127) {
                $sb = $sb.Append("\u").Append(([int] $c).ToString("X").PadLeft(4, "0"))
            }
            else {
                $sb = $sb.Append($c)
            }
        }
        $sb.ToString()
    }
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
        [parameter(Mandatory, HelpMessage = 'Passwort zum Zugriff auf die CheckMK API.')]
        [ValidateNotNullOrEmpty()]
		[SecureString]
		$Secret,
        [parameter(HelpMessage = 'Wenn bestehende Objekte bearbeitet werden sollen, muss das ETag des Objektes zuvor abgerufen und bei der Änderungsanfrage in den Header eingefügt werden.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IfMatch
    )


	# Ab PS7 wird ConvertFrom-SecureString möglich
    $password = [System.Net.NetworkCredential]::new("", $Secret).Password

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
    $PSBoundParameters.Add('UseBasicParsing', $true)
    $BaseResponse = try {
        $PrimaryResponse = Invoke-WebRequest @PSBoundParameters
        $PrimaryResponse.BaseResponse
        }
        catch [System.Net.WebException] {
            $ErrMessage =  $_.ErrorDetails.Message;
            Write-Verbose "An exception was caught: $($_.Exception.Message)"
            $ResponseErrorObj = $_.Exception.Response # Nur BaseResponse bei Exceptions möglich
            Add-Member -InputObject $ResponseErrorObj -NotePropertyName ErrorMessage -NotePropertyValue $ErrMessage #add catched error message to $BaseResponse object
            $ResponseErrorObj
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
    $ConnectionCheckIntervalMinutes = 60
    If ($Global:CMKLastSuccessfulConnect -and (($Global:CMKLastSuccessfulConnect | Get-Date) -gt (Get-Date).AddMinutes(-$ConnectionCheckIntervalMinutes))){
        # Recently checked
        Write-Verbose ":$($MyInvocation.MyCommand): Last connection check at $($Global:CMKLastSuccessfulConnect)."
    }
    else {
        # New check required
        Write-Verbose ":$($MyInvocation.MyCommand): Connection check..."
        If (-not (Test-NetConnection -ComputerName $Connection.Hostname -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded) {
            Write-Verbose "$($Connection.Hostname) ist nicht erreichbar"
            throw [System.Net.WebException]
        } 
        else {
            $Global:CMKLastSuccessfulConnect = Get-Date -Format 'o'
        }
    }

    $PSBoundParameters.Headers = $Connection.Header
    $PSBoundParameters.Uri = "$($Connection.APIUrl)$($Uri)"
    $PSBoundParameters.Remove('Connection') | Out-Null
    $PSBoundParameters.Remove('EndpointReturnsList') | Out-Null
    Write-Verbose "$Method $($PSBoundParameters.Uri)   ---  Body: $($PSBoundParameters.Body)"
    $Response = Invoke-CustomWebRequest @PSBoundParameters
    Write-Verbose "$([int]($Response.BaseResponse.StatusCode)) $($Response.BaseResponse.StatusDescription)"
    if ([int]($Response.BaseResponse.StatusCode) -eq 200) {
        # 200 Ok
        $CheckMKObject = ($Response.Response.Content | ConvertFrom-Json)
        $CheckMKObject | Add-Member -MemberType NoteProperty -Name ETag -Value $Response.Response.Headers.ETag

        if ($EndpointReturnsList.IsPresent) {
            return $CheckMKObject.Value
        }
        else {
            return $CheckMKObject
        }
    }
    elseif ((@('Post', 'Delete') -contains $Method) -and ([int]($Response.BaseResponse.StatusCode) -eq 204)) {
        # 204 No Content
    }
    else {
        # Nicht OK. Error Code lässt sich mit -verbose anzeigen.
        throw "StatusCode: $([int]($Response.BaseResponse.StatusCode)) StatusDescription: $($Response.BaseResponse.StatusDescription)`r`nMessage: `r`n$($Response.BaseResponse.ErrorMessage)"
    }
}
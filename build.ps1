$partsFolder = Join-Path -Path $PSScriptRoot -ChildPath 'src'
if (-not (Test-Path -Path $partsFolder -PathType Container)) {
    Write-Host 'Parts container not found!'
    exit 1
}
Write-Host 'Pipeline variables not initialized, running from local moduleinfo.json'
$jsonPath = Join-Path -Path $PSScriptRoot -ChildPath 'moduleinfo.json'
if (Test-Path -Path $jsonPath -PathType Leaf) {
    $moduleInfo = (Get-Content -Path $jsonPath | ConvertFrom-Json)
} else {
    Write-Host 'moduleinfo.json not found!'
    exit 1    
}
If ($env:GITHUB_REF -like 'refs/tags/*') {
    # pipeline release build, with version
    $tag = $env:GITHUB_REF -replace 'refs/tags/', ''
    $version = $tag -replace '^v', ''
} elseIf ($env:GITHUB_REF) {
    # normal pipeline build, no version
    $version = '0.0.0'
} else {
    # local build, no version
    $version = '0.0.0'
}
$outputFolder = Join-Path -Path $PSScriptRoot -ChildPath $moduleInfo.ModuleName
if (-not (Test-Path -Path $outputFolder -PathType Any)) {
    try {
        $null = New-Item -Path $outputFolder -ItemType Directory -Force -EA Stop
    } catch {
        Write-Host 'Error creating output folder: {0}' -f $_.Exception.Message
        exit 2
    }
}
$moduleManifestName = Join-Path -Path $outputFolder -ChildPath ('{0}.psd1' -f $moduleInfo.ModuleName)
$moduleBodyName = Join-Path -Path $outputFolder -ChildPath ('{0}.psm1' -f $moduleInfo.ModuleName)
$lines = New-Object System.Collections.Generic.List[string]
$functions = New-Object System.Collections.Generic.List[string]
$curFile = Join-Path -Path $partsFolder -ChildPath '_header.ps1'
if (Test-Path -Path $curFile -PathType Leaf) {
    Write-Host 'Processing header'
    foreach ($line in (Get-Content -Path $curFile)) {
        $null = $lines.Add($line)
    }
}

$privateFolder = Join-Path -Path $partsFolder -ChildPath 'private'
if (Test-Path -Path $privateFolder -PathType Container) {
    foreach ($file in (Get-ChildItem -Path $privateFolder -Filter '*.ps1')) {
        Write-Host ('Processing private insert {0}' -f $file.Name)
        $curFile = $file.FullName
        foreach ($line in (Get-Content -Path $curFile)) {
            $null = $lines.Add($line)
        }
    }
}

$publicFolder = Join-Path -Path $partsFolder -ChildPath 'public'
if (Test-Path -Path $publicFolder -PathType Container) {
    foreach ($file in (Get-ChildItem -Path $publicFolder -Filter '*.ps1')) {
        Write-Host ('Processing public insert {0}' -f $file.Name)
        $curFile = $file.FullName
        foreach ($line in (Get-Content -Path $curFile)) {
            $null = $lines.Add($line)
        }
        $funcs = (Get-Command $curFile).ScriptBlock.Ast.FindAll(
            { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] },$false 
        ).Name
        foreach ($func in $funcs) {
            Write-Host ('Adding function {0}' -f $func)
            $null = $functions.Add($func)
        }
    }
}

$curFile = Join-Path -Path $partsFolder -ChildPath '_footer.ps1'
if (Test-Path -Path $curFile -PathType Leaf) {
    Write-Host 'Processing footer'
    foreach ($line in (Get-Content -Path $curFile)) {
        $null = $lines.Add($line)
    }
}
if ($functions.Count -gt 0) {
    $null = $lines.Add(('Export-ModuleMember -Function @(''{0}'')' -f ($functions -join ''', ''')))
}
try {
    $lines | Set-Content -Path $moduleBodyName -Encoding UTF8BOM -Force -EA Stop
} catch {
    exit 3
}
$manifestData = @{
    ModuleVersion = $version
    GUID = $moduleInfo.ModuleGUID
    Author = $moduleInfo.moduleAuthor
    CompanyName = $moduleInfo.companyName
    Copyright = ('{0} {1}' -f [datetime]::Now.Year, $moduleInfo.companyName)
    Description = $moduleInfo.Description
	HelpInfoURI = $moduleInfo.HelpInfoURI
    ProjectURI = $moduleInfo.ProjectURI
    PowerShellVersion = $moduleInfo.PowerShellVersion
    CompatiblePSEditions = $moduleInfo.CompatiblePSEditions
    Path = $moduleManifestName
    RootModule = ('{0}.psm1' -f $moduleInfo.ModuleName)
    NestedModules = @()
    RequiredModules = $moduleInfo.RequiredModules
    FunctionsToExport = $functions
    CmdletsToExport = @()
    VariablesToExport = @()
    PrivateData = @{}
    Tags = $moduleInfo.Tags
}

Write-Host 'Building module manifest'
New-ModuleManifest @manifestData

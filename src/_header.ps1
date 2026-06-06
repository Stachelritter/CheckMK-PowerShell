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
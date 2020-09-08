
#
# Pieter De Ridder
#
# Utility script to request Certificate password (hashed) from user, so we can store it safe for later import.
# Works with *.p12 and *.pfx certificates.
#
# One will be able to retrieve the password from the hash file. But will need some Powershell knowledge to do so.
#
# Create date : 07/09/2020
# Change date : 08/09/2020
#
# usage:
# .\certs_store_hash.ps1
#
# No parameters required
#


# global variables
[string]$global:CurrentFolder   = $PSScriptRoot
[bool]$global:IsIntegerAnswer   = $false


#
# Function : Exit-Script
# exit script
#
Function Exit-Script() {
    Write-Host ""
    Write-Host "-- END --"
    Write-Host ""
    Exit(0)
}

#
# Function : Abort-Script
# abort script if needed
#
Function Abort-Script() {
    Write-Host ""
    Write-Warning "-- ABORTED --"
    Write-Host ""
    Exit(6)  # SIGABRT
}


#
# Function : Main
# Main function body
#
Function Main {
    Param (
        $Arguments
    )

    # search all *.p12 or *.pfx files
    $arrCertificateFiles = @(Get-ChildItem -Path "$($global:CurrentFolder)\*" -File -Include *.p12, *.pfx)

    # list a menu for user, so (s)he can choose
    [int32]$answer = -1
    do {
        try {      
            [int32]$number = 1
            Write-Host "Found following certificates:"
            ForEach($CertFile in $arrCertificateFiles) {
                Write-Host "$($number) : $($CertFile.Name)"
                $number += 1
            }

            $answer = Read-Host -Prompt "Choose certificate by number"
            $global:IsIntegerAnswer = $true
        } catch {
            Write-Warning "Wrong code, retry."
            Start-Sleep -Seconds 2
        }
    } while (($answer -lt 1) -or ($answer -gt $arrCertificateFiles.Length))
    
    # generate password file for the selected user certificate
    if ($global:IsIntegerAnswer) {
        # get the original full filename of the certificate file
        [string]$originalFileName = "$($arrCertificateFiles[$answer -1].FullName)"

        Write-Host ""
        Write-Host "-> Selected $([char]34)$(Split-Path $originalFileName -Leaf)$([char]34)."

        # store the password hash in a .txt file
        [string]$hash_filename = "$($originalFileName.Substring(0, $originalFileName.Length -3))txt"
    
        # prompt certificate password to user
        [System.Security.SecureString]$password = Read-Host -Prompt "Enter the password for the certificate" -AsSecureString

        # store password in hashed file
        $hash_credential = New-Object -TypeName System.Management.Automation.PSCredential -Argumentlist "username_does_not_matter", $password
        $hash_credential.Password | ConvertFrom-SecureString | Set-Content $hash_filename

        Write-Host ""
        Write-Host "Written $($hash_filename) file."
    } else {
        # bail out
        Abort-Script
    }

    # end script
    Exit-Script
}

# --- main function ---
# The global $args variable (Powershell runspace created variable),
# is proxied through the main function.
Main -Arguments $args

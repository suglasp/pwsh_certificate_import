
#
# Pieter De Ridder
#
# Script to import certificates to user or computer stores.
#
# Create date : 07/09/2020
# Change date : 08/09/2020
#
# usage:
# .\certs_import.ps1 [-user] [-computer] [-store cert:\<path>] [-export] [-debug]
#
# default : running .\certs_import.ps1 is equal to running .\certs_import.ps1 -user
#


# global variables
[string]$global:CurrentFolder    = $PSScriptRoot
[string]$global:CertificateStore = "Cert:\CurrentUser\My"
[string]$global:UserBranch       = $True
[bool]$global:Debug              = $False
[bool]$global:Exportable         = $False

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
# Function : Write-Dump
# Dump some debug info
#
Function Write-Dump() {
    param(
        [string]$msg
    )

    If ($global:Debug) {
        Write-Host "DEBUG : $($msg)"
    }
}


#
# Function : Main
# Main function body
#
Function Main {
    Param (
        $Arguments
    )

    # process script CLI args
    if ($Arguments) {
        for($i = 0; $i -lt $Arguments.Length; $i++) {

           [string]$strLowerArch = $Arguments[$i].ToString().ToLowerInvariant()

           Switch ($strLowerArch) {
                "-user" {
                    # enable user importing
                    $global:UserBranch = $True
                }

                "-computer" {
                    # enable computer importing
                    $global:UserBranch = $False
                }

                "-store" {
                    # custom store path
                    If (($i +1) -le $Arguments.Length) {
                        $global:CertificateStore = $Arguments[$i+1]

                        If ($global:CertificateStore.ToLowerInvariant().Contains("localmachine")) {
                            $global:UserBranch = $False
                        } else {
                            $global:UserBranch = $True
                        }
                    }
                }

                "-export" {
                    # make PFX or P12 Exportable
                    $global:Exportable = $True
                }

                "-debug" {
                    # enable debugging mode
                    $global:Debug = $True
                }


            }
        }
    }


    # If the user provides -Computer and no -Store option, make sure the 'default' import path is changed to the machine My store.
    If ($global:CertificateStore.ToLowerInvariant().Contains("my")) {
        If ($global:UserBranch -eq $False) {
            $global:CertificateStore = "Cert:\LocalMachine\My"
       
            Write-Dump -msg "STORE OVERRIDE to Machine My"
        }
    }
    
    # debugging output
    Write-Dump -msg "$($global:UserBranch)"
    Write-Dump -msg "$($global:CertificateStore)"
    Write-Dump -msg "$($global:Exportable)"

    # Import certificate if the provided store path is correct
    If (Test-Path $global:CertificateStore) {
    
        # search all *.cer, *.p12 or *.pfx files
        $arrCertificateFiles = @(Get-ChildItem -Path "$($global:CurrentFolder)\*" -File -Include *.cer, *.p12, *.pfx)
    
        # try to import each found certificates
        ForEach($CertFile in $arrCertificateFiles) {

            # PFX/P12 hashed password placeholder
            [System.Management.Automation.PsCredential]$CertificateCredential = $null

            # get the original full filename of the certificate file
            [string]$originalFileName = "$($CertFile.FullName)"
    
            If ($CertFile.Extension.ToLowerInvariant() -eq ".cer")  {
                # IMPORT CER FILE
                Write-Host ">> Importing CER file"
                Write-Host "File  : $($originalFileName)"
                Write-Host "Store : $($global:CertificateStore)"
                Write-Host ""

                try {
                    Import-Certificate -FilePath $originalFileName -CertStoreLocation $global:CertificateStore
                } catch {
                    Write-Warning "[!] Error while importing CER file."
                    Abort-Script
                }
            } else {
                # IMPORT PFX FILE
                Write-Host ">> Importing PFX file"
                Write-Host "File  : $($originalFileName)"
                Write-Host "Store : $($global:CertificateStore)"
                Write-Host ""

                # load the certificate password hash if the .txt file exists
                [string]$hash_filename = "$($originalFileName.Substring(0, $originalFileName.Length -3))txt"

                If (Test-Path $hash_filename) {
                    Write-Host "Certificate password hash present."
                    $CertificateHash = Get-Content $hash_filename | ConvertTo-SecureString
                    $CertificateCredential = New-Object System.Management.Automation.PsCredential("username_does_not_matter", $CertificateHash)

                    #$CertificateCredential.GetNetworkCredential().UserName
                    #$CertificateCredential.GetNetworkCredential().Password
                } else {
                    Write-Host "[!] Certificate password hash file is NOT present."
                    Abort-Script
                }


                If ($CertificateCredential) {
                    try {
                        If ($global:Exportable) {
                            Import-PfxCertificate -FilePath $originalFileName -Password $CertificateCredential.Password -CertStoreLocation $global:CertificateStore
                        } Else {
                            Import-PfxCertificate -FilePath $originalFileName -Password $CertificateCredential.Password -CertStoreLocation $global:CertificateStore -Exportable
                        }
                    } catch {
                        Write-Warning "[!] Error while importing PFX file."
                        Write-Warning " -> Possibly password incorrect or, on machine Store level, you need Administrator priviledges."
                        Abort-Script
                    }
                } else {
                    Write-Warning "[!] PFX password is NULL? Aborted!"
                    Abort-Script
                }
            }
        }

    } else {
        Write-Warning "[!] Store $($global:CertificateStore) does not exist. Aborted!"
        Abort-Script
    }

    # end script
    Exit-Script
}


# --- main function ---
# The global $args variable (Powershell runspace created variable),
# is proxied through the main function.
Main -Arguments $args

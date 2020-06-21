########################################################################
#
##################### DNSCleaner #######################################
#
# Required to run properly (in the same directory):
# DnsShell.dll ; HANDLE.psm1 ; handle.exe ; Administrator Privileges
#
# Version: 04-11-2015
# Author:  Fabian Dubacher
#
##################### Description: #####################################
#
# This script lets you configure DNS-Zones and :
#  - logs CNAMES, which point to non-existing A/AAAA-Records.
#  - logs A/AAAA-Records, which do not have accompanying PTR-Records.
#  - logs PTR-Records, which do not have accompanying A/AAAA-Records.
#  - emails the logfile to the specified email-address, if configured.
#
#  IMPORTANT: If there is no log file in the defined directory after
#             the script was run, the script is not done yet (wait at
#             least 5 minutes) or something went wrong.
#
#########################################################################

#<Settings>

#Full path and name of the input file
[string]$script:inputFile = "C:\Users\test\Desktop\InputFile.txt"

#Full path and name of the output file (Time Stamp is being added only if $sendMail is $false)
[string]$script:outputFile = "C:\Users\test\Desktop\OutputFile.txt"

#Full path and name of the Error/Warning-Log-File
[string]$script:logFile = "C:\Users\test\Desktop\Log.txt"

#Name or IP of the DNS Server
[string]$script:server = "192.168.159.130"

#Add a zone to check by separating them with a "," (at least one forward and one reverse zone is required)
[array]$script:zone = "test.local", "1.0.0.2.ip6.arpa", "1.168.192.in-addr.arpa", "not.existing.local"

#Define a forward zone filter in regex format. For example if you have a zone like this: "example.zone.germany.de", the filter would look like this: "(.[^\s])+?\.example\.zone\.germany\.de"
[regex]$script:forwardZoneFilter = "(.[^\s])+?\.test\.local"

# $true = queries the DNS Server and generates a new input file (Path defined in inputFile)
# $false = tries to get the file from the directory
[bool]$script:queryDns = $true

#email

# $true = send an email after every check with the inputfile, the outputfile and the logfile as an attachement
# $false = doesn't send an email
[bool]$script:sendMail = $true
$script:From = "E-Mail-Adresse"
$script:To = "E-Mail-Adresse"
$script:Subject = "DNS:Check"
$script:Body = "log of the last check: `r`n`r`n" #log is added in the send mail function
$script:SMTPServer = "smtp.gmail.com"
$script:SMTPPort = "587"
$script:Credentials = New-Object System.Management.Automation.PSCredential "benutzername", (ConvertTo-SecureString "password" -AsPlainText -force)

# </End Settings>


# <Variables>

#Content of the log file before it's getting written to the disk
[string]$script:log = ""

#The array of record types which get checked by the script
[array]$script:recordTypes = "A", "CNAME", "AAAA", "PTR"

#The content of the currently worked on file is getting loaded into this array
[array]$script:currentFile = $null

#Attachement of the email
$script:Attachment_OutputFile = $script:outputFile
$script:Attachment_LogFile = $script:logFile
$script:Attachment_InputFile = $script:inputFile

#Script start path
$script:ScriptStartDir = Split-Path $MyInvocation.MyCommand.Path

# </End variables>


#<Functions>

#queries DNS and writes all records (A, AAAA, CNAME, PTR) of DNS into a structured plain text input file
function WriteDnsRecordsToFile
{
    try
    {
        $null > $script:inputFile
    }
    catch
    {
        ProcessError("Attempt to create " + "`s" + $script:inputFile + "`s" + "failed")
    }

    try
    {
        if ((Test-Connection -Computername $server -BufferSize 16 -Count 1 -Quiet) -ne $true)
        {
            ProcessError("Could not connect to the DNS-Server under " + $server + "; Script ended at an early stage")
            ExitScript
        }
    }
    catch
    {
        ProcessError("An Error occured while trying to test the connection to the DNS-Server")
    }

    $A = ""
    for ($x = 0; $x -lt $script:zone.Length; $x++)
    {
        $script:zoneTitleSet = $false
        $script:zoneFound = $false

        for ($y = 0; $y -lt $script:recordTypes.Length; $y++)
        {
            if ((Get-DnsZone $zone[$x]).Length -ne 0)
            {
                $recordsOfTypesSet = $false
                try
                {
                    $A = Get-DnsRecord -Server $script:server -ZoneName $script:zone[$x] -RecordType $script:recordTypes[$y] #| Select-String -Pattern '(.[^\s])+?\.test\.local'
                    $A = $A -replace "\s", "`n"
                    $A = $A.Split("`n")

                    if ($script:zoneTitleSet -eq $false)
                    {
                        "ZONE " + $script:zone[$x] + ":" >> $script:inputFile
                        $script:zoneTitleSet = $true
                    }
                    "`t"+" - " + $script:recordTypes[$y] + " Records:" >> $script:inputFile
                    $recordsOfTypesSet = $true
                    $script:zoneFound = $true
                }
                catch
                {
                    ProcessWarning("Could not find " + $script:recordTypes[$y] + " Records in zone " + $script:zone[$x])
                }


                for ($i = 0; $i -le $A.Length; $i++)
                {    
                    if ($A[$i] -match $script:forwardZoneFilter)
                    {
                        "`t" + "`t" + $A[$i] >> $script:inputFile
                    }
                    if ($A[$i] -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                    {
                        "`t" + "`t" + $A[$i] >> $script:inputFile
                    }
                    elseif ($A[$i] -match "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
                    {
                        "`t" + "`t" + $A[$i] >> $script:inputFile
                    }
                    Write-Host "`n"
                }

                if ($recordsOfTypesSet -eq $true)
                {
                    "`t"+" - " + "RECORDS END" >> $script:inputFile
                }

                $A = ""
            }
            else
            {
                ProcessWarning("Could not find zone: " + $zone[$x])
            }
        }
      
        if ($script:zoneFound -eq $true)
        {
            "ZONE END" >> $script:inputFile
        }

    }
    Start-Sleep -Milliseconds 10
}

#reads the input file and creates an empty output file 
function ReadInFileAndCreateOutput
{
   try
   {
        If (Test-Path $script:inputFile)
        {
          $script:currentFile = Get-Content -Path $script:inputFile
        }
        Else
        {
          throw New-Object System.FormatException ("Could not find " + $script:inputFile)
        }
   }
   catch [Exception]
   {
        ProcessError($_.Exception.Message)
        return
   }

   # Create Output File
   if ($sendMail -eq $false)
   {
        $script:outputFile = $script:outputFile.Insert(0, (Get-Date -UFormat "%Y-%m-%d_%H-%M-%S_"))
   }
   $null > $script:outputFile
}

#checks CNAME-Records if they point to non-existing A/AAAA-Records and writes them to the output file
function Check_CNAME_to_A_AAAA
{
    [System.Collections.ArrayList]$arrayCNAMEs = New-Object System.Collections.ArrayList
    [System.Collections.ArrayList]$arrayARecords = New-Object System.Collections.ArrayList

    [bool]$CNAMEsReading = $false
    [bool]$CNAMEsDone | Out-Null
    [bool]$ARecordsReading = $false
    [bool]$AAAARecordsReading = $false
    [bool]$CompareToRecordsDone = $false
    [bool]$zoneLock | Out-Null
    [int]$i = 0
    [int]$ZONE_END_line = 0
    [string]$currentZone

    "*** Listing CNAME-Records which point to non-existing A/AAAA-Records ***" >> $script:outputFile

    while ($true)
    {
        $zoneLock = $false
        $CNAMEsDone = $false
        $CNAMEsReading = $false

        #Read in Records
        while($i -lt $script:currentFile.Count)
        {
            $script:currentFile[$i] = $script:currentFile[$i].Trim()
            if ($script:currentFile[$i] -match "ZONE.+[:]" -and $zoneLock -eq $false)
            {
                $currentZone = $script:currentFile[$i]
                $zoneLock = $true
            }

            if ($script:currentFile[$i] -NotMatch "ZONE END")
            {
                #CNAME Records
                if ($CNAMEsReading -eq $true -and $CNAMEsDone -eq $false)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $CNAMEsReading = $false
                    }
                    else
                    {
                        $arrayCNAMEs.Add($script:currentFile[$i]) | Out-Null
                    }
                }
                if ($script:currentFile[$i] -eq "- CNAME Records:")
                {
                    $CNAMEsReading = $true
                }
            }
            else
            {
                if ($CNAMEsDone -eq $false)
                {
                    $CNAMEsDone = $true
                    $CNAMEsReading = $false
                    $ZONE_END_line = $i
                }
            }

            if ($CompareToRecordsDone -eq $false)
            {
                #A Records
                if ($ARecordsReading -eq $true)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $ARecordsReading = $false
                    }
                    else
                    {
                        $arrayARecords.Add($script:currentFile[$i]) | Out-Null
                    }
                }
                if ($script:currentFile[$i] -eq "- A Records:")
                {
                    $ARecordsReading = $true
                }

                #AAAA Records
                if ($AAAARecordsReading -eq $true)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $AAAARecordsReading = $false
                    }
                    else
                    {
                        $arrayARecords.Add($script:currentFile[$i]) | Out-Null
                    }
                }
                if ($script:currentFile[$i] -eq "- AAAA Records:")
                {
                    $AAAARecordsReading = $true
                }
            }

            $i++
        }

        $CompareToRecordsDone = $true
        $i = $ZONE_END_line + 1

        "`t" + $currentZone >> $script:outputFile

        for ($x = 0; $x -lt $arrayCNAMEs.Count; $x++)
        {
            if ($arrayCNAMEs[$x].EndsWith("."))
            {
                [bool]$match = $false

                for($y = 0; $y -lt $arrayARecords.Count; $y++)
                {
                    if ($arrayCNAMEs[$x].Trim(" ", ".") -eq $arrayARecords[$y].Trim(" ", "."))
                    {
                        $match = $true
                    }
                }

                if ($match -ne $true)
                {
                    "`t`t NO_RECORD - `t No A/AAAA Record for CNAME " + $arrayCNAMEs[$x-1] >> $script:outputFile
                }
            }
            else
            {
                try
                {
                    if (-Not $arrayCNAMEs[$x+1].EndsWith("."))
                    {
                        "`t`t NOT_IN_ZONE - `t CNAME " + $arrayCNAMEs[$x] + " does NOT point to a record in the given zones" >> $script:outputFile
                    }
                }
                catch
                {

                }
            }
        }

        $arrayCNAMEs.Clear() | Out-Null
        #$arrayARecords.Clear() | Out-Null

        if (($ZONE_END_line + 1) -ge $script:currentFile.Count)
        {
            break
        }
        
    }
}

#checks A/AAAA-Records if they point to non-existing PTR-Records and writes them to the output file
function Check_A_AAAA_to_PTR
{
    [System.Collections.ArrayList]$arrayPTRs = New-Object System.Collections.ArrayList
    [System.Collections.ArrayList]$arrayARecords = New-Object System.Collections.ArrayList

    [bool]$PTRsReading = $false
    [bool]$ARecordsDone | Out-Null
    [bool]$ARecordsReading = $false
    [bool]$AAAARecordsReading = $false
    [bool]$CompareToRecordsDone = $false
    [bool]$zoneLock | Out-Null
    [int]$i = 0
    [int]$ZONE_END_line = 0
    [string]$currentZone

    "*** Listing A/AAAA-Records which point to non-existing PTR-Records ***" >> $script:outputFile

    while ($true)
    {
        $zoneLock = $false
        $ARecordsDone = $false
        $PTRsReading = $false
        $ARecordsReading = $false
        $AAAARecordsReading = $false

        #Read in Records
        while($i -lt $script:currentFile.Count)
        {
            $script:currentFile[$i] = $script:currentFile[$i].Trim()
            if ($script:currentFile[$i] -match "ZONE.+[:]" -and $zoneLock -eq $false)
            {
                $currentZone = $script:currentFile[$i]
            }

            if ($script:currentFile[$i] -NotMatch "ZONE END")
            {
                #A Records
                if ($ARecordsReading -eq $true -and $ARecordsDone -eq $false)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $ARecordsReading = $false
                    }
                    else
                    {
                        $arrayARecords.Add($script:currentFile[$i]) | Out-Null
                        $zoneLock = $true
                    }
                }
                if ($script:currentFile[$i] -eq "- A Records:")
                {
                    $ARecordsReading = $true
                }

                #AAAA Records
                if ($AAAARecordsReading -eq $true -and $ARecordsDone -eq $false)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $AAAARecordsReading = $false
                    }
                    else
                    {
                        $arrayARecords.Add($script:currentFile[$i]) | Out-Null
                        $zoneLock = $true
                    }
                }
                if ($script:currentFile[$i] -eq "- AAAA Records:")
                {
                    $AAAARecordsReading = $true
                }
            }
            else
            {        
                if ($ARecordsDone -eq $false)
                {
                    $ARecordsDone = $true
                    $ZONE_END_line = $i
                }
            }

            #PTR Records
            if ($CompareToRecordsDone -eq $false)
            {
                if ($PTRsReading -eq $true)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $PTRsReading = $false
                    }
                    else
                    {
                        $arrayPTRs.Add($script:currentFile[$i]) | Out-Null            
                    }
                }
                if ($script:currentFile[$i] -eq "- PTR Records:")
                {
                    $PTRsReading = $true
                }
            }

            $i++
        }

        $CompareToRecordsDone = $true
        $i = $ZONE_END_line + 1

        "`t" + $currentZone >> $script:outputFile

        for ($x = 0; $x -lt $arrayARecords.Count; $x++)
        {
            if ((-Not ($arrayARecords[$x] -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") -and -Not ($arrayARecords[$x] -match "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")))
            {
                [bool]$match = $false

                for($y = 0; $y -lt $arrayPTRs.Count; $y++)
                {
                    if ($arrayARecords[$x].Trim(" ", ".") -eq $arrayPTRs[$y].Trim(" ", "."))
                    {
                        $match = $true
                    }
                }

                if ($match -ne $true)
                {
                    "`t`t NO_RECORD - `t No PTR Record for A/AAAA Record " + $arrayARecords[$x] >> $script:outputFile
                }
            }
        }

        $arrayARecords.Clear() | Out-Null
        
        if (($ZONE_END_line + 1) -ge $script:currentFile.Count)
        {
            break
        }
    }
}

#checks PTR-Records if they point to non-existing A/AAAA-Records and writes them to the output file
function Check_PTR_to_A_AAAA
{
    [System.Collections.ArrayList]$arrayPTRs = New-Object System.Collections.ArrayList
    [System.Collections.ArrayList]$arrayARecords = New-Object System.Collections.ArrayList

    [bool]$PTRsReading = $false
    [bool]$PTRsDone | Out-Null
    [bool]$ARecordsReading = $false
    [bool]$AAAARecordsReading = $false
    [bool]$CompareToRecordsDone = $false
    [bool]$zoneLock | Out-Null
    [int]$i = 0
    [int]$ZONE_END_line = 0
    [string]$currentZone

    "*** Listing PTR-Records which point to non-existing A/AAAA-Records ***" >> $script:outputFile

    while ($true)
    {
        $zoneLock = $false
        $PTRsDone = $false
        $PTRsReading = $false

        #Read in Records
        while($i -lt $script:currentFile.Count)
        {
            $script:currentFile[$i] = $script:currentFile[$i].Trim()
            if ($script:currentFile[$i] -match "ZONE.+[:]" -and $zoneLock -eq $false)
            {
                $currentZone = $script:currentFile[$i]
            }

            if ($script:currentFile[$i] -NotMatch "ZONE END")
            {
                #PTR Records
                if ($PTRsReading -eq $true -and $PTRsDone -eq $false)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $PTRsReading = $false
                    }
                    else
                    {
                        $arrayPTRs.Add($script:currentFile[$i]) | Out-Null
                        $zoneLock = $true
                    }
                }
                if ($script:currentFile[$i] -eq "- PTR Records:")
                {
                    $PTRsReading = $true
                }
            }
            else
            {        
                if ($PTRsDone -eq $false -and ($arrayPTRs.Count -ge 1))
                {
                    $PTRsDone = $true
                    $ZONE_END_line = $i
                }
            }

            if ($CompareToRecordsDone -eq $false)
            {
                #A Records
                if ($ARecordsReading -eq $true)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $ARecordsReading = $false
                    }
                    else
                    {
                        $arrayARecords.Add($script:currentFile[$i]) | Out-Null
                    }
                }
                if ($script:currentFile[$i] -eq "- A Records:")
                {
                    $ARecordsReading = $true
                }

                #AAAA Records
                if ($AAAARecordsReading -eq $true)
                {
                    if ($script:currentFile[$i] -eq "- RECORDS END")
                    {
                        $AAAARecordsReading = $false
                    }
                    else
                    {
                        $arrayARecords.Add($script:currentFile[$i]) | Out-Null
                    }
                }
                if ($script:currentFile[$i] -eq "- AAAA Records:")
                {
                    $AAAARecordsReading = $true
                }
            }

            $i++
        }

        $CompareToRecordsDone = $true
        $i = $ZONE_END_line + 1

        "`t" + $currentZone >> $script:outputFile

        for ($x = 0; $x -lt $arrayPTRs.Count; $x++)
        {
            if ($arrayPTRs[$x].EndsWith("."))
            {
                [bool]$match = $false

                for($y = 0; $y -lt $arrayARecords.Count; $y++)
                {
                    if ($arrayPTRs[$x].Trim(" ", ".") -eq $arrayARecords[$y].Trim(" ", "."))
                    {
                        $match = $true
                    }
                }

                if ($match -ne $true)
                {
                    "`t`t NO_RECORD - `t No A/AAAA Record for PTR-Record " + $arrayPTRs[$x-1] >> $script:outputFile
                }
            }
            else
            {
                try
                {
                    if (-Not $arrayPTRs[$x+1].EndsWith("."))
                    {
                        "`t`t NOT_IN_ZONE - `t PTR " + $arrayPTRs[$x] + " does NOT point to a record in the given zones" >> $script:outputFile
                    }
                }
                catch
                {

                }
            }
        }

        $arrayPTRs.Clear() | Out-Null
        
        if (($ZONE_END_line + 1) -ge $script:currentFile.Count)
        {
            break
        }
        
    }
}

#sends an email containing the input, output and log file according to settings
function SendMail
{
    $retryCount = 1;
    $success = $false
    while($retryCount -le 3)
    {
        try
        {
            $script:Body = $script:Body + $script:log
			Send-MailMessage -From $script:From -to $script:To -Subject $script:Subject -Body $script:Body -SmtpServer $script:SMTPServer -port $script:SMTPPort -Attachments $script:Attachment_OutputFile, $script:Attachment_LogFile, $script:Attachment_InputFile -Credential $script:Credentials -EA Stop -useSSL
            $success = $true
            break
        }
        catch
        {
            ProcessWarning("Could not send mail at try " + $retryCount.ToString())
        }
        $retryCount++
    }

    if($success -eq $false)
    {
        ProcessError("Could not send mail after " + $retryCount.ToString() + " tries.")
    }
}

#exception handling
function ProcessError ([string]$errMsg)
{
    $script:log = $script:log + "`t" + "ERROR: " + $errMsg + "`r`n"
}

#warning handling
function ProcessWarning ([string]$warnMsg)
{
    $script:log = $script:log + "`t" + "WARNING: " + $warnMsg + "`r`n"
}

#writes log to disk
function CreateLogFile
{
    (GET-Openfile $script:logFile $script:ScriptStartDir | Close-Openfile -ScriptStartDir $script:ScriptStartDir) | Out-Null
    
    try
    {
        $script:oldLogContent = [System.IO.File]::ReadAllText($script:logFile)
    }
    catch
    {
        ProcessWarning("Could not find an existing log file")
    }

    try
    {
        if((Test-Path -Path ($script:logFile)) -ne $true)
        {
            new-item -Path ($script:logFile) –itemtype file | Out-Null
        }

        $file = [System.IO.File]::Open($script:logFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $writer = New-Object System.IO.StreamWriter($file)
        $writer.WriteLine($script:oldLogContent)
        $writer.WriteLine((Get-Date -UFormat "%Y-%m-%d_%H-%M-%S_") + " Started (queryDns: " + $script:queryDns + " | sendMail: " + $script:sendMail + ")")
        $writer.WriteLine($script:log)
        $writer.Close()
        $file.Close()
    }
    catch
    {
        ProcessError($_.Exception.Message)
    }
}

#imports the required modules (searching in the scripts start directory) 'HANDLE.psm1' and 'DNSShell.dll'
function ImportModules
{
    try
    {
        Import-Module -Name ($script:ScriptStartDir + "\DNSShell.dll")
        Import-Module -Name ($script:ScriptStartDir + "\HANDLE.psm1")
    }
    catch
    {
        ProcessError($_.Exception.Message)
        ExitScript
    }
}

#force closes all handles to the input, output and log file
function ForceCloseHandlesOfRequiredFiles
{
    (GET-Openfile $script:inputFile $script:ScriptStartDir | Close-Openfile -ScriptStartDir $script:ScriptStartDir) | Out-Null
    (GET-Openfile $script:outputFile $script:ScriptStartDir | Close-Openfile -ScriptStartDir $script:ScriptStartDir) | Out-Null
    (GET-Openfile $script:logFile $script:ScriptStartDir | Close-Openfile -ScriptStartDir $script:ScriptStartDir) | Out-Null
}

#exit script
function ExitScript
{
    CreateLogFile
    Exit
}

#</End Functions>


#<Logic>

ImportModules
ForceCloseHandlesOfRequiredFiles
if ($script:queryDns -eq $true)
{
	WriteDnsRecordsToFile
}
ReadInFileAndCreateOutput
Check_CNAME_to_A_AAAA
Check_A_AAAA_to_PTR
Check_PTR_to_A_AAAA
if ($script:sendMail -eq $true)
{
    SendMail
}
CreateLogFile
ForceCloseHandlesOfRequiredFiles

#</End Logic>
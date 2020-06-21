Function global:GET-OpenFilePID() 
                { 
                                param 
                                ( 
                                [parameter(ValueFromPipeline=$true, 
                                                Mandatory=$true)] 
                                [String[]]$HandleData 
                                ) 
                                 
                                Process 
                                { 
                                                $OpenFile=New-Object PSObject -Property @{FILENAME='';ProcessPID='';FILEID=''} 
                                                 
                                                $StartPid=($HandleData[0] | SELECT-STRING 'pid:').matches[0].Index 
                                                $OpenFile.Processpid=$HandleData[0].substring($StartPid+5,7).trim() 
                                                 
                                                $StartFileID=($HandleData[0] | SELECT-STRING 'type: File').matches[0].Index 
                                                $OpenFile.fileid=$HandleData[0].substring($StartFileID+10,14).trim() 
                                                 
                                                $OpenFile.Filename=$HandleData[0].substring($StartFileID+26).trim() 
                                                Return $OpenFile 
                                } 
                } 
                 
Function global:GET-Openfile() 
{ 
[Cmdletbinding()] 
param 
                (  
                [parameter(Mandatory=$True, 
                                ValueFromPipeline=$True)] 
                                [String[]]$Filename,
                [parameter(Mandatory=$True)] 
                                [string[]]$ScriptStartDir
                 
                ) 
                 
                Process 
                { 
                If ( ! (TEST-LocalAdmin) ) { Write-Host 'Need to RUN AS ADMINISTRATOR first'; Return 1 } 
                IF ( ! ($Filename) ) { Write-Host 'No Filename or Search Parameter supplied.' } 
                $HANDLEAPP="& " + $ScriptStartDir +"'\handle.exe'"
                $Expression=$HANDLEAPP+' '+$Filename 
                 
                $OPENFILES=(INVOKE-EXPRESSION $Expression) -like '*pid:*' 
                 
                $Results=($OPENFILES | GET-openfilepid) 
 
                Return $results 
                } 
} 
 
Function global:Close-Openfile() 
{ 
[CmdletBinding(SupportsShouldProcess=$true)] 
Param( 
                [parameter(Mandatory=$True, 
                                ValueFromPipelineByPropertyName=$True)] 
                                [string[]]$ProcessPID, 
                [parameter(Mandatory=$True, 
                                ValueFromPipelinebyPropertyName=$True)] 
                                [string[]]$FileID, 
                [parameter(Mandatory=$false, 
                                ValueFromPipelinebyPropertyName=$True)] 
                                [String[]]$Filename,
                [parameter(Mandatory=$True)] 
                                [string[]]$ScriptStartDir
                ) 
                 
                Process 
                { 
        $HANDLEAPP="& " + $ScriptStartDir +"'\handle.exe'"                 
        $Expression=$HANDLEAPP+' -p '+$ProcessPID[0]+' -c '+$FileID[0]+' -y' 
                if ( $PSCmdlet.ShouldProcess($Filename) )  
                                { 
                                INVOKE-EXPRESSION $Expression | OUT-NULL 
                                } 
                } 
} 
 
Function global:TEST-LocalAdmin() 
                { 
                Return ([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] "Administrator") 
                }
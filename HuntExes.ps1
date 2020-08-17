<#
HuntExes - Extract Sysmon Event ID 1 (Process Creation) events from either the local Microsoft-Windows-Sysmon/Operational log, or an archived evtx file, extract MD5, SHA256, and IMPHASH hashes of those Processes from the sysmon log, and query an online service (currently Malware Bazaar https://bazaar.abuse.ch/) to identify malicious processes.
Summary of what HuntExes does:
 - Parse out key data elements from sysmon event 1 (Process Create) - UtcTime, Computer, Hashes, Image
 - From the Hashes, regex to parse out the MD5, SHA256, and IMPHASH separately
 - If CSV files don't exist, create 6 CSV Files: MD5Unknown, MD5Bad, SHA256Unknown, SHA256Bad, IMPHASHUnknown, IMPHASHBad, MD5Allowlist, SHA256Allowlist, IMPHASHAllowlist
 	- Unknown means no results were found from querying bazaar (or future virustotal integration, or whatever other services).  Unknown was picked because "good" would be potentially misleading.
	- Bad means results were found and the hash matches a sample that's reported malicious.
    - AllowList is to manually enter hashes and a comment so that HuntExes ignores them - it won't query, the Bad or Unknown lists, or Malware Bazaar if it parses these hashes.
 - When looping through the events loaded form the Sysmon log...
    - If hash is found in the allow file, skip everythign else and move on to the next hash/event
	- If hash is found in the bad file, write Alert to the console
	- If hash is found in the Unknown file, check to the datestamp of the last lookup and query Malware Bazaar again if it was more than 7 days ago.  Update the lookup date if the file is still Unknown, or move the hash's entry to the Bad file if there's a hit.
 - If the current hash isn't found in the local files, query Malware Bazaar.
	- If bazaar returns 'no_results', write the Hash to the relevant "Unknown" file.
	- If bazaar returns 'ok', write the hash to the bad file and Alert.
Requirements:
Logs must be from Sysmon version 10 or later.  Version 10 added a new element, OriginalFileName, to the Process Create events.  HuntExes can't currently parse logs that don't contain it.
The system running HuntExes must have Sysmon version 10 installed, otherwise get-winevent won't retrieve any details from the events.
Your Sysmon Config should have have md5, sha256, and IMPHASH algorithms enabled.  This should be done at the top of your config using the following line:
<HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms> 
Testing has shown the parsing to work if some/all of those aren't available (the missing hash(es) will be skipped) without error.  But the focus during testing has been on sysmon logs with all of them enabled.
Note:
Testing has shown that an archived .evtx file is changed the first time it is read using get-winevent (which is how HuntExes reads the events).  The file's hash and LastWriteTime change, but the event data does not.  Subsequent reads do not have the same effect.  This is possibly due to Microsoft flipping a bit in the file to indicate it had been read, but I have not confirmed.
#>


#required for Queries to Malware Bazaar to work
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12



Function Banner {
	write-host "                                HHHHHHHHH     HHHHHHHHH                                     tttt      "
    Start-Sleep -m 10
	write-host "                                H:::::::H     H:::::::H                                  ttt:::t      "
    Start-Sleep -m 10
	write-host "                                H:::::::H     H:::::::H                                  t:::::t      "
    Start-Sleep -m 10
	write-host "                                HH::::::H     H::::::HH                                  t:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H                                    t:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H                                    t:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H                                    t:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H                                    t:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::HHHHHHH:::::H                               tttttt:::::tttttt "
    Start-Sleep -m 10
	write-host "                       __=========H=================H====================╗          t:::::::::::::::t "
    Start-Sleep -m 10
	write-host '.====----....__  __,-""  [      ]=H╔╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╗H====================╝          t:::::::::::::::t '
    Start-Sleep -m 10
    write-host '|::::::::::::::"":::\_____________)╚╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╝H                               tttttt:::::tttttt '
    Start-Sleep -m 10
	write-host '|:::::::::::::::::::,-"(( ]       H:::::HHHHHHH:::::H  uuuuuu    uuuuuunnnn  nnnnnnnn    t:::::t      '
    Start-Sleep -m 10
	write-host "|::::___....--,_::,'    ¯¯        H:::::H     H:::::H  u::::u    u::::un:::nn::::::::nn  t:::::t      "
    Start-Sleep -m 10
	write-host " ''''           \'                H:::::H     H:::::H  u::::u    u::::un::::::::::::::nn t:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H  u::::u    u::::unn:::::::::::::::nt:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H  u::::u    u::::u  n:::::nnnn:::::nt:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H  u::::u    u::::u  n::::n    n::::nt:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H  u::::u    u::::u  n::::n    n::::nt:::::t      "
    Start-Sleep -m 10
	write-host "                                  H:::::H     H:::::H  u:::::uuuu:::::u  n::::n    n::::nt:::::t      "
    Start-Sleep -m 10
	write-host "                                HH::::::H     H::::::HHu:::::::::::::::uun::::n    n::::nt::::::ttt   "
    Start-Sleep -m 10
	write-host "                                H:::::::H     H:::::::H u:::::::::::::::un::::n    n::::ntt:::::::t   "
    Start-Sleep -m 10
	write-host "                                H:::::::H     H:::::::H  uu::::::::uu:::un::::n    n::::n  tt:::::t   "
    Start-Sleep -m 10
	write-host "                                HHHHHHHHH     HHHHHHHHH    uuuuuuuu  uuuunnnnnn    nnnnnn    tttttt   "
    Start-Sleep -m 10
	write-host "                                                                                                      "
    Start-Sleep -m 10
	write-host "              EEEEEEEEEEEEEEEEEEEEEE                                   _______                        "
    Start-Sleep -m 10
	write-host "              E::::::::::::::::::::E                                  |v 1.0.1___                     "
    Start-Sleep -m 10
	write-host "              E::::::::::::::::::::E                                  |@EdwardsCP|                    "
    Start-Sleep -m 10
	write-host "              E::::::::::::::::::::E                                  ¯¯¯¯¯¯¯¯¯¯¯¯                    "
    Start-Sleep -m 10
	write-host "              EE:::::EEEEEEEEE:::::E                                                                  "
    Start-Sleep -m 10
	write-host "               E:::::E       EEEEEExxxxxxx      xxxxxxx eeeeeeeeeeee        ssssssssss                "
    Start-Sleep -m 10
	write-host "               E:::::E              x:::::x    x:::::xee::::::::::::ee    ss::::::::::s               "
    Start-Sleep -m 10
	write-host "               E::::::EEEEEEEEEE     x:::::x  x:::::xe::::::eeeee:::::eess:::::::::::::s              "
    Start-Sleep -m 10
	write-host "               E:::::::::::::::E      x:::::xx:::::xe::::::e     e:::::es::::::ssss:::::s             "
    Start-Sleep -m 10
	write-host "               E:::::::::::::::E       x::::::::::x e:::::::eeeee::::::e s:::::s  ssssss              "
    Start-Sleep -m 10
	write-host "               E::::::EEEEEEEEEE        x::::::::x  e:::::::::::::::::e    s::::::s                   "
    Start-Sleep -m 10
	write-host "               E:::::E                  x::::::::x  e::::::eeeeeeeeeee        s::::::s                "
    Start-Sleep -m 10
	write-host "               E:::::E        EEEEEE    x:::::::::x e:::::::e            ssssss   s:::::s              "
    Start-Sleep -m 10
	write-host "              EE::::::EEEEEEEE:::::E   x:::::xx:::::xe::::::::e          s:::::ssss::::::s            "
    Start-Sleep -m 10
	write-host "              E::::::::::::::::::::E  x:::::x  x:::::xe::::::::eeeeeeee  s::::::::::::::s             "
    Start-Sleep -m 10
	write-host "              E::::::::::::::::::::E x:::::x    x:::::xee:::::::::::::e   s:::::::::::ss              "
    Start-Sleep -m 10
	write-host "              EEEEEEEEEEEEEEEEEEEEEExxxxxxx      xxxxxxx eeeeeeeeeeeeee    sssssssssss                "
    Start-Sleep -m 10



    FileCheck
}



# Check for CSV Files, create and add header if they don't exist.  Then Run the ImportHashCSVs function to load the CSVs to DataTables
<# Note:
For each hash that is entered into one of the CSVs...
The Image, Computer, and EventUtcTime will always reflect the event details from the first time that hash was discovered by HuntExes in the environment where it is running.  This doesn't necessarily mean it's the first instance of it appearing in the environment.
The HuntExesDatestamp will always be the date when HuntExes was run and that hash was first discovered.
The LastLookupDate (only in the Unknown CSVs) will reflect the last date HuntExes queried MalwareBazaar to look for that Hash.  By default, HuntExes won't query the hash again if this date is less than or equal to 7 days ago.
#>
Function FileCheck {
	$script:CurDir = Get-Location
	$script:CurDirPath = $script:CurDir.Path
	$script:HashesDir = $script:CurDirPath + '\Hashes'
	$script:MD5UnknownCSV = 'MD5Unknown.csv'
	$script:MD5UnknownFile = "$script:HashesDir\$script:MD5UnknownCSV"
	$script:MD5BadCSV = 'MD5Bad.csv'
	$script:MD5BadFile = "$script:HashesDir\$script:MD5BadCSV"
    $script:MD5AllowListCSV = 'MD5AllowList.csv'
	$script:MD5AllowListFile = "$script:HashesDir\$script:MD5AllowListCSV"
	$script:SHA256UnknownCSV = 'SHA256Unknown.csv'
	$script:SHA256UnknownFile = "$script:HashesDir\$script:SHA256UnknownCSV"
	$script:SHA256BadCSV = 'SHA256Bad.csv'
	$script:SHA256BadFile = "$script:HashesDir\$script:SHA256BadCSV"
    $script:SHA256AllowListCSV = 'SHA256AllowList.csv'
	$script:SHA256AllowListFile = "$script:HashesDir\$script:SHA256AllowListCSV"
	$script:IMPHASHUnknownCSV = 'IMPHASHUnknown.csv'
	$script:IMPHASHUnknownFile = "$script:HashesDir\$script:IMPHASHUnknownCSV"
	$script:IMPHASHBadCSV = 'IMPHASHBad.csv'
	$script:IMPHASHBadFile = "$script:HashesDir\$script:IMPHASHBadCSV"
    $script:IMPHASHAllowListCSV = 'IMPHASHAllowList.csv'
	$script:IMPHASHAllowListFile = "$script:HashesDir\$script:IMPHASHAllowListCSV"

	If (!(Test-Path $script:HashesDir)) {
		New-Item -Type "directory" -Path "$script:HashesDir"
		}
	If (!(Test-Path $script:MD5UnknownFile)) {
		Set-Content $script:MD5UnknownFile -Value '"MD5","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate"'
		}
	If (!(Test-Path $script:MD5BadFile)) {
		Set-Content $script:MD5BadFile -Value '"MD5","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate"'
		}
    If (!(Test-Path $script:MD5AllowListFile)) {
		Set-Content $script:MD5AllowListFile -Value '"MD5","Comment"'
		}
	If (!(Test-Path $script:SHA256UnknownFile)) {
		Set-Content $script:SHA256UnknownFile -Value '"SHA256","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate"'
		}
	If (!(Test-Path $script:SHA256BadFile)) {
		Set-Content $script:SHA256BadFile -Value '"SHA256","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate"'
		}
    If (!(Test-Path $script:SHA256AllowListFile)) {
		Set-Content $script:SHA256AllowListFile -Value '"SHA256","Comment"'
		}
	If (!(Test-Path $script:IMPHASHUnknownFile)) {
		Set-Content $script:IMPHASHUnknownFile -Value '"IMPHASH","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate"'
		}
	If (!(Test-Path $script:IMPHASHBadFile)) {
		Set-Content $script:IMPHASHBadFile -Value '"IMPHASH","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate"'
		}
    If (!(Test-Path $script:IMPHASHAllowListFile)) {
		Set-Content $script:IMPHASHAllowListFile -Value '"IMPHASH","Comment"'
		}
    ImportHashCSVs
}



Function ImportHashCSVs{
    #Import CSVs to Datatables so they're in memory
    #First Import CSV to an object
    $script:MD5BadImported = Import-Csv $script:MD5BadFile
    $script:MD5UnknownImported = Import-Csv $script:MD5UnknownFile
    $script:MD5AllowListImported = Import-Csv $script:MD5AllowListFile
    $script:SHA256BadImported = Import-Csv $script:SHA256BadFile
    $script:SHA256UnknownImported = Import-Csv $script:SHA256UnknownFile
    $script:SHA256AllowListImported = Import-Csv $script:SHA256AllowListFile
    $script:IMPHASHBadImported = Import-Csv $script:IMPHASHBadFile
    $script:IMPHASHUnknownImported = Import-Csv $script:IMPHASHUnknownFile
    $script:IMPHASHAllowListImported = Import-Csv $script:IMPHASHAllowListFile

    #Second Create tables
    $script:dtMD5Bad = New-Object System.Data.DataTable("MD5Bad")
    $script:dtMD5Unknown = New-Object System.Data.DataTable("MD5Unknown")
    $script:dtMD5AllowList = New-Object System.Data.DataTable("MD5AllowList")
    $script:dtSHA256Bad = New-Object System.Data.DataTable("SHA256Bad")
    $script:dtSHA256Unknown = New-Object System.Data.DataTable("SHA256Unknown")
    $script:dtSHA256AllowList = New-Object System.Data.DataTable("SHA256AllowList")
    $script:dtIMPHASHBad = New-Object System.Data.DataTable("IMPHASHBad")
    $script:dtIMPHASHUnknown = New-Object System.Data.DataTable("IMPHASHUnknown")
    $script:dtIMPHASHAllowList = New-Object System.Data.DataTable("IMPHASHAllowList")

    #Third create Schema (columns)
    #Descriptions - Hash, First Seen Image, First Seen Computer, First Seen EventUtcTime, First Seen HuntexesDatestamp, Most Recent LookupDate
    $script:dtMD5Columns = @("MD5","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate")
    $script:dtSHA256Columns = @("SHA256","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate")
    $script:dtIMPHASHColumns = @("IMPHASH","Image","Computer","EventUtcTime","HuntExesDatestamp","LastLookupDate")
    $script:dtMD5AllowListColumns = @("MD5","Comment")
    $script:dtSHA256AllowListColumns = @("SHA256","Comment")
    $script:dtIMPHASHAllowListColumns = @("IMPHASH","Comment")

    foreach ($script:dtMD5Column in $script:dtMD5Columns){
        $script:dtMD5Bad.Columns.Add($script:dtMD5Column) | Out-Null
    }

    foreach ($script:dtMD5Column in $script:dtMD5Columns){
        $script:dtMD5Unknown.Columns.Add($script:dtMD5Column) | Out-Null
    }

    foreach ($Script:dtMD5AllowListColumn in $Script:dtMD5AllowListColumns){
        $script:dtMD5AllowList.Columns.Add($script:dtMD5AllowListColumn) | Out-Null
    }

    foreach ($script:dtSHA256Column in $script:dtSHA256Columns){
        $script:dtSHA256Bad.Columns.Add($script:dtSHA256Column) | Out-Null
    }

    foreach ($script:dtSHA256Column in $script:dtSHA256Columns){
        $script:dtSHA256Unknown.Columns.Add($script:dtSHA256Column) | Out-Null
    }
    foreach ($Script:dtSHA256AllowListColumn in $Script:dtSHA256AllowListColumns){
        $script:dtSHA256AllowList.Columns.Add($script:dtSHA256AllowListColumn) | Out-Null
    }

    foreach ($script:dtIMPHASHColumn in $script:dtIMPHASHColumns){
        $script:dtIMPHASHBad.Columns.Add($script:dtIMPHASHColumn) | Out-Null
    }

    foreach ($script:dtIMPHASHColumn in $script:dtIMPHASHColumns){
        $script:dtIMPHASHUnknown.Columns.Add($script:dtIMPHASHColumn) | Out-Null
    }
    foreach ($Script:dtIMPHASHAllowListColumn in $Script:dtIMPHASHAllowListColumns){
        $script:dtIMPHASHAllowList.Columns.Add($script:dtIMPHASHAllowListColumn) | Out-Null
    }


    #Forth put the values from the new objects created from the CSVs into the tables
    foreach ($script:line in $script:MD5BadImported){
        $script:row = $script:dtMD5Bad.NewRow()
        foreach ($script:dtMD5Column in $script:dtMD5Columns){
            $script:row[$script:dtMD5Column] = $script:line.$script:dtMD5Column
        }
        $script:dtMD5Bad.Rows.Add($script:row) | Out-Null
    }

    foreach ($script:line in $script:MD5UnknownImported){
        $script:row = $script:dtMD5Unknown.NewRow()
        foreach ($script:dtMD5Column in $script:dtMD5Columns){
            $script:row[$script:dtMD5Column] = $script:line.$script:dtMD5Column
        }
        $script:dtMD5Unknown.Rows.Add($script:row) | Out-Null
    }

    foreach ($script:line in $script:MD5AllowListImported){
        $script:row = $script:dtMD5AllowList.NewRow()
        foreach ($script:dtMD5AllowListColumn in $script:dtMD5AllowListColumns){
            $script:row[$script:dtMD5AllowListColumn] = $script:line.$script:dtMD5AllowListColumn
        }
        $script:dtMD5AllowList.Rows.Add($script:row) | Out-Null
    }


    foreach ($script:line in $script:SHA256BadImported){
        $script:row = $script:dtSHA256Bad.NewRow()
        foreach ($script:dtSHA256Column in $script:dtSHA256Columns){
            $script:row[$script:dtSHA256Column] = $script:line.$script:dtSHA256Column
        }
        $script:dtSHA256Bad.Rows.Add($script:row) | Out-Null
    }

    foreach ($script:line in $script:SHA256UnknownImported){
        $script:row = $script:dtSHA256Unknown.NewRow()
        foreach ($script:dtSHA256Column in $script:dtSHA256Columns){
            $script:row[$script:dtSHA256Column] = $script:line.$script:dtSHA256Column
        }
        $script:dtSHA256Unknown.Rows.Add($script:row) | Out-Null
    }

    foreach ($script:line in $script:SHA256AllowListImported){
        $script:row = $script:dtSHA256AllowList.NewRow()
        foreach ($script:dtSHA256AllowListColumn in $script:dtSHA256AllowListColumns){
            $script:row[$script:dtSHA256AllowListColumn] = $script:line.$script:dtSHA256AllowListColumn
        }
        $script:dtSHA256AllowList.Rows.Add($script:row) | Out-Null
    }

    foreach ($script:line in $script:IMPHASHBadImported){
        $script:row = $script:dtIMPHASHBad.NewRow()
        foreach ($script:dtIMPHASHColumn in $script:dtIMPHASHColumns){
            $script:row[$script:dtIMPHASHColumn] = $script:line.$script:dtIMPHASHColumn
        }
        $script:dtIMPHASHBad.Rows.Add($script:row) | Out-Null
    }

    foreach ($script:line in $script:IMPHASHUnknownImported){
        $script:row = $script:dtIMPHASHUnknown.NewRow()
        foreach ($script:dtIMPHASHColumn in $script:dtIMPHASHColumns){
            $script:row[$script:dtIMPHASHColumn] = $script:line.$script:dtIMPHASHColumn
        }
        $script:dtIMPHASHUnknown.Rows.Add($script:row) | Out-Null
    }
    foreach ($script:line in $script:IMPHASHAllowListImported){
        $script:row = $script:dtIMPHASHAllowList.NewRow()
        foreach ($script:dtIMPHASHAllowListColumn in $script:dtIMPHASHAllowListColumns){
            $script:row[$script:dtIMPHASHAllowListColumn] = $script:line.$script:dtIMPHASHAllowListColumn
        }
        $script:dtIMPHASHAllowList.Rows.Add($script:row) | Out-Null
    }
    write-host " "
    Write-Host "========================="
    Write-Host "Total AllowListed MD5 loaded into memory from" $Script:MD5AllowListFile ":" $script:dtMD5AllowList.Rows.Count
    Write-Host "Total AllowListed SHA256 loaded into memory from" $script:SHA256AllowListFile ":" $script:dtSHA256AllowList.Rows.Count
    Write-Host "Total AllowListed IMPHASH loaded into memory from" $script:IMPHASHAllowListFile ":" $script:dtIMPHASHAllowList.Rows.Count
    Write-Host "Total BadListed MD5 loaded into memory from" $script:MD5BadFile ":" $script:dtMD5Bad.Rows.Count
    Write-Host "Total BadListed SHA256 loaded into memory from" $script:SHA256BadFile ":" $script:dtSHA256Bad.Rows.Count
    Write-Host "Total BadListed IMPHASH loaded into memory from" $script:IMPHASHBadFile ":" $script:dtIMPHASHBad.Rows.Count
    Write-Host "Total UnknownListed MD5 loaded into memory from" $script:MD5UnknownFile ":" $script:dtMD5Unknown.Rows.Count
    Write-Host "Total UnknownListed SHA256loaded into memory from" $script:SHA256UnknownFile ":" $script:dtSHA256Unknown.Rows.Count
    Write-Host "Total UnknownListed IMPHASH loaded into memory from" $script:IMPHASHUnknownFile ":" $script:dtIMPHASHUnknown.Rows.Count
    Write-Host "========================="
    write-host " "
    #After the tables are loaded with data from the CSVs, go to the menu so the user can select what they want to process
    MenuLogOrFile
}



Function MenuLogOrFileOptions {
    Write-Host "========================="
    Write-Host "Do you want to process the Sysmon Operational log from an archived EVTX File, or the live log on the local computer?" -ForegroundColor Yellow
    Write-Host "[1] Archived EVTX File"
    Write-Host "[2] Live Log"
    Write-Host "[Q] Quit (Saves new Unknown and Bad hash entries to CSVs)"
    Write-Host "========================="
    }


Function MenuLogOrFile {
    Do {
        MenuLogOrFileOptions
        $Script:MenuLogOrFileChoice = Read-Host -Prompt 'Please enter a selection from the menu (1, 2, or Q) and press Enter'
        switch ($Script:MenuLogOrFileChoice){
            '1'{
                $script:EVTXLoad = $true
                ProcessEVTXFile
            }
            '2'{
                $script:events = Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational'; id=1} #-MaxEvents 100
                $script:EVTXLoad = $false
                write-host "Total Number of Events Loaded:" $script:events.count
                ProcessEvents
            }
            'Q'{
            $script:dtMD5Bad | Export-Csv $Script:MD5BadFile -NoTypeInformation
	    write-host "File Updated: " $Script:MD5BadFile
            $script:dtSHA256Bad | Export-Csv $Script:SHA256BadFile -NoTypeInformation
	    write-host "File Updated: " $Script:SHA256BadFile
            $script:dtIMPHASHBad | Export-Csv $script:IMPHASHBadFile -NoTypeInformation
	    write-host "File Updated: " $script:IMPHASHBadFile

            $script:dtMD5Unknown | Export-Csv $Script:MD5UnknownFile -NoTypeInformation
	    write-host "File Updated: " $Script:MD5UnknownFile
            $script:dtSHA256Unknown | Export-Csv $Script:SHA256UnknownFile -NoTypeInformation
	    write-host "File Updated: " $Script:SHA256UnknownFile
            $script:dtIMPHASHUnknown | Export-Csv $script:IMPHASHUnknownFile -NoTypeInformation
	    write-host "File Updated: " $script:IMPHASHUnknownFile
            Exit
            }
        }
    }
    Until ($Script:MenuLogOrFileChoice -eq 'q') 
}



#Function to select a FileName to Open using a dialog box
Function Get-FileName($initialDirectory){   
	[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
	$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	$OpenFileDialog.initialDirectory = $initialDirectory
	$OpenFileDialog.filter = "Event Log (*.EVTX)| *.EVTX"
	$OpenFileDialog.ShowDialog() | Out-Null
	$OpenFileDialog.filename
}

Function ProcessEVTXFile{
    $Script:EVTXLog = Get-Filename
    $script:events = Get-WinEvent -Path $Script:EVTXLog -FilterXPath *[System[EventID=1]] #-MaxEvents 500
    write-host "Total Number of Events Loaded:" $script:events.count
    ProcessEvents
}





#Function to loop though each sysmon event, extract relevant data, check against AllowList, then Bad, then Unknown, then DateCheck (if found in unknown), then MalwareBazaar
Function ProcessEvents{
    $I = $script:events.count
    $NoMD5Counter = 0
    $NoSHA256Counter = 0
    $NoIMPHASHCounter = 0
    $AllowedMD5Counter = 0
    $AllowedSHA256Counter = 0
    $AllowedIMPHASHCounter = 0
    $BadMD5Counter = 0
    $BadSHA256Counter = 0
    $BadIMPHASHCounter = 0
    $UnknownMD5NewCounter = 0
    $UnknownSHA256NewCounter = 0
    $UnknownIMPHASHNewCounter = 0
    $UnknownMD5OldCounter = 0
    $UnknownSHA256OldCounter = 0
    $UnknownIMPHASHOldCounter = 0
    $script:BazaarCounter = 0
    $PassCount = 0			  
	foreach ($script:event in $script:events) {
        #For ever 50th event processed, display a countdown of how many loaded events are left.  Comment out both of these If statements if it's too noisy.
        If ($PassCount -eq 51){
            $PassCount = 1
        }
        If ($PassCount -eq 50){
            Write-Host "Remaining Events to process: " $I
        }
        
        #prep some variables to be null or false before each pass
        $MD5nextEvent = $false
        $SHA256nextEvent = $false
        $IMPHASHnextEvent = $false
        $Script:MD5FirstSeen = $false
        $Script:SHA256FirstSeen = $false
        $Script:IMPHASHFirstSeen = $false
        $script:BazaarMD5 = $false
        $script:BazaarSHA256 = $false
        $script:BazaarIMPHASH  = $false
        Clear-Variable -Name MD5Allowed -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name SHA256Allowed -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name IMPHASHAllowed -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name MD5Bad -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name SHA256Bad -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name IMPHASHBad -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name MD5Unknown -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name SHA256Unknown -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name IMPHASHUnknown -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name HashfileEntryDate -Scope Script -ErrorAction SilentlyContinue
	    $script:eventXML = [xml]$script:Event.ToXml()
	    $script:Computer = $script:eventXML.Event.System.Computer
	    $script:UtcTime = $script:eventXML.Event.EventData.Data[1].'#text'
	    $script:Image =  $script:eventXML.Event.EventData.Data[4].'#text'
	    $script:Hashes = $script:eventXML.Event.EventData.Data[17].'#text'

	    #note: $matches below can't have the script: prefix.
        $script:MD5Parse = $script:Hashes -match '^.*MD5=([A-F0-9]{32}).*$'
        #if MD5 is found, load it to the variable to continue processing
        if ($script:MD5Parse){
            $script:MD5 = $Matches[1]
        }
        #if MD5 isn't found in this event, set MD5nextEvent to true. This should help handle environments with sysmon configs that don't generate MD5
        if (!($script:MD5Parse)){
            $MD5nextEvent = $true
            $NoMD5Counter++
            #write-host "No MD5 parsed from this event" $script:UtcTime $script:Computer $script:Image
        }

        $script:SHA256Parse = $script:Hashes -match '^.*SHA256=([A-F0-9]{64}).*$'
        #if SHA256 is found, load it to the variable to continue processing
        if ($script:SHA256Parse){
            $script:SHA256 = $Matches[1]
        }
        #if SHA256 isn't found in this event, set SHA256nextEvent to true. This should help handle environments with sysmon configs that don't generate SHA256
        if (!($script:SHA256Parse)){
            $SHA256nextEvent = $true
            $NoSHA256Counter++
            #write-host "No SHA256 parsed from this event" $script:UtcTime $script:Computer $script:Image
        }

        $Script:IMPHASHParse = $script:Hashes -match '^.*IMPHASH=([A-F0-9]{32}).*$'
         #if IMPHASH is found, load it to the variable to continue processing
        if ($script:IMPHASHParse){
            $script:IMPHASH = $Matches[1]
        }
        #if IMPHASH isn't found in this event, set IMPHASHnextEvent to true. This should help handle environments with sysmon configs that don't generate IMPHASH
        if (!($script:IMPHASHParse)){
            $IMPHASHnextEvent = $true
            $NoIMPHASHCounter++
            #write-host "No IMPHASH parsed from this event" $script:UtcTime $script:Computer $script:Image
        }

        #If NextEvent isn't True, do the AllowList check.  if a hash is found in an AllowList, set NextEvent to true to move on to the next event.
        if (!($MD5NextEvent)) {
            $Script:MD5Allowed = ($script:dtMD5AllowList.Rows | Where-Object {($_.MD5 -eq $script:MD5)})
            if ($Script:MD5Allowed){
                write-host "$script:MD5 MD5 allowed true"
                $AllowedMD5Counter++
                $MD5nextEvent = $true
            }
        }
        if (!($SHA256nextEvent)){
            $Script:SHA256Allowed = ($script:dtSHA256AllowList.Rows | Where-Object {($_.SHA256 -eq $script:SHA256)})
            if ($Script:SHA256Allowed){
                write-host "$script:SHA256 SHA256 allowed true"
                $AllowedSHA256Counter++
                $SHA256nextEvent = $true
            }
        }
        if (!($IMPHASHnextEvent)){
            $Script:IMPHASHAllowed = ($script:dtIMPHASHAllowList.Rows | Where-Object {($_.IMPHASH -eq $script:IMPHASH)})
            if ($Script:IMPHASHAllowed){
                write-host "$script:IMPHASH IMPHASH allowed true"
                $AllowedIMPHASHCounter++
                $IMPHASHnextEvent = $true
            }
        }
        #After the Allowed File check, if NextEvent isn't True, do the BadFile Check.  if a hash is found in a BadFile, alert and set NextEvent to True to move on to the next event.
        if (!($MD5NextEvent)) {
            $Script:MD5Bad = ($script:dtMD5Bad.Rows | Where-Object {($_.MD5 -eq $script:MD5)})
            if ($Script:MD5Bad){
                $Script:HashfileEntryDate = $Script:MD5Bad.HuntExesDatestamp
		        Write-Host "========================"
                write-host "MD5 "$script:MD5" was found in Known Bad list with original HuntExes Datestamp "$script:HashFileEntryDate -ForegroundColor Yellow
		        Write-Host "Current Sysmon Event Computer" $script:Computer
		        Write-Host "Current Sysmon Event Image" $script:Image
		        Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		        Write-Host "========================"
                $BadMD5Counter++
                $MD5NextEvent = $true
            }
        }

        if (!($SHA256NextEvent)) {
            $Script:SHA256Bad = ($script:dtSHA256Bad.Rows | Where-Object {($_.SHA256 -eq $script:SHA256)})
            if ($Script:SHA256Bad){
                $Script:HashfileEntryDate = $Script:SHA256Bad.HuntExesDatestamp
                Write-Host "========================"
                write-host "SHA256 "$script:SHA256" was found in Known Bad list with original HuntExes Datestamp "$script:HashFileEntryDate  -ForegroundColor Yellow
		        Write-Host "Current Sysmon Event Computer" $script:Computer
		        Write-Host "Current Sysmon Event Image" $script:Image
		        Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		        Write-Host "========================"
                $BadSHA256Counter++
                $SHA256NextEvent = $true
            }
        }
        if (!($IMPHASHNextEvent)) {
            $Script:IMPHASHBad = ($script:dtIMPHASHBad.Rows | Where-Object {($_.IMPHASH -eq $script:IMPHASH)})
            if ($Script:IMPHASHBad){
                $Script:HashfileEntryDate = $Script:IMPHASHBad.HuntExesDatestamp
                Write-Host "========================"
                write-host "IMPHASH "$script:IMPHASH" was found in Known Bad list with original HuntExes Datestamp "$script:HashFileEntryDate  -ForegroundColor Yellow
		        Write-Host "Current Sysmon Event Computer" $script:Computer
		        Write-Host "Current Sysmon Event Image" $script:Image
		        Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		        Write-Host "========================"
                $BadIMPHASHCounter++
                $IMPHASHNextEvent = $true
            }
        }



        #After the Bad File check, if NextEvent isn't True, do the UnknownFile Check.  if a hash is found in an UnknownFile, run datecheck.  If not found, query bazaar
        if (!($MD5NextEvent)) {
            $Script:MD5Unknown = ($script:dtMD5Unknown.Rows | Where-Object {($_.MD5 -eq $script:MD5)})
                
            #set BazaarLookup MD5 so the switch in CheckBazaar does MD5 processing if we get to it
            $script:BazaarLookup = "MD5"

            #if Hash is found in Unknown Datatable, do the DateCheck
            if ($Script:MD5Unknown){
                $Script:LastLookupDate = $Script:MD5Unknown.LastLookupDate
                $Script:MD5FirstSeen = $false
                $UnknownMD5OldCounter++
                datecheck
            }
            #if Hash is not found in Unknown Datatable, set FirstSeen to true, then CheckBazaar
            if (!($script:MD5Unknown)){
                $Script:MD5FirstSeen = $true
                $UnknownMD5NewCounter++
                CheckBazaar
            }

                        }
        if (!($SHA256NextEvent)) {
            $Script:SHA256Unknown = ($script:dtSHA256Unknown.Rows | Where-Object {($_.SHA256 -eq $script:SHA256)})

            #set BazaarLookup SHA256 so the switch in CheckBazaar does SHA256 processing if we get to it
            $script:BazaarLookup = "SHA256"

            #if Hash is found in Unknown Datatable, do the DateCheck
            if ($Script:SHA256Unknown){
                $Script:LastLookupDate = $Script:SHA256Unknown.LastLookupDate
                $Script:SHA256FirstSeen = $false
                $UnknownSHA256OldCounter++
                datecheck
            }

            #if Hash is not found in Unknown Datatable, set FirstSeen to true, then CheckBazaar
            if (!($script:SHA256Unknown)){
                $Script:SHA256FirstSeen = $true
                $UnknownSHA256NewCounter++
                CheckBazaar
            }

                
        }
        if (!($IMPHASHNextEvent)) {
            $Script:IMPHASHUnknown = ($script:dtIMPHASHUnknown.Rows | Where-Object {($_.IMPHASH -eq $script:IMPHASH)})

            #set BazaarLookup IMPHASH so the switch in CheckBazaar does IMPHASH processing if we get to it
            $script:BazaarLookup = "IMPHASH"

            #if Hash is found in Unknown Datatable, do the DateCheck
            if ($Script:IMPHASHUnknown){
                $Script:LastLookupDate = $Script:IMPHASHUnknown.LastLookupDate
                $Script:IMPHASHFirstSeen = $false
                $UnknownIMPHASHOldCounter++
                datecheck
            }

            #if Hash is not found in Unknown Datatable, set FirstSeen to true, then CheckBazaar
            if (!($script:IMPHASHUnknown)){
                $Script:IMPHASHFirstSeen = $true
                $UnknownIMPHASHNewCounter++
                CheckBazaar
            }

        }
    $PassCount++
    $I--
    }#end of foreach loop
    write-host "========================="
    if ($script:EVTXLoad){
	    write-host "summary from file: "$Script:EVTXLog -ForegroundColor Yellow
    }
    if (!($script:EVTXLoad)){
        write-host "Summary from local live Microsoft-Windows-Sysmon/Operational Log"  -ForegroundColor Yellow
    }
    write-host "The hit counts below are totals, not unique hits per hash."  -ForegroundColor Yellow
    write-host " "
    write-host "Total Events with No MD5 parsed: " $NoMD5Counter
    write-host "Total Events with No SHA256 parsed: " $NoSHA256Counter
    write-host "Total Events with No IMPHASH parsed: " $NoIMPHASHCounter
    write-host " "
    write-host "Total Allowlisted MD5 found: " $AllowedMD5Counter
    write-host "Total Allowlisted SHA256 found: "$AllowedSHA256Counter
    write-host "Total Allowlisted IMPHASH found: "$AllowedIMPHASHCounter
    write-host " "
    write-host "Total Badlisted MD5 found: "$BadMD5Counter
    write-host "Total Badlisted SHA256 found: "$BadSHA256Counter
    write-host "Total Badlisted IMPHASH found: "$BadIMPHASHCounter
    write-host " "
    write-host "Total New Unknown MD5 found: "$UnknownMD5NewCounter
    write-host "Total New Unknown SHA256 found: "$UnknownSHA256NewCounter
    write-host "Total New Unknown IMPHASH found: "$UnknownIMPHASHNewCounter
    write-host " "
    write-host "Total Existing Unknownlisted MD5 found: "$UnknownMD5OldCounter
    write-host "Total Existing Unknownlisted SHA256 found: "$UnknownSHA256OldCounter
    write-host "Total Existing Unknownlisted IMPHASH found: "$UnknownIMPHASHOldCounter
    write-host " "
    write-host "Total Queries sent to Malware Bazaar: "$script:BazaarCounter
    write-host "========================="
}#end of ProcessEvents Function

#DateCheck Function - test to see if the LastLookupDate for an Unknown Hash entry is less than or equal to 7 days old.  Query Bazaar again if it is older.
Function DateCheck {
    $script:TodayDatestamp = (get-date).ToString("yyyy-M-dd")
	$script:SevenDaysAgo = (get-date).AddDays(-7)
	$script:SevenDaysAgoStamp = $script:SevenDaysAgo.ToString("yyyy-M-dd")
	$script:LastLookupDatestamp = (Get-Date -date $Script:LastLookupDate).toString("yyyy-M-dd")
    #If Entry in Unknown table 7 or more days old.  Look it up again.
	If ($script:LastLookupDatestamp -le $script:SevenDaysAgoStamp){
		CheckBazaar
    }
    #If Entry in Unknown table is more recent than 7 days ago, NextEvent
	If ($script:LastLookupDatestamp -gt $script:SevenDaysAgoStamp){
		$Script:NextEvent = $True
    }
}


#CheckBazaar Function
Function CheckBazaar {
    $script:BazaarCounter++
    $Script:LastLookupDate = (get-date).ToString("yyyy-M-dd")
    $script:bazaaruri = 'https://mb-api.abuse.ch/api/v1/'
    Switch ($script:BazaarLookup){
        'MD5'{
            $script:MD5query = "query=get_info&hash=$script:MD5&limit=1"
		    $script:MD5request = invoke-webrequest -Uri $script:bazaaruri -Method POST -Body $script:MD5query
		    $script:MD5RequestJson = $script:MD5request.Content
		    $script:MD5RequestResult = ConvertFrom-Json $script:MD5RequestJson
		    $script:MD5RequestResultData = $script:MD5RequestResult.query_status
            If ($Script:MD5FirstSeen){
                #If FirstSeen and the result from Bazaar is hash_not_found, then this needs to be a new entry in dtMD5Unknown
                If ($script:MD5RequestResultData -match 'hash_not_found') {
                    $script:NewRow = $script:dtMD5Unknown.NewRow()
                    $script:NewRow.MD5 = $script:MD5
                    $script:NewRow.Image = $script:Image
                    $script:NewRow.Computer = $script:Computer
                    $script:NewRow.EventUtcTime = $script:UtcTime 
                    $script:NewRow.HuntExesDatestamp = (get-date).ToString("yyyy-M-dd")
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtMD5Unknown.Rows.Add($Script:NewRow)
                }
                #If Firstseen and the result fromm Bazaar is ok, then this needs to be a new entry in dtMD5Bad, and Alert
                If ($script:MD5RequestResultData -match 'ok') {
                    $script:NewRow = $script:dtMD5Bad.NewRow()
                    $script:NewRow.MD5 = $script:MD5
                    $script:NewRow.Image = $script:Image
                    $script:NewRow.Computer = $script:Computer
                    $script:NewRow.EventUtcTime = $script:UtcTime 
                    $script:NewRow.HuntExesDatestamp = (get-date).ToString("yyyy-M-dd")
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtMD5Bad.Rows.Add($Script:NewRow)

                    Write-Host "========================"
                    write-host "NEWLY DETECTED HASH IS IN MalwareBazaar - POTENTIALLY MALICIOUS!" -ForegroundColor Yellow
                    write-host "MD5 "$script:MD5
		            Write-Host "Current Sysmon Event Computer" $script:Computer
		            Write-Host "Current Sysmon Event Image" $script:Image
		            Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		            Write-Host "========================"
                }
            }
            if (!($Script:MD5FirstSeen)){
                #If NOT FirstSeen and the result from Bazaar is hash_not_found, then the existing row in dtMD5Unknown needs to be updated with $Script:LastLookupDate
                If ($script:MD5RequestResultData -match 'hash_not_found') {
                    ($script:dtMD5Unknown.Rows | Where-Object {($_.MD5 -eq $script:MD5)}).LastLookupDate = $Script:LastLookupDate
                }
                #If NOT firstSeen and the result from Bazaar is ok, then the existing row data in dtMD5Unknown needs to be moved to dtMD5Bad, and Alert
                If ($script:MD5RequestResultData -match 'ok') {
                    $script:OldRow = ($script:dtMD5Unknown.Rows | Where-Object {($_.MD5 -eq $script:MD5)})
                    $script:NewRow = $script:dtMD5Bad.NewRow()
                    $script:NewRow.MD5 = $script:OldRow.MD5
                    $script:NewRow.Image = $script:OldRow.Image
                    $script:NewRow.Computer = $script:OldRow.Computer
                    $script:NewRow.EventUtcTime = $script:OldRow.UtcTime 
                    $script:NewRow.HuntExesDatestamp = $script:OldRow.HuntExesDatestamp
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtMD5Bad.Rows.Add($Script:NewRow)

                    Write-Host "========================"
                    write-host "PREVIOUSLY UNKNOWN HASH IS NOW IN MalwareBazaar - POTENTIALLY MALICIOUS!" -ForegroundColor Yellow
                    write-host "MD5 "$script:MD5
                    write-host "This HuntExes Environment Original Sysmon Event Computer" $script:OldRow.Computer
                    write-host "This HuntExes Environment Original Sysmon Event Image" $script:OldRow.Image
                    write-host "This HuntExes Environment Original Sysmon Event UtcTime" $script:OldRow.UtcTime
		            Write-Host "Current Sysmon Event Computer" $script:Computer
		            Write-Host "Current Sysmon Event Image" $script:Image
		            Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		            Write-Host "========================"

                    ($script:dtMD5Unknown.Rows | Where-Object {($_.MD5 -eq $script:MD5)}).Delete()
                }
            }
            
          

            #after processing, set BazaarLookup to none so we know it's not left set on a valid option for a later pass through the loop
            $script:BazaarLookup = "none"
        }
        'SHA256'{
            $script:SHA256query = "query=get_info&hash=$script:SHA256&limit=1"
		    $script:SHA256request = invoke-webrequest -Uri $script:bazaaruri -Method POST -Body $script:SHA256query
		    $script:SHA256RequestJson = $script:SHA256request.Content
		    $script:SHA256RequestResult = ConvertFrom-Json $script:SHA256RequestJson
		    $script:SHA256RequestResultData = $script:SHA256RequestResult.query_status
            If ($Script:SHA256FirstSeen){
                If ($script:SHA256RequestResultData -match 'hash_not_found') {
                    $script:NewRow = $script:dtSHA256Unknown.NewRow()
                    $script:NewRow.SHA256 = $script:SHA256
                    $script:NewRow.Image = $script:Image
                    $script:NewRow.Computer = $script:Computer
                    $script:NewRow.EventUtcTime = $script:UtcTime 
                    $script:NewRow.HuntExesDatestamp = (get-date).ToString("yyyy-M-dd")
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtSHA256Unknown.Rows.Add($Script:NewRow)
                }
                If ($script:SHA256RequestResultData -match 'ok') {
                    $script:NewRow = $script:dtSHA256Bad.NewRow()
                    $script:NewRow.SHA256 = $script:SHA256
                    $script:NewRow.Image = $script:Image
                    $script:NewRow.Computer = $script:Computer
                    $script:NewRow.EventUtcTime = $script:UtcTime 
                    $script:NewRow.HuntExesDatestamp = (get-date).ToString("yyyy-M-dd")
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtSHA256Bad.Rows.Add($Script:NewRow)

                    Write-Host "========================"
                    write-host "NEWLY DETECTED HASH IS IN MalwareBazaar - POTENTIALLY MALICIOUS!" -ForegroundColor Yellow
                    write-host "SHA256 "$script:SHA256
		            Write-Host "Current Sysmon Event Computer" $script:Computer
		            Write-Host "Current Sysmon Event Image" $script:Image
		            Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		            Write-Host "========================"
                }
            }
            if (!($Script:SHA256FirstSeen)){
                If ($script:SHA256RequestResultData -match 'hash_not_found') {
                    ($script:dtSHA256Unknown.Rows | Where-Object {($_.SHA256 -eq $script:SHA256)}).LastLookupDate = $Script:LastLookupDate
                }
                If ($script:SHA256RequestResultData -match 'ok') {
                    $script:OldRow = ($script:dtSHA256Unknown.Rows | Where-Object {($_.SHA256 -eq $script:SHA256)})
                    $script:NewRow = $script:dtSHA256Bad.NewRow()
                    $script:NewRow.SHA256 = $script:OldRow.SHA256
                    $script:NewRow.Image = $script:OldRow.Image
                    $script:NewRow.Computer = $script:OldRow.Computer
                    $script:NewRow.EventUtcTime = $script:OldRow.UtcTime 
                    $script:NewRow.HuntExesDatestamp = $script:OldRow.HuntExesDatestamp
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtSHA256Bad.Rows.Add($Script:NewRow)

                    Write-Host "========================"
                    write-host "PREVIOUSLY UNKNOWN HASH IS NOW IN MalwareBazaar - POTENTIALLY MALICIOUS!" -ForegroundColor Yellow
                    write-host "SHA256 "$script:SHA256
                    write-host "This HuntExes Environment Original Sysmon Event Computer" $script:OldRow.Computer
                    write-host "This HuntExes Environment Original Sysmon Event Image" $script:OldRow.Image
                    write-host "This HuntExes Environment Original Sysmon Event UtcTime" $script:OldRow.UtcTime
		            Write-Host "Current Sysmon Event Computer" $script:Computer
		            Write-Host "Current Sysmon Event Image" $script:Image
		            Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		            Write-Host "========================"
                    ($script:dtSHA256Unknown.Rows | Where-Object {($_.SHA256 -eq $script:SHA256)}).Delete()
                }

            }

        #after processing, set BazaarLookup to none so we know it's not left set on a valid option for a later pass through the loop
        $script:BazaarLookup = "none"
        }
        'IMPHASH'{
            $script:IMPHASHquery = "query=get_imphash&imphash=$script:IMPHASH&limit=1"
		    $script:IMPHASHrequest = invoke-webrequest -Uri $script:bazaaruri -Method POST -Body $script:IMPHASHquery
		    $script:IMPHASHRequestJson = $script:IMPHASHrequest.Content
		    $script:IMPHASHRequestResult = ConvertFrom-Json $script:IMPHASHRequestJson
		    $script:IMPHASHRequestResultData = $script:IMPHASHRequestResult.query_status
            If ($Script:IMPHASHFirstSeen){
                If ($script:IMPHASHRequestResultData -match 'no_results') {
                    $script:NewRow = $script:dtIMPHASHUnknown.NewRow()
                    $script:NewRow.IMPHASH = $script:IMPHASH
                    $script:NewRow.Image = $script:Image
                    $script:NewRow.Computer = $script:Computer
                    $script:NewRow.EventUtcTime = $script:UtcTime 
                    $script:NewRow.HuntExesDatestamp = (get-date).ToString("yyyy-M-dd")
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtIMPHASHUnknown.Rows.Add($Script:NewRow)
                }
                If ($script:IMPHASHRequestResultData -match 'ok') {
                    $script:NewRow = $script:dtIMPHASHBad.NewRow()
                    $script:NewRow.IMPHASH = $script:IMPHASH
                    $script:NewRow.Image = $script:Image
                    $script:NewRow.Computer = $script:Computer
                    $script:NewRow.EventUtcTime = $script:UtcTime 
                    $script:NewRow.HuntExesDatestamp = (get-date).ToString("yyyy-M-dd")
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtIMPHASHBad.Rows.Add($Script:NewRow)

                    Write-Host "========================"
                    write-host "NEWLY DETECTED HASH IS IN MalwareBazaar - POTENTIALLY MALICIOUS!" -ForegroundColor Yellow
                    write-host "IMPHASH "$script:IMPHASH                    
		            Write-Host "Current Sysmon Event Computer" $script:Computer
		            Write-Host "Current Sysmon Event Image" $script:Image
		            Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		            Write-Host "========================"
                }
            }  
            if (!($Script:IMPHASHFirstSeen)){
                If ($script:IMPHASHRequestResultData -match 'no_results') {
                    ($script:dtIMPHASHUnknown.Rows | Where-Object {($_.IMPHASH -eq $script:IMPHASH)}).LastLookupDate = $Script:LastLookupDate
                }
                If ($script:IMPHASHRequestResultData -match 'ok') {
                    $script:OldRow = ($script:dtIMPHASHUnknown.Rows | Where-Object {($_.IMPHASH -eq $script:IMPHASH)})
                    $script:NewRow = $script:dtIMPHASHBad.NewRow()
                    $script:NewRow.IMPHASH = $script:OldRow.IMPHASH
                    $script:NewRow.Image = $script:OldRow.Image
                    $script:NewRow.Computer = $script:OldRow.Computer
                    $script:NewRow.EventUtcTime = $script:OldRow.UtcTime 
                    $script:NewRow.HuntExesDatestamp = $script:OldRow.HuntExesDatestamp
                    $script:NewRow.LastLookupDate = $Script:LastLookupDate
                    $script:dtIMPHASHBad.Rows.Add($Script:NewRow)

                    Write-Host "========================"
                    write-host "PREVIOUSLY UNKNOWN HASH IS NOW IN MalwareBazaar - POTENTIALLY MALICIOUS!" -ForegroundColor Yellow
                    write-host "IMPHASH "$script:IMPHASH
                    write-host "This HuntExes Environment Original Sysmon Event Computer" $script:OldRow.Computer
                    write-host "This HuntExes Environment Original Sysmon Event Image" $script:OldRow.Image
                    write-host "This HuntExes Environment Original Sysmon Event UtcTime" $script:OldRow.UtcTime
		            Write-Host "Current Sysmon Event Computer" $script:Computer
		            Write-Host "Current Sysmon Event Image" $script:Image
		            Write-Host "Current Sysmon Event UtcTime" $script:UtcTime
		            Write-Host "========================"

                    ($script:dtIMPHASHUnknown.Rows | Where-Object {($_.IMPHASH -eq $script:IMPHASH)}).Delete()
                }
            }

            #after processing, set BazaarLookup to none so we know it's not left set on a valid option for a later pass through the loop
            $script:BazaarLookup = "none"
        }
        
    }
}

#Run the Banner, which calls the FileCheck Function to start the HuntExes Process.
Banner

# HuntExes.ps1

HuntExes - Extract Sysmon Event ID 1 (Process Creation) events from either the local Microsoft-Windows-Sysmon/Operational log, or archived evtx files, extract MD5, SHA1, SHA256, and IMPHASH hashes of those Processes from the sysmon log, and query Malware Bazaar (https://bazaar.abuse.ch/) to identify malicious processes.

Summary of what HuntExes does:
 - Parse out key data elements from sysmon event 1 (Process Create) - UtcTime, Computer, Hashes, Image
 
 - From the Hashes, regex to parse out the MD5, SHA1, SHA256, and IMPHASH separately
 
 - If CSV files for storing a history of hashes don't exist, create them: MD5Unknown, MD5Bad, SHA1Unknown, SHA1Bad, SHA256Unknown, SHA256Bad, IMPHASHUnknown, IMPHASHBad, MD5Allowlist, 
SHA256Allowlist, SHA256Allowlist, IMPHASHAllowlist
 	- Unknown means no results were found from querying bazaar (or future virustotal integration, or whatever other services).  Unknown was picked because "good" would be potentially misleading.
	- Bad means results were found and the hash matches a sample that's reported malicious.
    - AllowList is to manually enter hashes and a comment so that HuntExes ignores them - it won't query, the Bad or Unknown lists, or Malware Bazaar if it parses these hashes.
	
 - When looping through the events loaded from the Sysmon log...
    - If hash is found in the allow file, skip everything else and move on to the next hash/event
	- If hash is found in the bad file, write Alert to the console
	- If hash is found in the Unknown file, check to the datestamp of the last lookup and query Malware Bazaar again if it was more than 7 days ago.  Update the lookup date if the file is still Unknown, or move the hash's entry to the Bad file if there's a hit.
	
 - If the current hash isn't found in the local files, query Malware Bazaar.
	- If bazaar returns 'no_results', write the Hash to the relevant "Unknown" file.
	- If bazaar returns 'ok', write the hash to the bad file and Alert.
	
Requirements:
 - Logs must be from Sysmon version 10 or later.  Version 10 added a new element, OriginalFileName, to the Process Create events.  HuntExes can't currently parse logs that don't contain it.
 - The system running HuntExes must have Sysmon version 10 installed, otherwise get-winevent won't retrieve any details from the events.

Previous versions of HuntExes recommended that you have MD5, SHA256, and IMPHASH algorithms enabled in your sysmon config.  As of version 1.2.0, HuntExes handles SHA1 in addition to those other hashes.  So it can parse every type of hash that Sysmon generates.  The choice is yours.

Note:
Testing has shown that an archived .evtx file is changed the first time it is read using get-winevent (which is how HuntExes reads the events).  The file's hash and LastWriteTime change, but the event data does not.  Subsequent reads do not have the same effect.  This is possibly due to Microsoft flipping a bit in the file to indicate it had been read, but I have not confirmed. UPDATE: This behavior is no longer being seen on my test system as of Oct 2020.  Possibly changed due to a Windows update.

Screenshots from Version 1.2.0...

HuntExes.ps1 is run, it imports csv files from .\Hashes\ into tables

![Example1](/Example1.png)

Several archived .evtx files are opened...

![Example2](/Example2.png)

The total number of files loaded is output to the console.  The total number of Events ID 1's in the first evtx is output to the console.  Events are processed, and the remaining events to proceess is output to the console every time 50 events have been completed.

![Example3](/Example3.png)

When a newly detected hash is matched to Malware Bazaar, the details are output to the console.  Likewise, when a hash matches one from the local Bad files/tables, the details are output to the console.

![Example4](/Example4.png)

When all of the events from an evtx are finished processing, summary data about that file is output to the console.  If there are additional files to process, the script moves on to loading those events.

![Example5](/Example5.png)

The flowchart below is provided to help with ongoing development.  It's a general overview of how HuntExes works.

![HuntExesFlow](/HuntExesFlow.png)

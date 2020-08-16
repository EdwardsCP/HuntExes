# HuntExes

HuntExes - Extract Sysmon Event ID 1 (Process Creation) events from either the local Microsoft-Windows-Sysmon/Operational log, or an archived evtx file, extract MD5, SHA256, and IMPHASH hashes of those Processes from the sysmon log, and query an online service (currently Malware Bazaar https://bazaar.abuse.ch/) to identify malicious processes.

Summary of what HuntExes does:
 - Parse out key data elements from sysmon event 1 (Process Create) - UtcTime, Computer, Hashes, Image
 - From the Hashes, regex to parse out the MD5, SHA256, and IMPHASH separately
 - If CSV files don't exist, create 9 CSV Files: MD5Unknown, MD5Bad, SHA256Unknown, SHA256Bad, IMPHASHUnknown, IMPHASHBad, MD5Allowlist, SHA256Allowlist, IMPHASHAllowlist
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

![Example1](/Example1.png)

![Example2](/Example2.png)

![Example3](/Example3.png)

![Example4](/Example4.png)

HuntExes was quit so the csv files would be updated.  Then a noisy and benign (in in the case of the samples found in this environment) IMPHASH was moved to the AllowList, and another evtx was processed.  HuntExes writes to the console when it encounters a whitelisted hash

![Example5](/Example5.png)

![HuntExesFlow](/HuntExesFlow.png)

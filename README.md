<h2>Description</h2>

The primary objective of this project was to design and implement a controlled Windows Virtual Machine (VM) Honeypot within Microsoft Azure. The purpose was to simulate an enticing target for potential cyber threats, enabling the collection and analysis of security events & displaying them visually in Microsoft Sentinel.

<h2>Environments and Utilities Used</h2>

- <b>Azure</b> 
- <b>Virtual Machine: Windows 11 Pro</b> (22H2)
- <b>Log Analytics Workspace</b>
- <b>Microsoft Sentinel</b>
- <b>Powershell ISE</b>
- <b>IPGeolocation.io API</b>


<h2>Project Breakdown</h2>

Resource Group Creation: <br /> Created a dedicated resource group in Azure to organize and manage project resources effectively.<br/>
<br />
<img src="https://i.imgur.com/rfDPF0t.png" height="80%" width="80%"/>
<br />
<br />
Virtual Machine Setup: 
<br />Created a Windows Virtual Machine with a public IP address to act as the Honeypot. 
<br />Configured a network firewall with an inbound rule allowing all traffic for the VM. <br/>
<br />
<img src="https://i.imgur.com/ey3U9P4.png" height="80%" width="80%"/>
<br />
<br />
<img src="https://i.imgur.com/7snYITY.png" height="40%" width="80%"/>
<br />
<br />
Log Analytics Workspace: <br/>
Created a Log Analytics workspace and connected it to the Virtual Machine to collect and store security-related logs.<br />
<br />
<img src="https://i.imgur.com/7sbHeaP.png" height="80%" width="80%"/>
<br />
<br />
Microsoft Sentinel Integration: <br />
Created a Microsoft Sentinel instance and linked it to the Log Analytics workspace.<br />
<br />
<img src="https://i.imgur.com/8TmGpNo.png" height="80%" width="80%"/>
<br />
<br />
Virtual Machine Configuration: <br />
Remotely accessed the VM using RDP and turned off the Windows firewall to allow ICMP pings making the VM more discoverable to potential threat actors.<br />
<br />
<img src="https://i.imgur.com/7bkcyDv.png" height="40%" width="80%"/>
<br />
<br />
Log Extraction & Processing:
<br />Added a powershell script on the VM that extracted the failed logon attempt entries from Event Viewer (Event ID: 4625) and fed the source IP addresses into the IPGeolocation.io API obtaining longitude and latitude data. <br />
<br /> This data was then dumped into log file - C:\ProgramData\failed_rdp.log. <br />
<br />
I created an account on IpGeolocation.io and got my own api, the free version is limited to 1000 requests. <br />
<br />
<img src="https://i.imgur.com/8pwQwON.png" height="80%" width="80%"/> <br />
<br />
This code block defines the variables and is where my custom API key wass entered:
```# Get API key from here: https://ipgeolocation.io/
$API_KEY      = "<api key goes here>"
$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"
```
<br />
This section of the code checks the event viewer logs and interates over each relevant field of data: 
<br />
<br />
<img src="https://i.imgur.com/9oX6arW.png" height="80%" width="80%"/>
<br />
This section of the code sends the source IP address to the IP then stores the geolocation and relevant failed logon details into the failed_rdp log file:
<br />
<br />

```
# Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
```
<br />
I then created a custom log in Log Anyalytics named 'FAILED_RDP_WITH_GEO_CL' that pointed to the failed_rdp log file. <br /> 
<br />
<img src="https://i.imgur.com/UC1Lb1d.png" height="80%" width="80%"/> <br />
<img src="https://i.imgur.com/14SVPZ1.png" height="80%" width="80%"/> <br />
Data Extraction and Visualization:<br />
In Microsoft Sentinel I used Kusto Query Language (KQL) to run the query below & extract the relevant fields. I then had Sentinel display the data visually with a Map and saved it as a workspace that would auto-refresh itself & populate it with new data.<br />
<br />

```
FAILED_RDP_WITH_GEO_CL
| parse RawData with * "latitude:" Latitude ",longitude:" Longitude ",destinationhost:" DestinationHost ",username:" Username ",sourcehost:" Sourcehost ",state:" State ", country:" Country ",label:" Label ",timestamp:" Timestamp
| where DestinationHost != "samplehost"
| where Sourcehost != ""
| summarize event_count=count() by Sourcehost, Latitude, Longitude, Country, Label, DestinationHost 
```
<br />
After leaving the VM running overnight, I came back the following day and found there was various sign in attempts from multiple countries. Threat actors using brute forcing methods like using common usernames such as 'admin' or 'administrator. <br />
<br />
<img src="https://i.imgur.com/svLC8dH.png" height="80%" width="80%"/> <br />

<h2>Conclusion</h2>

This project showcases hands-on experience in setting up a Honeypot, configuring resources in an Azure environment and implementing methods to ingest log data into a SIEM. I gained practical insights on how KQL can be used to parse data and how to visualize that data to make it easier to digest and analyze. It has exposed myself to real-world data & given me a glimpse of the threats that are out there & how vunerable our infrastructure can be if we do not implement strong security controls & practices. 
<br />
<h2>Resources</h2>

- https://portal.azure.com/
- https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1
- https://ipgeolocation.io/
</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>

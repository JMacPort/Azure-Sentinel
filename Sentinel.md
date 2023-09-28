Azure Sentinel is a part of the larger Microsoft Suite of cloud apps and is used a SIEM or Security Information Events Manager. This can be used to visualize security alerts, create new alerts, and more. 
While Sentinel is just one piece of Azure as a whole, this lab also accesses a few other apps, such as Log Analytics Workspaces, Virtual Machines, and more. 

This lab was created by Josh Madakor and a link to the video can be found [here](https://www.youtube.com/watch?v=RoZeVbbZ0o0)

To start, an Azure account is needed. With this account $200 USD in free credits can be obtained which is much more than enough for this lab as it will only be up for a maximum of 1-2 days.
Once logged in, the first thing is to go to (https://www.portal.azure.com). This is going to the main management page in which everything can be accessed easily. A virtual machine will be created
first with no security measures, as this machine is going to be a honeypot to attract various bots and hackers to gain entry to the VM via RDP." Technically, this can be done on a machine with default specs, 
but I found it better to use 2 CPU, 4GB RAM as the performance is much better. In the Networking section, a security group was created that essentially opens all ports. 

![image](https://github.com/JMacPort/Azure-Sentinel/assets/145376972/2edd1db3-025b-4844-88a5-abfa80e4b839)

Then a Log Analytics Workspace was created to establish a link between the VM and Sentinel (the SIEM). In Microsoft Defender > Environment Settings > Created VM, it was enabled for Servers, disabled for SQL
Servers and then all data collection was enabled to ensure all logs will be collected. Back in the Log Analytics Workspace (LAW), the workspace and the VM were then connected so all of the logs we are collecting can be passed through.

Now in Sentinel, simply add the created workspace, and now the connection between the three main aspects is setup. The VM will produce logs which will be sent to the LAW, and then the LAW will send these logs 
in Sentinel for visualization and organization. 

Moving into the created VM by using RDP on my own PC. Using the IP address and then logging in with the originally created credentials. A Powershell script will be used to extract logs from the Event Viewer
and translate them. To the best of my knowledge this script was created by Josh. Instead of copy/pasting the script I will provide a brief description at the bottom of what it does, along with a link to his github page. This script utilizes 
an API from [ipgeolocation](https://www.ipgeolocation.com) which is used to transform the logs using more specific geographical data, which will be touched more on later. Once the script is added to the VM, as long
as the VM remains on and the script is running, it will generate log data based on failed RDP events.

***On a personal note, seeing these Powershell scripts more often is bettering my ability to read them and have been practicing writing them, although extremely simple and basic.*** 

In the Log Analytics Workspace that was created earlier, a new table is created. Here, I had to troubleshoot how to do this as it has been updated since the video was released, which led me to look through comments
and documentation regarding Azure. A custom log (MMA-Based) will allow us to import a sample log for the LAW to read and start the machine learning process. Once this is imported, you can use the Logs section in the LAW 
to query using KQL. Simply typing the file name, after some time to generate the logs, will present the failed security events that were tracked by the Event Viewer. The entries below are what propagated when the file is run, 
which is the test data generated from the Powershell script.

![image](https://github.com/JMacPort/Azure-Sentinel/assets/145376972/e82b526a-196d-4ae6-b5a6-ad8d4360ed79)

Finally, going into Sentinel, a new workbook is created based off of the LAW. This links the visualization aspect to Sentinel. The default queries are removed and a new query is added. Here the following query is input and
is based on the labels that were originally provided from the script. Again, this query was provided in the comments of the youtube and combines a few comments to structure the query better.
```
FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude
```
Once the query is run and the fields propagate, switch the visualization mode to map to get a global view of where attacks will be coming from. Funny enough, before I set this up I already had someone from France attempt to gain entry.
Now, just tweak the map settings to use Latitude/Longitude and size by Event Count as this will show where the majority of attacks are coming from. In Metric Settings, change the label to country and the value to the Event Count. Below will
be a map of my immediate results and then I will post an update after around a day to show what I had attracted. 

![image](https://github.com/JMacPort/Azure-Sentinel/assets/145376972/f9274535-cc78-4fdc-91eb-d9438b69adde)

From here, it is just a waiting game until someone/something finds the IP and tries to gain access. Most likely, since all of the ports are open, there are other attacks happening as well but it is filtered to just RDP for simplicity sake. 

Powershell Script Rundown:
- Creates the variables for the API Key, log file name, and path name.
- Creates an XML filter to single out the failed RDP attempts.
- Adds sample data to the log file to propagate data in the log file, for testing.
- If statement will test is the log file is already created, if not it will create it
- A while loop starts by checking the Event Viewer for new attempts
- If found, a for loop is run on each event which makes sure there is an IP address, if not it will skip it
- It then takes the following fields from the event. Timestamp, Event ID, Destination Host, Source Host, IP address, and the attempted username.
- The log contents are grabbed and if the currently grabbed event is not located in the file the API will be called.
- The API will take the previously grabbed info and translate it into latitude, longitude, state, and country.
- These are the labels we can use in Sentinel to query a map. 

[Link](https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1) to Josh's script
















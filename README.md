# SOC Analyst Detection Lab

## Objective

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system and use of an EDR, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies. 

### Skills Learned
<!--- [Bullet Points - Remove this afterwards] --->

- Detection of remote connections and creating alerts for detection.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used
<!--- [Bullet Points - Remove this afterwards] --->

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
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

3. 
*Ref 1: Network Diagram*

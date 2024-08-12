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

This is a lab from a blog post. You can follow along with it [here](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro).

1. Download and install VMware Workstation Pro.
2. Download and deploy a free Windows VM directly from Microsoft
3. Download and install Ubuntu into a new VM and make sure to set a static IP on the same subnet as the Microsoft OS.
4. Set a memorable username/password (this is just a lab)
5. Install OpenSSH server on Ubuntu
6. Continue on the Ubuntu Server install till complete. 
7. Restart Ubuntu
8. Ping google
``` ping -c 2 google.com ```
9. 

### Prevent VM from going into standby
1. From an administrative command prompt, let’s prevent the VM from going into sleep/standby mode during our shenanigans
```
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
```



*Ref 1: Network Diagram*

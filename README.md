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

1. Download and install VMware Workstation Pro.
2. Download and deploy a free Windows VM directly from Microsoft
3. Download and install Ubuntu into a new VM and make sure to set a static IP on the same subnet as the Microsoft OS.
4. Set a memorable username/password (this is just a lab)
5. Install OpenSSH server on Ubuntu
6. Continue on the Ubuntu Server install till complete. 
7. Restart Ubuntu
8. Ping google
``` ping -c 2 google.com ```

### Turn off Microsoft Defender

1. Permanently disable Microsoft Defender so it doesn’t interfere with the shady stuff we’re planning. This is trickier than it sounds (especially in Windows 11) as Defender will turn itself back on, so follow ALL of these instructions verbatim in the exact order below.

2. These steps are closely derived from this guide and this one as well, but with fewer screenshots. If you need more guidance, see the original guides.

> **_NOTE:_** for an easier option, consider just using Sordum’s Defender Control (not covered in this guide, but fairly straightforward)

3. Disable Tamper Protection

4. Click the “Start” menu icon

5. Click “Settings”

6. Click “Privacy & security” on the left

7. Click “Windows Security”

8. Click “Virus & threat protection”

9. Under “Virus & threat protection settings” click “Manage settings”

10. Toggle OFF the “Tamper Protection” switch. When prompted, click “Yes”

11. While you’re in there, toggle every other option OFF as well, even though we’re about to take care of it a couple different ways.

12. Close the windows we just opened.

13. Permanently Disable Defender via Group Policy Editor

14. Click the “Start” menu icon

15. Type “cmd” into the search bar within the Start Menu

16. Right+Click “Command Prompt” and click “Run as administrator”

17. Run the following command
``` gpedit.msc ```
18. Inside the Local Group Policy Editor

19. Click Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus

20. Double-click “Turn off Microsoft Defender Antivirus”

21. Select “Enabled”

22. If you enable this policy setting, Microsoft Defender Antivirus does not run, and will not scan computers for malware or other potentially unwanted software.

23. Click Apply

24. Click OK

25. Permanently Disable Defender via Registry

26. From the same administrative command prompt we previously opened, copy/paste this command and press Enter
``` REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f ```
27. Prepare to boot into Safe Mode to disable all Defender services

28. Click the “Start” menu icon

29. type “msconfig” into the search bar within the Start Menu

30. Go to “Boot” tab and select “Boot Options”

31. Check the box for “Safe boot” and “Minimal”

32. Safe boot

33. Click Apply and OK

34. System will restart into Safe Mode

35. Now, in Safe Mode, we’ll disable some services via the Registry

36. Click the “Start” menu icon

37. Type “regedit” into the search bar and hit Enter

38. For each of the following registry locations, you’ll need to browse to the key, find the “Start” value, and change it to 4

39. Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense

40. Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot

41. Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend

42. Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv

43. Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc

44. Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter
    
46. Leave Safe Mode the same way we got into it
    
48. Click the “Start” menu icon
    
50. type “msconfig” into the search bar within the Start Menu
    
52. Go to “Boot” tab and select “Boot Options”
    
54. Uncheck the box for “Safe boot”
    
56. Click Apply and OK
    
58. System will restart into normal desktop environment, now (hopefully) Defender-free.

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
### Install LimaCharlie EDR on Windows VM 

1. LimaCharlie is a very powerful “SecOps Cloud Platform”. It not only comes with a cross-platform EDR agent, but also handles all of the log shipping/ingestion and has a threat detection engine. I am a huge fan of LimaCharlie for many reasons, one of which is that they have a free tier for up to two systems which is what allows me to make it an instrumental part of this guide.
   
2. Create a free LimaCharlie account.
   
3. LimaCharlie will ask you a few questions about your role. Answer however you wish, it just helps their developers build a better product. If you’d like for them to know that this series helped you discover LC, reference this blog post under “How did you hear about us?” Completely optional, I do not get kickbacks or anything :)

5. Once logged into LimaCharlie, create an organization

6. Name: whatever you want, but it must be unique

7. Data Residency: whatever is closest

8. Demo Configuration Enabled: disabled

9. Template: Extended Detection & Response Standard

10. Once the org is created, click “Add Sensor”

11. Select Windows

12. Provide a description such as: Windows VM - Lab

13. Click Create

14. Select the Installation Key we just created

15. Specify the x86-64 (.exe) sensor, but then skip ahead to my instructions versus the ones provided.

16. IN THE WINDOWS VM, open an Administrative PowerShell prompt and paste the following commands:

17. cd C:\Users\User\Downloads
18. Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe
19. Shift into a standard command prompt by running this command
``` cmd.exe ```
20. Next, we will copy the install command provided by LimaCharlie which contains the installation key. Paste this command into your open terminal.
21. Paste this command into the admin command prompt in your Windows VM
22. This is the expected output, ignore the “ERROR” that says “service installed!” Still waiting on those guys to fix that :)

23. If you experience an error trying to install the EXE, try the x86-64 MSI option on the LimaCharlie installer dialog.

24. If everything worked correctly, in the LimaCharlie web UI you should also see the sensor reporting in.

25. Now let’s configure LimaCharlie to also ship the Sysmon event logs alongside its own EDR telemetry

26. In the left-side menu, click “Artifact Collection”

27. Next to “Artifact Collection Rules” click “Add Rule”

28. Name: windows-sysmon-logs

29. Platforms: Windows

30. Path Pattern: wel://Microsoft-Windows-Sysmon/Operational:*

31. Retention Period: 10

32. Click “Save Rule”

33. LimaCharlie will now start shipping Sysmon logs which provide a wealth of EDR-like telemetry, some of which is redundant to LC’s own telemetry, but Sysmon is still a very power visibility tool that runs well alongside any EDR agent.

34. The other reason we are ingesting Sysmon logs is that the built-in Sigma rules we previously enabled largely depend on Sysmon logs as that is what most of them were written for.

35. That’s all we’ll do with LimaCharlie for now. We’ll dive deeper into what it can do later on. Feel free to close all open windows on the Windows VM as we’re now moving onto the Linux VM.

36. Pro Tip: Now would be a good time to Snapshot your Windows VM in case it gets hosed later on. You can always revert to this “Clean” snapshot later on to get back to a good state.
*Ref 1: Network Diagram*

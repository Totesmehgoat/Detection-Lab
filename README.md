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

*Ref 1: Network Diagram*

# FalconZero
[![](https://img.shields.io/badge/Category-Defense%20Evasion-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-C%20%2f%20C++%20%2f%20Python3-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Version-1.0-E5A505?style=flat-square)]()

Introducing FalconZero v1.0 - a stealthy, targeted Windows Loader for delivering second-stage payloads(shellcode) from Github to the host machine undetected - first public release version Loader/Dropper of the FALCONSTRIKE project


## Features
- [X] Dynamic shellcode execution
- [X] Usage of Github as the payload storage area - the payload is fetched from Github - using legitimate sites for implant communication to make it stealthier
- [X] Targeted implant Loader - only execute on targeted assets - thwart automated malware analysis and hinder reverse engineering efforts on non-targeted assets
- [X] Killdates - implant expires after a specific date
- [X] Stealthy shellcode injection technique without allocating RWX memory pages in victim process to evade AV/EDRs - Process hollowing - currently spawns and injects to `explorer.exe`
- [X] Sensitive strings encrypted using XOR

## Payload Compatibility
- [X] [Metasploit](https://www.metasploit.com/)
- [X] [Covenant C2](https://cobbr.io/Covenant.html)
- [X] [Cobalt Strike](https://www.cobaltstrike.com/)
- [X] [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY)
- [X] [Faction C2](https://www.factionc2.com/)
- [X] [Throwback](https://github.com/silentbreaksec/Throwback)

And support for many more...

The ones mentioned in the list are the ones verified by the [testing team](https://github.com/Sumalyo).


## Usage
There are many hard things in life but generating an implant shouldn't be one. This is the reason the `generate_implant.py` script has been created to make your life a breeze.
The process is as simple as:
```
First generate your shellcode as a hex string
Upload it on Github and copy the Github raw URL
For testing(MessageBox shellcode): https://raw.githubusercontent.com/slaeryan/DigitalOceanTest/master/messagebox_shellcode_hex_32.txt
git clone https://github.com/slaeryan/FALCONSTRIKE.git
cd FALCONSTRIKE
pip3 install -r requirements.txt
python3 generate_implant.py
```
Follow the on-screen instructions and you'll find the output in `bin` directory if everything goes well.

## TO-DO
This is an alpha release version and depending on the response many more upgrades to existing functionalities are coming soon.

Some of them are:

- [ ] Integrate various Sandbox detection algorithms
- [ ] Integrate support for more stealthy shellcode injection techniques
- [ ] Integrate function obfuscation to make it stealthier
- [ ] Include a network component to callback to a C2 when a Stage-2 payload is released or to change targets/payloads and configure other options on-the-fly
- [ ] Inject to a remote process from where network activity is not unusual for fetching the shellcode - better OPSEC
- [ ] Include active hours functionality - Loader becomes active during a specified period of day etc.

Feel free to communicate any further feature that you want to see in the next release. Suggestions for improving existing features are also warmly welcome :)

## Read more
[![](https://img.shields.io/badge/FalconZero-E5A505?style=flat-square)](https://slaeryan.github.io/posts/falcon-zero-alpha.html)

## Author
Upayan ([@slaeryan](https://twitter.com/slaeryan)) [[slaeryan.github.io](https://slaeryan.github.io)]

## License
All the code included in this project is licensed under the terms of the GNU GPLv3 license.

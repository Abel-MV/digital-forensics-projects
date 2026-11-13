# Digital Forensics Projects

This repository contains digital forensics investigations I have completed as part of my cybersecurity learning and practical experience.

My aim is to improve my skills in analysing digital evidence, investigating suspicious activity and understanding how security incidents can be identified and reconstructed.

Each project includes the investigation process, tools used, findings, evidence and lessons learned.

## Objectives

- Develop practical digital forensics and incident investigation skills.
- Analyse network traffic and identify suspicious activity.
- Understand how to preserve and verify digital evidence.
- Investigate network connections, protocols and system artefacts.
- Reconstruct events using timestamps and available evidence.
- Identify indicators of compromise (IOCs).
- Document findings clearly and recognise the limitations of an investigation.

## Investigations

| Project | Description | Status |
|---|---|---|
| **Network Forensics Investigation — NetSupport RAT** | Analysis of a PCAP to investigate suspicious NetSupport communications, identify the affected host and examine periodic network traffic. | Completed — Publication in progress |

## Network Forensics Investigation — NetSupport RAT

### Overview

This project is based on the **Easy as 123** exercise from Malware-Traffic-Analysis.net.

I analysed a provided PCAP file using Wireshark and TShark to investigate suspicious network activity associated with NetSupport remote-control software.

The investigation focused on identifying the Windows host involved, understanding its communication with an external server and examining traffic patterns that could indicate command-and-control activity.

**Environment:** Kali Linux  
**Tools:** Wireshark, TShark, SHA-256 utilities and `awk`  
**Investigation date:** 6 November 2026

### Investigation Process

The main steps included:

1. Calculating SHA-256 hashes to compare the downloaded evidence with a working copy.
2. Identifying suspicious network connections in Wireshark.
3. Inspecting HTTP requests and reconstructing TCP streams.
4. Identifying the Windows host using DHCP information.
5. Examining Kerberos authentication traffic.
6. Analysing repeated HTTP POST requests using TShark and `awk`.
7. Creating a timeline of the observed network activity.
8. Documenting findings, indicators and investigation limitations.

### Key Findings

The investigation identified an internal Windows host communicating with an external server using HTTP requests containing NetSupport-related headers and messages.

Some HTTP POST requests were repeated at intervals of approximately 60 seconds. This behaviour was consistent with periodic remote-control communication, although the timing alone did not prove malicious activity.

DHCP traffic helped identify the device's hostname and network address. Kerberos traffic also revealed an associated domain account.

The findings supported the exercise's suspicion of remote-access activity, but the available PCAP did not confirm which commands were executed or establish the full extent of any compromise.

### Evidence

Four screenshots were recorded during the investigation:

- **E01:** SHA-256 calculation for the downloaded evidence.
- **E02:** NetSupport-related HTTP communication reconstructed in Wireshark.
- **E03:** Windows host identification using DHCP.
- **E04:** Repeated HTTP POST requests to the external server.

The original PCAP will not be redistributed in this repository. The investigation uses a publicly available training exercise, which is linked in the references.

## Investigation Approach

I follow a practical investigation process based on the evidence available.

| Stage | Purpose |
|---|---|
| Evidence acquisition | Identify the source and obtain the required files |
| Integrity checks | Calculate and compare hashes to check file consistency |
| Initial examination | Review the available evidence and identify relevant activity |
| Detailed analysis | Examine network protocols, connections and artefacts |
| Timeline reconstruction | Organise important events in chronological order |
| Findings | Explain what the evidence supports |
| Recommendations | Suggest appropriate investigative or defensive actions |
| Limitations | Record what could not be confirmed |

The exact steps may vary depending on the investigation and the available evidence.

## Tools

| Tool | Purpose |
|---|---|
| Wireshark | Packet inspection, protocol analysis and TCP stream reconstruction |
| TShark | Command-line filtering and extraction of network data |
| SHA-256 utilities | Calculating and comparing file hashes |
| `awk` | Processing timestamps and calculating time intervals |
| Kali Linux | Operating system used for the investigation |

Other forensic tools will be included as I complete further projects.

## Security and Evidence Handling

The investigations in this repository are based on authorised lab environments or publicly available training material.

I review screenshots and documentation before publishing them to avoid sharing unnecessary personal or sensitive information.

I also try to distinguish between confirmed observations, possible explanations and findings that need further investigation.

A hash comparison can show whether two files have identical contents, but it does not independently prove that the original evidence came from a trusted source.

## Lessons Learned

Through these investigations, I am developing a better understanding of:

- How network evidence can help investigate possible security incidents.
- How to use Wireshark and TShark together.
- How DHCP and authentication traffic can help identify devices and accounts.
- How repeated network connections can reveal useful behavioural patterns.
- Why timestamps, packet details and supporting evidence matter.
- Why it is important not to draw conclusions beyond what the evidence supports.

## Future Work

I plan to continue developing my digital forensics skills through:

- Additional network traffic investigations.
- Memory forensics.
- Windows forensic artefact analysis.
- File system and disk image examination.
- Incident timeline reconstruction.
- Digital evidence acquisition and integrity verification.

New investigations will be added once they have been completed, reviewed and documented.

## References

- [Malware Traffic Analysis — Easy as 123](https://malware-traffic-analysis.net/2026/02/28/index.html)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [TShark Documentation](https://www.wireshark.org/docs/man-pages/tshark.html)
- [NIST Computer Security Resource Center](https://csrc.nist.gov/)

---

*Part of the [Cybersecurity Portfolio](https://github.com/Abel-MV).*

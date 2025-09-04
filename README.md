# CodeAlpha_NetworkPacketSniffer

A Python program to capture and analyze network traffic packets.
This project helps understand how data flows in a network and the basics of protocols like TCP, UDP, ICMP.

---

### 📜 License & Disclaimer

This project is licensed under the **MIT License** – see the [LICENSE](./LICENSE) file for details.  

### ⚠️ Special Disclaimer
- This project is created for **educational and research purposes only**.  
- It can be used for **personal and commercial purposes**.  
- The author(s) are **NOT responsible** for any misuse, damage, or illegal activities caused by this software.  
- By using this tool, you accept that **you are fully responsible** for your actions.  
- Please use it **ethically and responsibly**, only on networks and systems you own or have explicit permission to test.

### 🎯 Features

- Captures live network packets.

- Displays source/destination IPs, ports, protocol, and payload in real time.

- Saves captured data in multiple formats:

  - **TXT** (human-readable log)
  
  - **CSV** (structured data)
  
  - **JSON** (machine-readable format)
  
  - **PCAP** (for Wireshark analysis)

---

### 🚀 How to Run

1. Install dependencies:
   
     **`pip install scapy`**
   
   
2. Run the sniffer (requires Admin/sudo):
   
     **`python sniff.py`**
   
   
3. Stop with Ctrl + C → results will be saved automatically.

   ---

### 📖 Learning Outcomes

How packets are structured (IP header, protocol, ports, payload).

Difference between TCP, UDP, ICMP.

Basics of packet sniffing and analysis using Python.

---

## 📂 Example Output (console)
`
[2025-09-04 13:45:21] 192.168.1.10 --> 8.8.8.8 | Protocol: UDP
   Ports: 54321 -> 53
   Payload: example.dns.query.....
`

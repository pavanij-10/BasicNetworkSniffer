# 🌐 Basic Network Sniffer & Traffic Analysis Dashboard

A beginner-friendly network analysis project built using Python, Scapy, Streamlit, and Pandas.

This project captures network packets, extracts useful information, and displays saved packet data through an interactive dashboard.

## 🎯 Project Objective

The goal is to understand how network packets work and learn the basics of network traffic analysis through practical implementation.

## ✨ Features

- **Packet Capture:** Capture IPv4 network traffic using Scapy.
- **Protocol Filtering:** Filter traffic by TCP, UDP, ICMP, or other IPv4 traffic.
- **Packet Inspection:** View source IP, destination IP, protocol, port numbers when available, and packet size.
- **Traffic Visualization:** Explore protocol distribution, IP address charts, and packet-size statistics.
- **IP Filtering:** Filter packets by source or destination IP address.
- **CSV Export:** Download filtered packet information for further analysis.
- **PCAP Support:** Load saved packet captures into the dashboard.

## 🔄 How It Works

1. `sniffer.py` captures network packets and displays their details.
2. Captured packets can be saved to a `.pcap` file.
3. `dashboard.py` reads a saved capture and presents its information through charts, statistics, and a packet table.
4. Users can filter the displayed packets and export the filtered data as CSV.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Scapy | Packet capture and inspection |
| Streamlit | Interactive dashboard |
| Pandas | Tabular data handling |
| Npcap | Windows packet-capture support |

## 📂 Project Structure

```text
BasicNetworkSniffer/
├── sniffer.py
├── dashboard.py
├── requirements.txt
├── README.md
└── .gitignore
```

## 🚀 Getting Started

**Requirements:** Python, Npcap on Windows, and the required Python packages.

### 1. Clone the repository

```bash
git clone https://github.com/pavanij-10/BasicNetworkSniffer.git
cd BasicNetworkSniffer
```

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Capture packets

```powershell
python sniffer.py
```

Follow the program prompts to choose the capture filter and options. Live capture may require appropriate permissions.

### 5. Open the dashboard

Ensure you have a saved `.pcap` capture available, then run:

```powershell
python -m streamlit run dashboard.py
```

Open the local URL displayed in the terminal, usually `http://localhost:8501`, and load your capture in the dashboard.

## 🔐 Responsible Use

Capture traffic only on networks you own or have permission to analyze. Packet captures may contain sensitive information, so handle and share them carefully.

## 📌 Scope

This is an educational project for basic packet capture and offline traffic analysis. It is not a full intrusion detection system or a replacement for advanced network analysis tools.

---

**Built as a hands-on project to learn Python, networking, and cybersecurity fundamentals.**

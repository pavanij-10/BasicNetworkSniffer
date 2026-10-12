# Basic Network Sniffer and Traffic Analysis Dashboard

## About the Project

This is a beginner-friendly network traffic analysis project built using Python, Scapy, and Streamlit. It captures authorized IPv4 network traffic, displays packet details, saves captured packets, and presents traffic statistics through a web dashboard.

## Features

- Capture live network packets
- Display source and destination IP addresses
- Identify protocols such as TCP, UDP, and other IPv4 protocols
- Display port numbers and packet sizes when available
- Save captured packets in PCAP format
- Visualize protocol and packet-size distributions
- View frequently appearing source and destination IP addresses
- Filter packet data by protocol and IP address
- Export packet-table data to CSV

## Technologies Used

- Python
- Scapy
- Streamlit
- Pandas

## Project Structure

```text
BasicNetworkSniffer/
├── sniffer.py
├── dashboard.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

1. Install Python on your computer.
2. Open a terminal in the project folder.
3. Create and activate a virtual environment.
4. Install the required packages:

```bash
pip install -r requirements.txt
```

## How to Run

### 1. Start the packet sniffer

```bash
python sniffer.py
```

Follow the menu to select a capture option and packet limit.

### 2. Start the dashboard

Open another terminal in the project folder and run:

```bash
python -m streamlit run dashboard.py
```

Open the local URL shown in the terminal, usually `http://localhost:8501`, and upload your saved PCAP file.

## Example Test Results

In one test run, the sniffer captured 50 packets:

- TCP: 34 packets
- UDP: 9 packets
- Other IPv4 protocols: 7 packets
- Total packet data size: 31,737 bytes

Results may differ between captures because network traffic changes over time.

## Limitations

- Captured traffic depends on the network interface, permissions, filters, and activity during capture.
- Encrypted HTTPS content is not automatically readable.
- The dashboard analyzes the packets provided in the uploaded capture file.

## Responsible Use

Use this project only on networks and devices you own or have explicit permission to inspect. Do not publish packet captures or exported data that may contain sensitive information.

## Future Improvements

- Improve support for additional protocols
- Add packet timestamps and capture-duration statistics
- Expand testing and error handling
- Improve dashboard filtering and analysis

## Disclaimer

This project is intended for educational purposes and for authorized network analysis.
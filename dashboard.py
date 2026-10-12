
import streamlit as st
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import Counter
from pathlib import Path


st.set_page_config(
    page_title="Basic Network Sniffer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown("""

<style>
    .stApp {
        background-color: #101713;
        color: #e5eee8;
    }

    [data-testid="stHeader"] {
        background-color: #101713;
    }

    [data-testid="stSidebar"] {
        background-color: #18231c;
    }

    h1, h2, h3, p, label,
    [data-testid="stWidgetLabel"],
    [data-testid="stMarkdownContainer"] p {
        color: #e5eee8 !important;
    }

    [data-testid="stCaptionContainer"] p {
        color: #a7b9ad !important;
    }

    [data-testid="stMetric"] {
        background-color: #1b2820;
        border: 1px solid #304638;
        padding: 18px;
        border-radius: 12px;
    }

    [data-testid="stMetricValue"] {
        color: #72e3a1 !important;
    }

    [data-testid="stFileUploader"] {
        background-color: #18231c;
        border: 1px dashed #4c8060;
        border-radius: 12px;
        padding: 14px;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #304638;
        border-radius: 8px;
    }

    div[data-baseweb="select"] > div,
    div[data-baseweb="input"] > div {
        background-color: #1b2820;
        border-color: #4c8060;
    }

    div[data-baseweb="select"] *,
    div[data-baseweb="input"] input {
        color: #e5eee8 !important;
    }

    div[data-testid="stDownloadButton"] button {
        background-color: #245c3b;
        color: #ffffff;
        border: 1px solid #72e3a1;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

st.title("Basic Network Sniffer")
st.caption("Educational network traffic analysis dashboard")

uploaded_file = st.file_uploader(
    "Upload a saved PCAP file",
    type=["pcap", "pcapng"]
)

if uploaded_file:
    try:
        packets = rdpcap(uploaded_file)
        rows = []

        for packet in packets:
            if IP not in packet:
                continue

            ip = packet[IP]

            if TCP in packet:
                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
                source_port = "-"
                destination_port = "-"
            else:
                protocol = "Other"
                source_port = "-"
                destination_port = "-"

            rows.append({
                "Source IP": ip.src,
                "Destination IP": ip.dst,
                "Protocol": protocol,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "Packet Size (bytes)": len(packet)
            })

        if not rows:
            st.warning("No IPv4 packets were found in this file.")
        else:
            df = pd.DataFrame(rows)

            st.subheader("Traffic Overview")

            
            packet_sizes = df["Packet Size (bytes)"]
            total_bytes = packet_sizes.sum()
            average_size = packet_sizes.mean()
            largest_size = packet_sizes.max()
            smallest_size = packet_sizes.min()

            col1, col2, col3 = st.columns(3)
            col1.metric("Packets Analyzed", len(df))
            col2.metric("Total Data", f"{total_bytes:,} bytes")
            col3.metric("Protocols Found", df["Protocol"].nunique())

            col4, col5, col6 = st.columns(3)
            col4.metric("Average Packet Size", f"{average_size:.1f} bytes")
            col5.metric("Largest Packet", f"{largest_size:,} bytes")
            col6.metric("Smallest Packet", f"{smallest_size:,} bytes")


            st.subheader("Protocol Distribution")
            protocol_counts = df["Protocol"].value_counts()
            st.bar_chart(protocol_counts)

            
            st.subheader("Packet Size Distribution")

            size_ranges = pd.cut(
                df["Packet Size (bytes)"],
                bins=[0, 99, 499, 1499, float("inf")],
                labels=[
                    "Under 100 bytes",
                    "100–499 bytes",
                    "500–1,499 bytes",
                    "1,500+ bytes"
                ],
                include_lowest=True
            )

            size_counts = size_ranges.value_counts(sort=False)

            st.bar_chart(size_counts)

            st.caption(
    "Packet counts grouped by captured packet size."
)


            left, right = st.columns(2)

            with left:
                st.subheader("Top Source IPs")
                st.bar_chart(df["Source IP"].value_counts().head(10))

            with right:
                st.subheader("Top Destination IPs")
                st.bar_chart(df["Destination IP"].value_counts().head(10))

            st.subheader("Filter Packets")

            selected_protocol = st.selectbox(
                "Protocol",
                ["All"] + sorted(df["Protocol"].unique().tolist())
            )

            search_ip = st.text_input("Filter by source or destination IP")

            filtered_df = df.copy()

            if selected_protocol != "All":
                filtered_df = filtered_df[
                    filtered_df["Protocol"] == selected_protocol
                ]

            if search_ip.strip():
                filtered_df = filtered_df[
                    (filtered_df["Source IP"] == search_ip.strip()) |
                    (filtered_df["Destination IP"] == search_ip.strip())
                ]

            st.dataframe(filtered_df, use_container_width=True)

            st.download_button(
                "Download Filtered Results (CSV)",
                filtered_df.to_csv(index=False).encode("utf-8"),
                file_name="filtered_packets.csv",
                mime="text/csv"
            )

            st.caption(
                "Privacy note: this dashboard displays packet metadata only, "
                "not raw payload contents. Upload captures you are authorized to analyze."
            )

    except Exception as error:
        st.error(f"Could not analyze this capture: {error}")
else:
    st.info("Upload captured_packets.pcap to begin analyzing traffic.")

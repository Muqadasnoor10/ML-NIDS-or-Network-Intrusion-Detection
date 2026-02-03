"""from collections import defaultdict
import time

flows = defaultdict(list)

def get_flow_id(pkt):
    if 'IP' in pkt and 'TCP' in pkt:
        ip = pkt['IP']
        tcp = pkt['TCP']
        return (ip.src, ip.dst, tcp.sport, tcp.dport, 'TCP')
    return None


def update_flow(pkt):
    flow_id = get_flow_id(pkt)
    if flow_id:
        flows[flow_id].append((time.time(), len(pkt)))


def compute_features(flow_packets):
    times = [p[0] for p in flow_packets]
    sizes = [p[1] for p in flow_packets]

    duration = max(times) - min(times)
    total_packets = len(sizes)
    total_bytes = sum(sizes)

    if duration == 0:
        duration = 1

    bytes_per_sec = total_bytes / duration
    packets_per_sec = total_packets / duration

    return {
        "Flow Duration": duration,
        "Total Fwd Packets": total_packets,
        "Total Length of Fwd Packets": total_bytes,
        "Flow Bytes/s": bytes_per_sec,
        "Flow Packets/s": packets_per_sec
    }
"""

from collections import defaultdict
import time
import numpy as np

# Dictionary to store flows
flows = defaultdict(list)

# Define a flow by 5-tuple: src IP, dst IP, src port, dst port, protocol
def get_flow_id(pkt):
    if 'IP' in pkt and 'TCP' in pkt:
        ip = pkt['IP']
        tcp = pkt['TCP']
        return (ip.src, ip.dst, tcp.sport, tcp.dport, 'TCP')
    return None

# Update flow with packet info
def update_flow(pkt):
    flow_id = get_flow_id(pkt)
    if flow_id:
        # Store timestamp, packet length, direction (1=forward, 0=backward)
        direction = 1  # default forward
        flows[flow_id].append((time.time(), len(pkt), direction))

# Compute 25 CIC features for a flow
def compute_features(flow_packets):
    times = np.array([p[0] for p in flow_packets])
    sizes = np.array([p[1] for p in flow_packets])
    directions = np.array([p[2] for p in flow_packets])

    duration = max(times) - min(times) if len(times) > 1 else 1
    total_packets = len(sizes)
    total_bytes = sizes.sum()

    # Forward / Backward stats
    fwd_bytes = sizes[directions==1].sum() if (directions==1).any() else 0
    bwd_bytes = sizes[directions==0].sum() if (directions==0).any() else 0
    fwd_pkts = (directions==1).sum()
    bwd_pkts = (directions==0).sum()

    # Packet length stats
    mean_pkt_len = sizes.mean()
    std_pkt_len = sizes.std() if len(sizes) > 1 else 0
    max_pkt_len = sizes.max()
    min_pkt_len = sizes.min()

    # Inter-arrival times
    if len(times) > 1:
        iat = np.diff(times)
        mean_iat = iat.mean()
        std_iat = iat.std()
        max_iat = iat.max()
        min_iat = iat.min()
    else:
        mean_iat = std_iat = max_iat = min_iat = 0

    # Bytes / packets per sec
    bytes_per_sec = total_bytes / duration
    pkts_per_sec = total_packets / duration

    # Return dictionary of features
    return {
        "Flow Duration": duration,
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Fwd Packet Length Mean": mean_pkt_len,
        "Fwd Packet Length Std": std_pkt_len,
        "Fwd Packet Length Max": max_pkt_len,
        "Fwd Packet Length Min": min_pkt_len,
        "Bwd Packet Length Mean": mean_pkt_len,   # simplified
        "Bwd Packet Length Std": std_pkt_len,
        "Bwd Packet Length Max": max_pkt_len,
        "Bwd Packet Length Min": min_pkt_len,
        "Flow Bytes/s": bytes_per_sec,
        "Flow Packets/s": pkts_per_sec,
        "Mean IAT": mean_iat,
        "Std IAT": std_iat,
        "Max IAT": max_iat,
        "Min IAT": min_iat,
        "Fwd Packets/s": fwd_pkts/duration,
        "Bwd Packets/s": bwd_pkts/duration,
        "Packet Length Variance": std_pkt_len**2,
        "Packet Length Std": std_pkt_len,
        "Packet Length Max": max_pkt_len,
        "Packet Length Min": min_pkt_len,
        "Total Packets": total_packets
    }

"""####FIRST TIME RUN
#from scapy.all import sniff

#def packet_callback(packet):
 #   print(packet.summary())

#sniff(prn=packet_callback, count=20)

#####SECOND TIME RUN
from scapy.all import sniff
from feature_extractor import update_flow, flows, compute_features
from predictor import predict_flow

def packet_callback(packet):
    update_flow(packet)

    # After some packets, evaluate flows
    for fid, pkts in list(flows.items()):
        if len(pkts) > 20:  # enough packets to judge
            features = compute_features(pkts)
            result = predict_flow(features)
            print(f"[ALERT] Flow {fid} → {result}")
            flows.pop(fid)

sniff(prn=packet_callback)
"""
from scapy.all import sniff
from feature_extractor import update_flow, flows, compute_features
from predictor import predict_flow
import time

# How many packets per flow before evaluating
PACKETS_THRESHOLD = 20

# Store alert counts for demo/logging
alert_count = 0

def process_flows():
    global alert_count
    for flow_id, pkts in list(flows.items()):
        if len(pkts) >= PACKETS_THRESHOLD:
            features = compute_features(pkts)
            result = predict_flow(features)

            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f"[{timestamp}] [ALERT #{alert_count+1}] Flow {flow_id} → {result}")

            # Increment alert counter
            alert_count += 1

            # Remove processed flow to save memory
            flows.pop(flow_id)

def packet_callback(pkt):
    # Update flow with packet
    update_flow(pkt)
    # Check and process flows
    process_flows()

if __name__ == "__main__":
    print("=== ML NIDS started! Press Ctrl+C to stop ===")
    sniff(prn=packet_callback)

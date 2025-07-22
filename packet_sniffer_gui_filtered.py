import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
import threading
import csv

# Globals
sniffing = False
captured_packets = []
displayed_data = []

def matches_filter(packet, proto_filter, ip_filter):
    if not IP in packet:
        return False

    ip_layer = packet[IP]
    proto_match = (
        (proto_filter == "ALL") or
        (proto_filter == "TCP" and TCP in packet) or
        (proto_filter == "UDP" and UDP in packet) or
        (proto_filter == "ICMP" and ICMP in packet)
    )
    
    ip_match = (
        not ip_filter or
        ip_filter == ip_layer.src or
        ip_filter == ip_layer.dst
    )
    
    return proto_match and ip_match

def process_packet(packet):
    global captured_packets
    proto_filter = proto_var.get()
    ip_filter = ip_entry.get().strip()

    if matches_filter(packet, proto_filter, ip_filter):
        captured_packets.append(packet)
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"
        pkt = {
            "Source": packet[IP].src,
            "Destination": packet[IP].dst,
            "Protocol": proto
        }
        displayed_data.append(pkt)
        output.insert(tk.END, f"{pkt['Source']} -> {pkt['Destination']} | Protocol: {pkt['Protocol']}\n")
        output.see(tk.END)

def start_sniffing():
    global sniffing
    sniffing = True
    status_label.config(text="Sniffing started...")
    sniff(prn=process_packet, store=False, stop_filter=lambda x: not sniffing)

def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Sniffing stopped.")

def start_thread():
    threading.Thread(target=start_sniffing, daemon=True).start()

def save_csv():
    if not displayed_data:
        messagebox.showinfo("No Data", "No packets to save.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if file_path:
        with open(file_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["Source", "Destination", "Protocol"])
            writer.writeheader()
            writer.writerows(displayed_data)
        messagebox.showinfo("Saved", f"Saved to {file_path}")

def save_pcap():
    if not captured_packets:
        messagebox.showinfo("No Data", "No packets to save.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        wrpcap(file_path, captured_packets)
        messagebox.showinfo("Saved", f"Saved to {file_path}")

# GUI
window = tk.Tk()
window.title("Packet Sniffer with Filters")
window.geometry("850x600")

# Filter UI
filter_frame = tk.Frame(window)
filter_frame.pack(pady=10)

tk.Label(filter_frame, text="Protocol:").grid(row=0, column=0, padx=5)
proto_var = tk.StringVar(value="ALL")
tk.OptionMenu(filter_frame, proto_var, "ALL", "TCP", "UDP", "ICMP").grid(row=0, column=1, padx=5)

tk.Label(filter_frame, text="IP Filter (Src/Dst):").grid(row=0, column=2, padx=5)
ip_entry = tk.Entry(filter_frame)
ip_entry.grid(row=0, column=3, padx=5)

# Buttons
tk.Button(window, text="Start Sniffing", command=start_thread, width=20).pack(pady=5)
tk.Button(window, text="Stop Sniffing", command=stop_sniffing, width=20).pack(pady=5)
tk.Button(window, text="Save to CSV", command=save_csv, width=20).pack(pady=5)
tk.Button(window, text="Save to PCAP", command=save_pcap, width=20).pack(pady=5)

# Status and Output
status_label = tk.Label(window, text="Status: Idle")
status_label.pack()

output = tk.Text(window, height=20)
output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

window.mainloop()
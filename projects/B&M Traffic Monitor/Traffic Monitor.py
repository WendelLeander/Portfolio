# NSS Project by: Wendel Walter A. Leander
# Version 1.0
# Python 3.13.9 & pip 25.2

import customtkinter as ctk
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, Ether, IP, IPv6, rdpcap
from scapy.arch.windows import get_windows_if_list
from ipaddress import ip_address
import threading, time, csv, os
from collections import Counter, defaultdict
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import webbrowser
import sys

# For Pyinstaller (Logo Embedding)
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # PyInstaller sets this temp folder at runtime
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Checks if a given MAC address is the broadcast MAC address.
def is_broadcast_mac(mac: str) -> bool:
    return mac.lower() == "ff:ff:ff:ff:ff:ff"
# Determines whether a given address (MAC or IP) is a multicast address.
def is_multicast_addr(addr: str) -> bool:
    try:
        if ":" in addr:
            first_octet = int(addr.split(":")[0], 16)
            return (first_octet & 1) == 1 and not is_broadcast_mac(addr)
        else:
            ip = ip_address(addr)
            return ip.is_multicast
    except Exception:
        return False

# Tool GUI
class MonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("Light")
        ctk.set_default_color_theme("blue")
        self.appearance_mode = "Light"
        self.title("B&M Traffic Monitor (Light Mode)")
        self.iconbitmap(resource_path("M.ico"))
        self.geometry("1200x800")

        # Capture state
        self.stop_event = threading.Event()
        self.capture_thread = None

        # Counters and data
        self.packet_counts = Counter()
        self.src_mac_counter = Counter()
        self.dst_mac_counter = Counter()
        self.bcast_mcast_senders = Counter()
        self.bm_types = {}  # store type per MAC for highlighting
        self.size_bins = Counter()
        self.timestamps = []

        # GUI layout
        self._build_ui()
        # Show npcap warning on startup
        self.after(500, self._show_npcap_warning)

    def _show_npcap_warning(self):
        warning_win = tk.Toplevel(self)
        warning_win.title("Npcap Required")
        warning_win.attributes("-topmost", True)
        warning_win.resizable(False, False)

        # Main message
        msg = (
            "⚠️ Npcap (or WinPcap) is required for this tool to work properly.\n\n"
            "To use live capture mode, please install Npcap:\n"
        )

        # Main message label
        ctk.CTkLabel(
            warning_win,
            text=msg,
            wraplength=380,
            justify="left",
            anchor="w"
        ).pack(padx=20, pady=(20, 5), anchor="w")

        # Clickable link
        link_label = tk.Label(
            warning_win,
            text="https://npcap.com/#download",
            fg="blue",
            cursor="hand2",
            font=("Segoe UI", 12, "underline")
        )
        link_label.pack(padx=20, anchor="w")

        def open_link(event):
            webbrowser.open("https://npcap.com/#download")

        link_label.bind("<Button-1>", open_link)

        # Larger "Without it..." text
        label = tk.Label(
            warning_win,
            text="Without it, you may see the error:",
            font=("Segoe UI", 12, "bold"),  # slightly larger + bold
            justify="left",
            anchor="w",
            wraplength=380
        )
        label.pack(padx=20, pady=(15, 2), anchor="w")  # smaller gap above, very small below

        # Red error message (closer to the line above)
        red_label = tk.Label(
            warning_win,
            text="Sniffing and sending packets is not available at layer 2.",
            fg="red",
            font=("Segoe UI", 12),
            justify="left",
            anchor="w",
            wraplength=380
        )
        red_label.pack(padx=20, pady=(0, 5), anchor="w")  # no big top padding → brings it closer

        # OK button
        ctk.CTkButton(
            warning_win,
            text="OK, Got It",
            command=warning_win.destroy,
            width=100
        ).pack(pady=(10, 15))

        warning_win.update_idletasks()

    def _build_ui(self):
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(side="top", fill="x", padx=8, pady=8)

        self.toggle_button = ctk.CTkButton(top_frame, text="Dark Mode 🌙", width=120, command=self._toggle_mode)
        self.toggle_button.pack(side="left", padx=(6, 8))

        ctk.CTkLabel(top_frame, text="Mode:").pack(side="left", padx=(6, 4))
        self.mode_var = tk.StringVar(value="Live")
        self.mode_combo = ttk.Combobox(top_frame, textvariable=self.mode_var, values=["Live", "PCAP"], width=12, state="readonly")
        self.mode_combo.pack(side="left", padx=4)
        self.mode_combo.bind("<<ComboboxSelected>>", lambda e: self._render_config_panel())

        self.config_frame = ctk.CTkFrame(self)
        self.config_frame.pack(side="top", fill="x", padx=8)
        self._render_config_panel()

        self.start_button = ctk.CTkButton(top_frame, text="Start Capture", width=140, command=self.start_capture)
        self.start_button.pack(side="right", padx=6)
        self.cancel_button = ctk.CTkButton(top_frame, text="Cancel", width=120, command=self.cancel_capture, state="disabled")
        self.cancel_button.pack(side="right", padx=6)

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate", variable=self.progress_var)
        self.progress.pack(fill="x", padx=10, pady=(8, 4))

        middle_frame = ctk.CTkFrame(self)
        middle_frame.pack(fill="both", expand=False, padx=8, pady=4)

        # Log area
        log_frame = ctk.CTkFrame(middle_frame)
        log_frame.pack(side="left", fill="both", expand=True, padx=(0, 6))
        ctk.CTkLabel(log_frame, text="Live Log:").pack(anchor="w", padx=6, pady=(6, 0))
        self.log_text = tk.Text(log_frame, height=20, wrap="none", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        ysb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        ysb.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=ysb.set)

        # Stats area
        stats_frame = ctk.CTkFrame(middle_frame, width=420)
        stats_frame.pack(side="right", fill="y", padx=(6, 0))
        ctk.CTkLabel(stats_frame, text="Traffic Summary").pack(anchor="w", padx=8, pady=(6, 2))
        self.summary_text = tk.Text(stats_frame, height=6, state="disabled")
        self.summary_text.pack(fill="x", padx=8)
        self.fig = plt.Figure(figsize=(3.4, 2.6), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.pie_canvas = FigureCanvasTkAgg(self.fig, master=stats_frame)
        self.pie_canvas.get_tk_widget().pack(padx=8, pady=6)

        bottom_frame = ctk.CTkFrame(self)
        bottom_frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        # Scrollable tables container
        tables_outer_frame = ctk.CTkFrame(bottom_frame)
        tables_outer_frame.pack(side="left", fill="both", expand=True, padx=(0, 6))

        canvas = tk.Canvas(tables_outer_frame, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(tables_outer_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        scrollable_frame = ctk.CTkFrame(canvas)
        window_id = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        def _on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def _on_canvas_configure(event):
            canvas.itemconfig(window_id, width=event.width)
        scrollable_frame.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        # Top Source MACs
        ctk.CTkLabel(scrollable_frame, text="Top Source MACs").pack(anchor="w", padx=6, pady=(6, 0))
        self.src_tree = ttk.Treeview(scrollable_frame, columns=("mac", "count"), show="headings", height=5)
        for col in ("mac", "count"):
            self.src_tree.heading(col, text=col.title())
            self.src_tree.column(col, anchor="center", width=150)
        self.src_tree.pack(fill="x", padx=6, pady=(0, 6))

        # Top Destination MACs
        ctk.CTkLabel(scrollable_frame, text="Top Destination MACs").pack(anchor="w", padx=6)
        self.dst_tree = ttk.Treeview(scrollable_frame, columns=("mac", "count"), show="headings", height=5)
        for col in ("mac", "count"):
            self.dst_tree.heading(col, text=col.title())
            self.dst_tree.column(col, anchor="center", width=150)
        self.dst_tree.pack(fill="x", padx=6, pady=(0, 6))

        # Top Broadcast/Multicast Senders
        ctk.CTkLabel(scrollable_frame, text="Top Broadcast/Multicast Senders").pack(anchor="w", padx=6)
        self.bm_tree = ttk.Treeview(scrollable_frame, columns=("mac", "count", "type"), show="headings", height=5)
        for col in ("mac", "count", "type"):
            self.bm_tree.heading(col, text=col.title())
            self.bm_tree.column(col, anchor="center", width=100)
        self.bm_tree.pack(fill="x", padx=6, pady=(0, 6))

        charts_frame = ctk.CTkFrame(bottom_frame, width=420)
        charts_frame.pack(side="right", fill="both", expand=False, padx=(6, 0))
        ctk.CTkLabel(charts_frame, text="Frame Size Distribution").pack(anchor="w", padx=6, pady=(6, 0))
        self.size_fig = plt.Figure(figsize=(4.5, 2.5), dpi=100)
        self.size_ax = self.size_fig.add_subplot(111)
        self.size_canvas = FigureCanvasTkAgg(self.size_fig, master=charts_frame)
        self.size_canvas.get_tk_widget().pack(padx=6, pady=(0, 6))

        self.view_graphs_btn = ctk.CTkButton(charts_frame, text="View Frame Rate Graph", command=self._open_frame_rate_window)
        self.view_graphs_btn.pack(padx=6, pady=6, anchor="s")

        self.export_btn = ctk.CTkButton(charts_frame, text="Export CSV Summary", command=self._export_csv)
        self.export_btn.pack(padx=6, pady=(2, 10), anchor="s")

    # Light/Dark toggle
    def _toggle_mode(self):
        if self.appearance_mode == "Light":
            ctk.set_appearance_mode("Dark")
            self.title("B&M Traffic Monitor (Dark Mode)")
            self.toggle_button.configure(text="Light Mode ☀️")
            self.appearance_mode = "Dark"
        else:
            ctk.set_appearance_mode("Light")
            self.title("B&M Traffic Monitor (Light Mode)")
            self.toggle_button.configure(text="Dark Mode 🌙")
            self.appearance_mode = "Light"

    def _render_config_panel(self):
        for w in self.config_frame.winfo_children():
            w.destroy()
        mode = self.mode_var.get()
        padx = 6
        if mode == "Live":
            ctk.CTkLabel(self.config_frame, text="Interface:").pack(side="left", padx=padx, pady=6)
            interfaces = [iface['name'] for iface in get_windows_if_list()]
            self.iface_var = tk.StringVar(value=interfaces[0] if interfaces else "")
            iface_combo = ttk.Combobox(self.config_frame, textvariable=self.iface_var, values=interfaces, width=30)
            iface_combo.pack(side="left", padx=padx, pady=6)
        else:
            ctk.CTkLabel(self.config_frame, text="PCAP File:").pack(side="left", padx=padx, pady=6)
            self.pcap_path = tk.StringVar()
            entry = ctk.CTkEntry(self.config_frame, textvariable=self.pcap_path, width=420)
            entry.pack(side="left", padx=padx, pady=6)
            ctk.CTkButton(self.config_frame, text="Browse", command=self._browse_pcap).pack(side="left", padx=padx, pady=6)

        ctk.CTkLabel(self.config_frame, text="Count:").pack(side="left", padx=padx)
        self.count_var = tk.StringVar(value="500")
        ctk.CTkEntry(self.config_frame, textvariable=self.count_var, width=80).pack(side="left", padx=padx)

        ctk.CTkLabel(self.config_frame, text="Timeout (s):").pack(side="left", padx=padx)
        self.timeout_var = tk.StringVar(value="30")
        ctk.CTkEntry(self.config_frame, textvariable=self.timeout_var, width=80).pack(side="left", padx=padx)

    def _log(self, msg: str):
        def inner():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", msg + "\n")
            self.log_text.configure(state="disabled")
            self.log_text.see("end")
        self.after(0, inner)

    # Select PCAP File
    def _browse_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap;*.pcapng")])
        if path:
            self.pcap_path.set(path)

    # Start Capture
    def start_capture(self):
        if self.capture_thread and self.capture_thread.is_alive():
            messagebox.showinfo("Capture running", "A capture is already running.")
            return
        self.packet_counts.clear()
        self.src_mac_counter.clear()
        self.dst_mac_counter.clear()
        self.bcast_mcast_senders.clear()
        self.bm_types.clear()
        self.size_bins.clear()
        self.timestamps.clear()
        self._clear_log()
        self.progress_var.set(0)
        self._update_summary_and_charts()
        self.stop_event.clear()
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")

        mode = self.mode_var.get()
        count = max(1, int(self.count_var.get() or 1))
        timeout = max(1, int(self.timeout_var.get() or 1))

        self.capture_thread = threading.Thread(target=self._capture_worker, args=(mode, count, timeout), daemon=True)
        self.capture_thread.start()

    def cancel_capture(self):
        self.stop_event.set()
        self._log("User requested cancel...")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _capture_worker(self, mode, count, timeout):
        start_time = time.time()
        try:
            if mode == "PCAP":
                path = getattr(self, "pcap_path", None)
                file_path = path.get() if path else ""
                if not file_path or not os.path.exists(file_path):
                    self._log("No PCAP selected.")
                    self.stop_event.set()
                else:
                    packets = rdpcap(file_path)
                    total = len(packets)
                    for idx, pkt in enumerate(packets[:count], start=1):
                        if self.stop_event.is_set():
                            break
                        self._handle_packet(pkt)
                        self.progress_var.set((idx / min(total, count)) * 100)
                        time.sleep(0.0005)
            else:
                iface = getattr(self, "iface_var", None)
                iface_name = iface.get() if iface else ""
                if not iface_name:
                    self._log("No interface selected.")
                    self.stop_event.set()
                else:
                    def prn(pkt):
                        self._handle_packet(pkt)
                        elapsed = time.time() - start_time
                        time_ratio = min(elapsed / timeout, 1.0)
                        count_ratio = min(self.packet_counts["total"] / count, 1.0)
                        progress = (time_ratio * 50.0) + (count_ratio * 50.0)
                        self.progress_var.set(progress)
                        if elapsed >= timeout or self.packet_counts["total"] >= count or self.stop_event.is_set():
                            self.stop_event.set()

                    sniff(iface=iface_name, prn=prn, store=False, timeout=timeout, count=count,
                          stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            self._log(f"Capture error: {e}")
        finally:
            self.progress_var.set(100.0)
            self._update_summary_and_charts()
            self.after(0, lambda: [self.start_button.configure(state="normal"),
                                   self.cancel_button.configure(state="disabled")])
    # Live log
    def _handle_packet(self, pkt):
        if not pkt or not pkt.haslayer(Ether):
            return
        dst_mac = pkt[Ether].dst
        src_mac = pkt[Ether].src

        protocol = ""
        if pkt.haslayer("ARP"):
            protocol = "ARP"
        elif pkt.haslayer("DHCP"):
            protocol = "DHCP"
        elif pkt.haslayer("DNS") and ("224.0.0.251" in pkt.summary() or "5353" in pkt.summary()):
            protocol = "mDNS"
        elif pkt.haslayer("UDP") and (pkt["UDP"].sport == 1900 or pkt["UDP"].dport == 1900):
            protocol = "SSDP"

        if is_broadcast_mac(dst_mac):
            self.packet_counts["broadcast"] += 1
            self.bcast_mcast_senders[src_mac] += 1
            self.bm_types[src_mac] = "broadcast"
            label = f"[BROADCAST] {pkt.summary()}"
            if protocol:
                label += f" | {protocol}"
            self._log(label)

        elif is_multicast_addr(dst_mac) or (pkt.haslayer(IP) and is_multicast_addr(pkt[IP].dst)):
            self.packet_counts["multicast"] += 1
            self.bcast_mcast_senders[src_mac] += 1
            self.bm_types[src_mac] = "multicast"
            label = f"[MULTICAST] {pkt.summary()}"
            if protocol:
                label += f" | {protocol}"
            self._log(label)

        else:
            self.packet_counts["unicast"] += 1

        self.packet_counts["total"] += 1
        self.src_mac_counter[src_mac] += 1
        self.dst_mac_counter[dst_mac] += 1

        raw_len = len(pkt)
        if raw_len < 64:
            self.size_bins["small"] += 1
        elif raw_len <= 512:
            self.size_bins["normal"] += 1
        else:
            self.size_bins["large"] += 1

        self.timestamps.append(time.time())
        if self.packet_counts["total"] % 10 == 0:
            self._update_summary_and_charts()

    # Outputs
    def _update_summary_and_charts(self):
        def inner():
            total = self.packet_counts.get("total", 0)
            b = self.packet_counts.get("broadcast", 0)
            m = self.packet_counts.get("multicast", 0)
            u = self.packet_counts.get("unicast", 0)
            summary = f"Total Frames: {total}\nBroadcast: {b}\nMulticast: {m}\nUnicast: {u}" if total else "No frames yet."
            self.summary_text.configure(state="normal")
            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("end", summary)
            self.summary_text.configure(state="disabled")

            self.ax.clear()
            if total:
                self.ax.pie([b, m, u], labels=["Broadcast", "Multicast", "Unicast"], autopct="%1.1f%%")
            self.ax.set_title("Frame Type Distribution")
            self.pie_canvas.draw()

            self.size_ax.clear()
            bins = ["<64B", "64–512B", ">512B"]
            vals = [self.size_bins.get("small", 0),
                    self.size_bins.get("normal", 0),
                    self.size_bins.get("large", 0)]
            self.size_ax.bar(bins, vals)
            self.size_ax.set_ylabel("Frames")
            self.size_ax.set_title("Frame Size Distribution")
            self.size_canvas.draw()

            for tree, counter in [(self.src_tree, self.src_mac_counter),
                                  (self.dst_tree, self.dst_mac_counter)]:
                for row in tree.get_children():
                    tree.delete(row)
                for mac, cnt in counter.most_common(10):
                    tree.insert("", "end", values=(mac, cnt))

            for row in self.bm_tree.get_children():
                self.bm_tree.delete(row)
            for mac, cnt in self.bcast_mcast_senders.most_common(10):
                t = self.bm_types.get(mac, "unknown")
                tag = "broadcast" if t == "broadcast" else "multicast"
                self.bm_tree.insert("", "end", values=(mac, cnt, t.title()), tags=(tag,))
        self.after(0, inner)

    def _open_frame_rate_window(self):
        if not self.timestamps:
            messagebox.showinfo("Frame Rate", "No data yet.")
            return
        win = tk.Toplevel(self)
        win.title("Frame Rate Over Time")
        fig = plt.Figure(figsize=(6, 3), dpi=100)
        ax = fig.add_subplot(111)
        t0 = self.timestamps[0]
        rel_times = [t - t0 for t in self.timestamps]
        bins = defaultdict(int)
        for t in rel_times:
            bins[int(t)] += 1
        ax.plot(list(bins.keys()), list(bins.values()), marker="o")
        ax.set_xlabel("Seconds")
        ax.set_ylabel("Frames/s")
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.get_tk_widget().pack(fill="both", expand=True)
        canvas.draw()

    # Export Outputs to CSV
    def _export_csv(self):
        if not self.packet_counts:
            messagebox.showinfo("Export", "No data to export.")
            return
        try:
            from datetime import datetime
            date_str = datetime.now().strftime("%m_%d_%Y_%H-%M-%S")
            filename = f"monitor_summary_{date_str}.csv"

            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Metric", "Value"])
                for key, val in self.packet_counts.items():
                    writer.writerow([key, val])
                writer.writerow([])
                writer.writerow(["Top Source MACs"])
                writer.writerow(["MAC", "Count"])
                for mac, cnt in self.src_mac_counter.most_common(10):
                    writer.writerow([mac, cnt])
                writer.writerow([])
                writer.writerow(["Top Destination MACs"])
                writer.writerow(["MAC", "Count"])
                for mac, cnt in self.dst_mac_counter.most_common(10):
                    writer.writerow([mac, cnt])
                writer.writerow([])
                writer.writerow(["Top Broadcast/Multicast Senders"])
                writer.writerow(["MAC", "Count", "Type"])
                for mac, cnt in self.bcast_mcast_senders.most_common(10):
                    writer.writerow([mac, cnt, self.bm_types.get(mac, "unknown")])

            messagebox.showinfo("Export Complete", f"Summary saved to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


if __name__ == "__main__":
    app = MonitorApp()
    app.mainloop()

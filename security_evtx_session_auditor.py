import sys
import ctypes
import os
import threading
import tkinter as tk
from tkinter import messagebox, filedialog
from tkcalendar import DateEntry
import csv
from evtx import PyEvtxParser  # Updated import: use capitalized Evtx module
from lxml import etree  # for fast XML parsing
import datetime

# --- Admin Check Code ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if not is_admin():
    script = os.path.abspath(__file__)
    params = " ".join([script] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)
# --- End Admin Check ---

def log_message(msg):
    """Log a message to the GUI text widget in a thread-safe manner."""
    root.after(0, lambda: output_text.insert(tk.END, msg + "\n"))

def parse_evtx_time(time_str):
    """
    Parse a SystemTime string from the EVTX file into a datetime object.
    The expected format is ISO 8601, e.g.:
       2023-06-12T13:45:10.123456Z
    We'll replace the trailing 'Z' with '+00:00' so that fromisoformat() works.
    """
    if time_str.endswith("Z"):
        time_str = time_str.replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(time_str)
    except Exception as e:
        log_message(f"Failed to parse time '{time_str}': {e}")
        return None

def process_logs_background(evtx_file, action_time, csv_filename="output.csv"):
    """
    Process the EVTX file and extract login and logout events.

    For login events (EventID 4624), we keep events whose SystemTime is before the action time.
    For logout events (EventID 4634 or 4647), we keep events whose SystemTime is after the action time.
    
    All events are collected first (Phase 1) and then correlated (Phase 2) so that a logout event 
    encountered before its corresponding login event is still available for correlation.
    """
    log_message("Starting EVTX processing...")

    # Phase 1: Collect events
    login_events = []   # List of dicts: { "target_logon_id", "target_user", "target_domain", "login_time" }
    logout_events = {}  # Dict mapping target_logon_id -> logout_time (as a datetime)

    # Precompile XPath queries.
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    xpath_event_id = etree.XPath(".//ns:EventID", namespaces=ns)
    xpath_time_created = etree.XPath(".//ns:TimeCreated", namespaces=ns)
    xpath_tli = etree.XPath(".//ns:Data[@Name='TargetLogonId']", namespaces=ns)
    xpath_user = etree.XPath(".//ns:Data[@Name='TargetUserName']", namespaces=ns)
    xpath_domain = etree.XPath(".//ns:Data[@Name='TargetDomainName']", namespaces=ns)

    records_processed = 0

    try:
        parser = PyEvtxParser(evtx_file)
        for record in parser.records():
            records_processed += 1
            if records_processed % 5000 == 0:
                log_message(f"Processed {records_processed} records...")

            xml_str = record['data']
            try:
                root_xml = etree.fromstring(xml_str.encode('utf-8'))
            except Exception:
                continue

            event_id_elements = xpath_event_id(root_xml)
            if not event_id_elements:
                continue
            event_id = event_id_elements[0].text
            if event_id not in ["4624", "4634", "4647"]:
                continue

            time_created_elements = xpath_time_created(root_xml)
            if not time_created_elements:
                continue
            event_time_str = time_created_elements[0].get("SystemTime")
            if not event_time_str:
                continue

            # Convert the event time to a datetime object.
            ev_time = parse_evtx_time(event_time_str)
            if ev_time is None:
                continue

            # Process login events (EventID 4624)
            if event_id == "4624":
                # Only consider logins that occurred before the action time.
                if ev_time < action_time:
                    tli_elements = xpath_tli(root_xml)
                    if not tli_elements:
                        continue
                    target_logon_id = tli_elements[0].text
                    if not target_logon_id or target_logon_id == "0x3e7":
                        continue
                    user_elements = xpath_user(root_xml)
                    target_user = user_elements[0].text if user_elements else ""
                    domain_elements = xpath_domain(root_xml)
                    target_domain = domain_elements[0].text if domain_elements else ""
                    login_events.append({
                        "target_logon_id": target_logon_id,
                        "target_user": target_user,
                        "target_domain": target_domain,
                        "login_time": ev_time  # store as datetime
                    })
            # Process logout events (EventID 4634 or 4647)
            elif event_id in ["4634", "4647"]:
                # Only consider logouts that occurred after the action time.
                if ev_time > action_time:
                    tli_elements = xpath_tli(root_xml)
                    if not tli_elements:
                        continue
                    target_logon_id = tli_elements[0].text
                    if not target_logon_id:
                        continue
                    # If multiple logout events occur for the same logon id, keep the earliest logout time.
                    if target_logon_id in logout_events:
                        if ev_time < logout_events[target_logon_id]:
                            logout_events[target_logon_id] = ev_time
                    else:
                        logout_events[target_logon_id] = ev_time
        log_message("Finished processing records.")
    except Exception as e:
        root.after(0, lambda: messagebox.showerror("Error", f"Error processing records:\n{e}"))
        return

    log_message(f"Total records processed: {records_processed}")
    log_message(f"Total login events found: {len(login_events)}")

    # Phase 2: Correlate events and write to CSV.
    try:
        with open(csv_filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["TargetLogonId", "TargetUserName", "TargetDomainName", "Login Time (UTC)", "Logout Time (UTC)"])
            for login in login_events:
                tid = login["target_logon_id"]
                # Only output sessions that have a corresponding logout event.
                if tid not in logout_events:
                    continue  
                row = [
                    tid,
                    login["target_user"],
                    login["target_domain"],
                    login["login_time"].isoformat(),
                    logout_events[tid].isoformat()
                ]
                writer.writerow(row)
        log_message("CSV file written successfully.")
    except Exception as e:
        root.after(0, lambda: messagebox.showerror("CSV Error", f"Error writing CSV file:\n{e}"))
        return

    # Build a summary of correlated sessions.
    summary = "\nRelated login sessions (UTC):\n"
    for login in login_events:
        tid = login["target_logon_id"]
        if tid not in logout_events:
            continue
        summary += (f"TargetLogonId: {tid}, "
                    f"TargetUserName: {login['target_user']}, "
                    f"TargetDomainName: {login['target_domain']}, "
                    f"Login Time: {login['login_time'].isoformat()}, "
                    f"Logout Time: {logout_events[tid].isoformat()}\n")
    
    root.after(0, lambda: output_text.insert(tk.END, summary + f"\nProcessing complete. Output written to {csv_filename}\n"))

def start_processing():
    try:
        hour = int(hour_spin.get())
        minute = int(minute_spin.get())
        second = int(second_spin.get())
    except ValueError:
        messagebox.showerror("Invalid Time", "Enter valid numeric time values.")
        return

    selected_date = date_entry.get_date()
    # Combine selected date and time (assume UTC)
    action_time = datetime.datetime.combine(
        selected_date,
        datetime.time(hour, minute, second, tzinfo=datetime.timezone.utc)
    )
    evtx_file = entry_file.get().strip()
    if not evtx_file:
        messagebox.showerror("Missing File", "Please specify the location of the security.evtx file.")
        return

    output_text.delete("1.0", tk.END)
    log_message("Processing logs...")
    threading.Thread(target=process_logs_background, args=(evtx_file, action_time), daemon=True).start()

def browse_file():
    path = filedialog.askopenfilename(
        title="Select security.evtx file",
        filetypes=[("EVTX files", "*.evtx"), ("All files", "*.*")]
    )
    if path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, path)

# --- Tkinter GUI Setup ---
root = tk.Tk()
root.title("Security EVTX Session Auditor (Optimized)")

main_frame = tk.Frame(root, padx=10, pady=10)
main_frame.pack(fill=tk.BOTH, expand=True)

file_frame = tk.Frame(main_frame)
file_frame.pack(anchor=tk.W, pady=5, fill=tk.X)
tk.Label(file_frame, text="Security EVTX File:").pack(side=tk.LEFT)
entry_file = tk.Entry(file_frame, width=50)
entry_file.pack(side=tk.LEFT, padx=5)
tk.Button(file_frame, text="Browse", command=browse_file).pack(side=tk.LEFT)

date_time_frame = tk.Frame(main_frame)
date_time_frame.pack(anchor=tk.W, pady=10, fill=tk.X)
tk.Label(date_time_frame, text="Date:").pack(side=tk.LEFT, padx=(0,5))
date_entry = DateEntry(date_time_frame, date_pattern="yyyy-mm-dd")
date_entry.pack(side=tk.LEFT, padx=(0,20))
time_frame = tk.Frame(date_time_frame)
time_frame.pack(side=tk.LEFT)
tk.Label(time_frame, text="Hour:").pack(side=tk.LEFT)
hour_spin = tk.Spinbox(time_frame, from_=0, to=23, width=3, format="%02.0f")
hour_spin.pack(side=tk.LEFT, padx=(0,5))
tk.Label(time_frame, text="Minute:").pack(side=tk.LEFT)
minute_spin = tk.Spinbox(time_frame, from_=0, to=59, width=3, format="%02.0f")
minute_spin.pack(side=tk.LEFT, padx=(0,5))
tk.Label(time_frame, text="Second:").pack(side=tk.LEFT)
second_spin = tk.Spinbox(time_frame, from_=0, to=59, width=3, format="%02.0f")
second_spin.pack(side=tk.LEFT)

tk.Button(main_frame, text="Process", command=start_processing).pack(anchor=tk.W, pady=5)
output_text = tk.Text(main_frame, wrap=tk.NONE, width=80, height=20)
output_text.pack(pady=10)

root.mainloop()

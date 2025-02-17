from flask import Flask, request, render_template, jsonify, send_file
import os
import datetime
import csv
from evtx import PyEvtxParser
from lxml import etree
import sys
import threading
import webbrowser

app = Flask(__name__)

bundle_dir = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
path_to_help = os.path.abspath(os.path.join(bundle_dir, "uploads"))
UPLOAD_FOLDER = path_to_help
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

results_cache = {}


def parse_evtx_time(time_str):
    try:
        if time_str.endswith("Z"):
            time_str = time_str.replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(time_str)
    except Exception:
        return None


def process_logs(evtx_path, action_time):
    login_events = []
    logout_events = {}
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    xpath_event_id = etree.XPath(".//ns:EventID", namespaces=ns)
    xpath_time_created = etree.XPath(".//ns:TimeCreated", namespaces=ns)
    xpath_tli = etree.XPath(".//ns:Data[@Name='TargetLogonId']", namespaces=ns)
    xpath_user = etree.XPath(".//ns:Data[@Name='TargetUserName']", namespaces=ns)
    xpath_domain = etree.XPath(".//ns:Data[@Name='TargetDomainName']", namespaces=ns)
    xpath_computer = etree.XPath(".//ns:Computer", namespaces=ns)
    xpath_logon_type = etree.XPath(".//ns:Data[@Name='LogonType']", namespaces=ns)
    xpath_ip_address = etree.XPath(".//ns:Data[@Name='IpAddress']", namespaces=ns)
    xpath_ip_port = etree.XPath(".//ns:Data[@Name='IpPort']", namespaces=ns)

    parser = PyEvtxParser(evtx_path)
    for record in parser.records():
        xml_str = record["data"]
        try:
            root_xml = etree.fromstring(xml_str.encode("utf-8"))
        except Exception:
            continue

        event_id_elements = xpath_event_id(root_xml)
        event_id = event_id_elements[0].text
        if event_id not in ("4624", "4634", "4647"):
            continue

        time_created_elements = xpath_time_created(root_xml)
        event_time_str = time_created_elements[0].get("SystemTime")
        ev_time = parse_evtx_time(event_time_str)
        if ev_time is None:
            continue

        if event_id == "4624" and ev_time < action_time:
            tli_elements = xpath_tli(root_xml)
            target_logon_id = tli_elements[0].text
            if not target_logon_id or target_logon_id in ["0x3e4", "0x3e5", "0x3e7"]:
                continue
            user_elements = xpath_user(root_xml)
            target_user = user_elements[0].text if user_elements else ""
            if target_user.startswith("DWM-") or target_user.startswith("UMFD-"):
                continue
            domain_elements = xpath_domain(root_xml)
            target_domain = domain_elements[0].text if domain_elements else ""
            computer_elements = xpath_computer(root_xml)
            computer_name = computer_elements[0].text if computer_elements else ""
            logon_type_elements = xpath_logon_type(root_xml)
            logon_type = logon_type_elements[0].text if logon_type_elements else ""
            ip_address_elements = xpath_ip_address(root_xml)
            ip_address = ip_address_elements[0].text if ip_address_elements else ""
            ip_port_elements = xpath_ip_port(root_xml)
            ip_port = ip_port_elements[0].text if ip_port_elements else ""

            login_events.append(
                {
                    "target_logon_id": target_logon_id,
                    "target_user": target_user,
                    "target_domain": target_domain,
                    "computer_name": computer_name,
                    "logon_type": logon_type,
                    "ip_address": ip_address,
                    "ip_port": ip_port,
                    "login_time": ev_time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

        # Process logoff events
        elif event_id in ("4634", "4647") and ev_time > action_time:
            tli_elements = xpath_tli(root_xml)
            if not tli_elements:
                continue
            target_logon_id = tli_elements[0].text
            if not target_logon_id:
                continue
            if target_logon_id in logout_events:
                # Update if this logout is earlier than the stored one
                if ev_time < parse_evtx_time(logout_events[target_logon_id]):
                    logout_events[target_logon_id] = ev_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            else:
                logout_events[target_logon_id] = ev_time.strftime("%Y-%m-%d %H:%M:%S")

    output_csv = os.path.join(UPLOAD_FOLDER, "output.csv")
    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            (
                "TargetLogonId",
                "TargetUserName",
                "TargetDomainName",
                "ComputerName",
                "LogonType",
                "IpAddress",
                "IpPort",
                "Login Time (UTC)",
                "Logout Time (UTC)",
                "Session Length",
            )
        )
        for login in login_events:
            tid = login["target_logon_id"]
            logout_time = logout_events.get(tid, "N/A")
            session_length = "N/A"
            if logout_time != "N/A":
                login_time_obj = parse_evtx_time(login["login_time"])
                logout_time_obj = parse_evtx_time(logout_time)
                if login_time_obj and logout_time_obj:
                    session_length = str(logout_time_obj - login_time_obj)
            else:
                continue
            writer.writerow(
                [
                    tid,
                    login["target_user"],
                    login["target_domain"],
                    login["computer_name"],
                    login["logon_type"],
                    login["ip_address"],
                    login["ip_port"],
                    login["login_time"],
                    logout_time,
                    session_length,
                ]
            )
    return output_csv, login_events


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/process", methods=["POST"])
def process():
    file = request.files["evtx_file"]
    filename = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filename)
    date = request.form.get("date")
    time_str = request.form.get("time")
    action_time = datetime.datetime.strptime(
        f"{date} {time_str}", "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=datetime.timezone.utc)
    output_file, results = process_logs(filename, action_time)
    results_cache[f"{date} {time_str}"] = results
    return jsonify({"date": date, "time": time_str})


@app.route("/results", methods=["GET"])
def results():
    date = request.args.get("date")
    time_str = request.args.get("time")
    output_csv = os.path.join(UPLOAD_FOLDER, "output.csv")
    results_list = []
    if os.path.exists(output_csv):
        with open(output_csv, "r") as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            for row in reader:
                results_list.append(
                    {
                        "target_logon_id": row[0],
                        "target_user": row[1],
                        "target_domain": row[2],
                        "computer_name": row[3],
                        "logon_type": row[4],
                        "ip_address": row[5],
                        "ip_port": row[6],
                        "login_time": row[7],
                        "logout_time": row[8],
                        "Session Length": row[9],
                    }
                )
    return jsonify({"results": results_list, "output_file": "/uploads/output.csv"})


@app.route("/output.html")
def output():
    return render_template("output.html")


@app.route("/uploads/<path:filename>")
def download_file(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)


if __name__ == "__main__":
    # Open the browser after a short delay
    threading.Timer(3, lambda: webbrowser.open("http://127.0.0.1:7878")).start()
    app.run(debug=False, port=7878)

# LogonSessionAuditor

This tool parses Windows EVTX logs to extract login and logout sessions from a security.evtx file. It uses a Tkinter GUI to let you select the EVTX file and specify a time for correlating login and logout events.

## Features

- Extract login (EventID 4624) and logout events (EventID 4634, 4647)
- Correlate sessions based on a specified UTC time
- Output the correlated sessions to a CSV file

## ToDo
- [ ] [Parse RDP Logs](https://1286158324-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MO79pt4NiZPFhlGCglR%2Fuploads%2Fjf7Sw5vieeT2M6bRt4w2%2FRDP_DFIR.pdf?alt=media&token=55b6337c-2a18-43de-8761-73dda2b5c222)
- [ ] Parse User Profile Service Logs
  - [ ] Event ID 5 "Load of user related registry hives"
  - [ ] Event ID 67
- [ ] Parse Group-Policy Logs
  - [ ] Event ID 5310
  - [ ] Event ID 4005
  - [ ] Event ID 4018
  - [ ] Event ID 5017
  - [ ] Event ID 4001
  - [ ] Event ID 8001 (subtract time take from event time))
  - [ ] Event ID 8005 (subtract time take from event time))
  - [ ] Event ID 5018 (subtract time take from event time))
- [ ] Parse Known-Folders API Logs
  - [ ] Event ID 1002 filter on username in path
- [ ] Parse Software Registry Hive
  - [ ] Creation of "CreateExplorerShellUnelevatedTask" task
- [ ] Parse Multiple Machines at once.
- [ ] Provide check box to show Session with no logout events (useful when identifying RDP activity while Security event log is cleared)

## Requirements

- Python 3.7+
- [tkcalendar](https://pypi.org/project/tkcalendar/)
- [evtx](https://pypi.org/project/evtx/)
- [lxml](https://pypi.org/project/lxml/)
- [Flask](https://pypi.org/project/flask/)

Install the required packages using:

```bash
pip install -r requirements.txt
```

## Executable Version
Web-based Flask app is available in the [latest release](https://github.com/0xHasanM/LogonSessionAuditor/releases).

## Contributing
Contributions are welcome! Feel free to fork the repository, make improvements, and submit a pull request.

## License
This project is open-source and available under the **MIT License**.

## Contributors
- [IRB0T](https://github.com/IRB0T)

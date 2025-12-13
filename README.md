# SherlocksHome (EDU)
###### BlueTeam EDU

A minimal Python snippet for observing **locally forwarded TCP traffic**.
Built for educational, debugging, and research scenarios in **controlled environments only**.

This is a snippet, not an application.

> Note
> This project does not crawl, scan, deanonymize, or monitor remote systems.
> It only inspects traffic that you explicitly forward to your own local machine.

---

## What It Does

* Listens on a configurable local TCP port.
* Captures basic packet metadata.
* Records timestamps, source and destination IPs, and ports.
* Writes results to a CSV file for later inspection.

No payload inspection. No protocol decoding. Metadata only.

---

## Typical Use Cases

* Debugging local port-forward or proxy setups.
* Verifying that forwarded traffic actually reaches the expected endpoint.
* Studying TCP connection patterns in a safe lab setup.
* Teaching fundamentals of packet capture and network metadata.
* Lightweight validation of service behavior for blue-team exercises.

---

## Usage

1. Set the local port in the script:

```python
LOCAL_PORT = 12345
```

2. Run the snippet:

```bash
python basic_example.py
```

3. Review the generated CSV file for timing and connection flow.

---

## Scope and Limitations

* Local traffic only.
* Requires traffic to be forwarded to the specified port.
* Not designed for high-volume capture.
* Not a monitoring or surveillance solution.

---

## Disclaimer

This project is provided for educational purposes only.
Use it exclusively on systems, networks, and traffic you own or are explicitly authorized to inspect.
The author assumes no responsibility for misuse.

---

## License

MIT License. See the LICENSE file for details.

---

© Volkan Sah

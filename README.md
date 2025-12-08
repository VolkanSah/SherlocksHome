# SherlocksHome (EDU)

A minimal Python snippet for **local traffic observation** when working with forwarded `.onion` or public endpoints.  
Designed strictly for **educational, debugging, and research scenarios** in controlled environments.

> **Note:**  
> This is *not* a crawler, scanner, deanonymizer, or monitoring tool for remote systems.  
> It only inspects traffic that **you locally forward to yourself**.

---

## Features

- Capture incoming TCP packets on a chosen local port.  
- Log timestamp, source/destination IP and ports.  
- Export results to CSV for further analysis.  
- Useful for debugging port‑forward setups or inspecting how forwarded traffic behaves.

---

## Usage

1. Set the desired local port inside the script.  
2. Run:

```bash
python sherlocks_home.py
````

3. Inspect the generated CSV file for timing and packet‑flow details.

---

## Intended Use

This snippet is aimed at:

* developers working with forwarded Tor services
* security researchers analyzing *their own* traffic
* blue‑teamers validating service behavior
* students learning about local packet inspection

It is **not** a security tool and provides zero offensive capability.

---

## Disclaimer

This project is for **educational use only**.
Use it exclusively on systems and traffic you own or are authorized to monitor.
The author assumes no responsibility for misuse.

---

## License

MIT License — see the `LICENSE` file.

---

© [Volkan Sah](https://github.com/volkansah)


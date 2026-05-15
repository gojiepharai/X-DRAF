# 📦 Cyber Risk Assessment Framework - (X-DRAF)

A Python tool that analyzes Open-Source Software (OSS) dependencies and calculates a **risk score (0–10)** based on FOUR main pillars such as:

- Vulnerabilities (CVEs, CVSS, exploitability)
- Maintainer health (activity, releases, bus factor)
- Supply chain security (signing, protections)
- Operational risk (update lag, lifecycle)

---

## 🚀 Features

- 🔍 Extract vulnerabilities from NVD JSON feeds
- 📊 Multi-dimensional risk scoring system
- 🧠 Smart heuristics (patch latency, exploitability, etc.)
- 🛠 Git-based maintainer health analysis
- 🎨 Risk tier classification (LOW → CRITICAL)
- ⚙️ Fully configurable scoring model

---

## 📁 Project Structure

```
project/
│
├── main.py                # Entry point (CLI)
├── config.py              # Scoring configuration
│
├── analyzer/              
│   ├── __init__.py
│   ├── utils.py           # Generic helper functions
│   ├── risk.py            # Risk tiers & color formatting
│   ├── nvd.py             # CVE extraction & matching logic
│   ├── git_analysis.py    # Git-based maintainer metrics
│   ├── scoring.py         # Core scoring engine
│
└── README.md
```

---

## 🧰 Requirements

- Python **3.9+**
- Git installed and available in PATH

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/gojiepharai/X-DRAF.git
cd x-draf
```

(Optional) Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
```

---

## 📥 Input Data

This tool expects:

### 1. NVD JSON File

Download from:
[https://nvd.nist.gov/vuln/data-feeds](https://nvd.nist.gov/vuln/data-feeds)

Example:

```
nvdcve-2.0-modified.json
```

---

### 2. Target Repository (optional but recommended)

Clone the Git repository you want analyse for maintainer analysis locally onto your pc:

```
/path/to/repo




## ▶️ Usage

Basic usage:

```bash
python main.py \
  --nvd path/to/nvd.json \
  --owner repo_owner \
  --name repo_name \
  --repo-path /path/to/local/repo
```

---

🧪 Example

```bash
python main.py --nvd-json
C:\Users\kathh\X-DRAF\nvdcve-2.0-modified.json
--repo veracrypt/VeraCrypt --keywords VeraCrypt
--use-cpe

---

📊 Output

The tool produces:

- Pillar scores:
  - Vulnerability
  - Maintainer Health
  - Supply Chain
  - Operational
- Final score (0–10)
- Risk tier:
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL

---

🧠 Scoring Model

Each dependency is evaluated across 4 pillars:


| Pillar            | Description                          |
| ----------------- | ------------------------------------ |
| Vulnerability     | CVSS, exploitability, patch latency  |
| Maintainer Health | Activity, responsiveness, bus factor |
| Supply Chain      | Signing, protections, registry risk  |
| Operational       | Update lag, lifecycle, criticality   |


Final score is a weighted aggregation defined in:

```
config.py
```

---

🎨 Risk Tiers


| Score Range | Tier     |
| ----------- | -------- |
| 0 – 3.0     | LOW      |
| 3.1 – 6.0   | MEDIUM   |
| 6.1 – 8.0   | HIGH     |
| 8.1 – 10    | CRITICAL |


---

🛠 Customization

You can tweak scoring behavior in:

```python
config.py
```

- Adjust weights
- Modify half-life decay functions
- Change thresholds

---

📌 Notes

- Git metrics require a **local clone** of the repository
- CVE matching uses:
  - GitHub references
  - Token matching
  - Optional CPE matching
- Some fields (e.g. EPSS, KEV) are placeholders for future enrichment

---

🧾 License

MIT License

```
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND...
```

---

🤝 Contributing

Contributions are welcome!

- Fork the repo
- Create a feature branch
- Submit a PR

---

💡 Future Improvements

- EPSS integration
- KEV (Known Exploited Vulnerabilities) support
- GitHub API integration (issues, PR response time)
- UI / Dashboard

---

👨‍💻 Author
[Henry Adu-Agyeman. Jr.](https://www.linkedin.com/in/henry-adu-agyeman-jr-85070038/)
Built with ❤️ to better understand dependency risk in modern software systems.

# nios-ibx-sdk

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-informational.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

> A collection of **Infoblox NIOS** scripts built on the **ibx-sdk** library—covering DNS records, grid operations, security (ADP/RPZ), and SSH utilities.

---

## 🧭 Overview

`nios-ibx-sdk` provides a suite of Python scripts designed to simplify management and automation of **Infoblox NIOS** environments.  
It extends the capabilities of the `ibx-sdk` library and includes helpers for DNS, DHCP, Grid operations, ADP, RPZ, and direct SSH-based workflows.

---

## ✨ Features

- DNS record management: A, PTR, CNAME, MX
- Grid automation workflows: pre-provisioning, lab building
- Security tooling for ADP (profiles, implementation, stats) and RPZ
- SSH utilities for NIOS member interactions
- Shared helper frameworks for consistent scripting

### Directory Overview

- `operations/` — DNS & Grid scripts  
- `security/` — ADP & RPZ utilities  
- `ssh/` — SSH wrappers and helpers  

---

## 📦 Requirements

- **Python 3.13+**
- **[ibx-sdk](https://github.com/Infoblox-PS/ibx-sdk/)** from Infoblox-PS

Install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install "git+https://github.com/Infoblox-PS/ibx-sdk.git"
```

---

## 🔧 Installation

```bash
git clone https://github.com/mragusa/nios-ibx-sdk.git
cd nios-ibx-sdk
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🔐 Configuration

Authentication and connectivity details for `ibx-sdk` should be set via environment variables or config files.  
Avoid embedding credentials in scripts.

---

## 🚀 Usage

All tools support `--help`.

### DNS Operations

**A Records**
```bash
python operations/nios_a.py --help
python operations/nios_a.py get --fqdn example.com
python operations/nios_a.py add --fqdn host.example.com --ip 192.168.1.10
python operations/nios_a.py delete --fqdn oldhost.example.com
```

**PTR, CNAME, MX**
```bash
python operations/nios_ptr.py --help
python operations/nios_cname.py --help
python operations/nios_mx.py --help
```

**Grid Pre-Provisioning**
```bash
python operations/nios_preprovision.py --help
```

**Build Lab Environment**
```bash
python operations/nios_buildlab.py --help
```

---

## 🔐 Security Tools

### Advanced DNS Protection (ADP)

```bash
python security/nios_adp_profile.py --help
python security/nios_adp_implementation.py --help
python security/nios_adp_stats.py --help
```

### RPZ Management

```bash
python security/nios_rpz_a.py --help
```

---

## 📡 SSH Framework

The `ssh/` directory includes helpers for issuing commands across NIOS devices when API access is insufficient.

---

## 🧱 Framework Helpers

- `ibx-sdk-framework.py` — shared API functions  
- `nios-ssh-framework.py` — SSH connection utilities  

These modules reduce boilerplate and provide consistent structure across scripts.

---

---

## 📜 License

MIT License — see `LICENSE` file.

---

## 📚 References

- Infoblox NIOS Documentation  
- ibx-sdk GitHub Repository  

---


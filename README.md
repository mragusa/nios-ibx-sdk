# nios-ibx-sdk
A collection of Infoblox scripts using the ibx-sdk library developed by Infoblox Professional Services

## Requirements
  - Python 3.10 or higher
  - [ibx-sdk](https://github.com/Infoblox-PS/ibx-sdk)

## Installation
1. **Setup Python venv**
```
python3 -m venv venv
```

2. **Install ibx-sdk**
```
pip install git+https://github.com/Infoblox-PS/ibx-sdk.git
```

## Operational Directory
| Script File | Description |
| :---: | :---: |
| `nios_buildlab.py` | populate NIOS with various test records |
| `nios_a.py` | script to interact with A records |
| `nios_ptr.py` | script to interact with PTR records |
| `nios_cname.py` | script to interact with CNAME records | 
| `nios_mx.py` | script to interact with MX records |
| `nios_preprovision.py` | preprovision nios members into grid |


## Security Directory
### Advanced DNS Protection
| Script Name | Description | 
| :---: | :---: |
| `nios_adp_profile.py` | Interact with ADP Profiles |
| `nios_adp_implementation.py` | Setup inital ADP values for evaluation prior to production |
| `nios_adp_stats.py` | Retieve last 30 mins of ADP statistics |
### RPZ
| Script Name | Description |
| :---: | :---: |
| `nios_rpz_a.py` | Add, Remove, Update RPZ A records |






[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

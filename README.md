# reporterman

A command-line tool to automate system audits with Metasploit and Searchsploit. It is supported by some ollama LLMs.

## Installation Guide

### Local Installation
>[!IMPORTANT]
>You must have python 3.12.3 or higher

You can install it by running:
```bash
sudo apt install python3.12 -y
```

#### Installation
```bash
git clone https://github.com/frajimmor2/tfg-audit-automation.git
cd tfg-audit-automation
pip install -r requirements.txt
pip install -e .
sudo $(which reporterman) setUp
```

Usage:

```bash
reporterman --help
```

> [!IMPORTANT]
>The changes in the code will be automatically updated. You will not need to reinstall to apply them.

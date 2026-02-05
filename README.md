# reporterman

A command-line tool to automate system audits with Metasploit and Searchsploit. It is supported by some ollama LLMs.

## Installation Guide

### Local Installation

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

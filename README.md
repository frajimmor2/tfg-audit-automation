# reporterman

A command-line tool to automate system audits with Metasploit and Searchsploit. It is supported by some ollama LLMs.

## Installation Guide

### Local Installation

#### Installation
```bash
git clone https://github.com/frajimmor2/tfg-audit-automation.git
cd tfg-audit-automation
chmod +x install_dependencies.sh
sudo ./install_dependencies.sh
ollama create soft_obs_analyzer -f llms/soft_obs_analyzer
ollama create exploit_selector_soft -f llms/exploit_selector_soft
pip install -r requirements.txt
pip install -e .
```

If you just wat to reinstall the models, just run this:

```bash
ollama create soft_obs_analyzer -f llms/soft_obs_analyzer
ollama create exploit_selector_soft -f llms/exploit_selector_soft
```

Usage:

```bash
reporterman --help
```

> [!IMPORTANT]
>The changes in the code will be automatically updated. You will not need to reinstall to apply them.

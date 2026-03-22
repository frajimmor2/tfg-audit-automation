<p align="center">
  <img src="src/reporterman/modules/reporting/assets/logo.png" alt="Logo" width="400"/>
</p>

A command-line tool to automate system audits with Metasploit. It is supported by some ollama LLMs.

## Installation Guide

### Local Installation
> [!WARNING]
> First of all, you must obtain an API KEY from NIST.
>
> You can request one here: https://nvd.nist.gov/developers/request-an-api-key
>
> Remember to add the API KEY to your local env

```bash
git clone https://github.com/frajimmor2/tfg-audit-automation.git
cd tfg-audit-automation
cp .env.example .env
```

After modifing the enviroment you can coninue with the installation.

```bash
chmod +x install.sh
sudo ./install.sh
source venv/bin/activate
```

Usage:

```bash
reporterman --help
```

> [!IMPORTANT]
>The changes in the code will be automatically updated. You will not need to reinstall to apply them.

---

If you just wat to reinstall the models, just run this:

```bash
ollama rm soft_obs_analyzer
ollama rm exploit_selector_vuln
ollama rm exploit_selector_soft
ollama rm llm_list_parser
ollama create soft_obs_analyzer -f llms/soft_obs_analyzer
ollama create exploit_selector_vuln -f llms/exploit_selector_vuln
ollama create exploit_selector_soft -f llms/exploit_selector_soft
ollama create llm_list_parser -f llms/llm_list_parser
```

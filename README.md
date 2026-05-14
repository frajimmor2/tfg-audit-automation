<p align="center">
  <img src="src/reporterman/modules/reporting/assets/logo.png" alt="Logo" width="400"/>
</p>

[![Compatibility](https://img.shields.io/badge/python-3.12.3-brightgreen.svg)](https://github.com/frajimmor2/tfg-audit-automation)
![](https://img.shields.io/github/v/release/frajimmor2/tfg-audit-automation)

A **command-line tool** designed to **automate system audits** using Metasploit, enhanced with the support of local Ollama LLMs. Reporterman enables you to perform complete black-box audits effortlessly and generate a comprehensive PDF report—all **with a single command**.

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

After modifing the enviroment you can continue with the installation.

```bash
chmod +x install.sh
sudo ./install.sh
source venv/bin/activate
```

> [!IMPORTANT]
>The changes in the code will be automatically updated. You will not need to reinstall to apply them.

Usage explanation:

```bash
reporterman --help
```
The `llms-time-exec-test` command runs a series of tests that simulate the average processing workload performed by the models. It then displays the time required to complete these tests.

If this test takes too long to execute (several minutes), it is an indication that the hardware is not powerful enough to properly run the tool.

It is estimated that for each audited software service, there is 1 call to the obsolescence review model, 3 calls to the exploit selector based on vulnerabilities, and 3 calls to the exploit selector based on service information.

With this information, it is possible to estimate the total time required to perform an audit, knowing the number of services being audited.

## Correct Use Guide

When performing a black-box audit, root privileges are typically required. To ensure a proper and uninterrupted workflow, it is highly recommended to run Reporterman with elevated permissions using sudo.

Actual usage:
```bash
sudo ./venv/bin/reporterman run target
```

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

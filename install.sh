#!/usr/bin/env bash

# Other dependencies
apt update -y
apt-get install python3.12 -y
apt-get install curl -y
sudo snap install metasploit-framework
apt-get install -y nmap
apt-get install -y jq

# LLMs
snap install ollama
ollama pull llama2-uncensored
ollama create soft_obs_analyzer -f llms/soft_obs_analyzer
ollama create exploit_selector_soft -f llms/exploit_selector_vuln
ollama create exploit_selector_soft -f llms/exploit_selector_soft
ollama create llm_list_parser -f llms/llm_list_parser

# Installation
chmod +x src/reporterman/modules/execution/exec_m.sh
chmod +x src/reporterman/modules/execution/exec_m_0.sh
chmod +x src/reporterman/modules/execution/exec_m_1.sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .

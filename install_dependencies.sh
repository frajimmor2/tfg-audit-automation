#!/usr/bin/env bash

# Other dependencies
apt update -y
apt-get install python3.12 -y
apt-get install curl -y
apt-get install -y iputils-ping
apt-get install -y nmap
apt-get install -y jq

# LLMs
snap install ollama
ollama pull llama2-uncensored

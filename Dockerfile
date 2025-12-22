FROM kalilinux/kali-rolling

# Install python 3.12.3
RUN apt-get update && apt install python3 python3-pip -y && apt install pypy3-venv python3.13-venv -y 

WORKDIR /app

COPY . .

# Required  venv and dependencies (The venv is required due to the docker image I'm using)
RUN python3 -m venv venv
RUN . /app/venv/bin/activate
RUN venv/bin/pip install --upgrade pip && \
    venv/bin/pip install -r requirements.txt

# Install the cli tool
RUN venv/bin/pip install .

ENTRYPOINT ["/app/venv/bin/reporterman"]

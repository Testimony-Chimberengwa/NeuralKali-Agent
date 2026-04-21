FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /opt/neuralkali

RUN apt-get update && apt-get install -y --no-install-recommends \
	nmap gobuster nikto sqlmap whatweb enum4linux \
	curl python3 python3-pip git netcat-openbsd wordlists \
	ca-certificates systemd \
	&& rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://ollama.com/install.sh | sh

COPY requirements.txt /opt/neuralkali/requirements.txt
COPY agent/ /opt/neuralkali/agent/
COPY config/ /opt/neuralkali/config/
COPY cli.py /opt/neuralkali/cli.py

RUN python3 -m pip install --no-cache-dir -r /opt/neuralkali/requirements.txt

RUN printf '[Unit]\nDescription=Ollama Service\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/ollama serve\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/ollama.service

RUN printf '[Unit]\nDescription=NeuralKali Agent\nAfter=network.target ollama.service\n\n[Service]\nType=simple\nWorkingDirectory=/opt/neuralkali\nExecStart=/usr/bin/python3 /opt/neuralkali/cli.py daemon\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/neuralkali-agent.service

EXPOSE 11434

CMD ["python3", "/opt/neuralkali/cli.py", "daemon"]

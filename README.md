# Raw socket server (base)

This repository contains a small Python script `server.py` that demonstrates receiving raw IP packets and printing a short summary for each packet.

Important notes

- Raw sockets require elevated privileges.
  - Windows: run PowerShell as Administrator. The script attempts to enable RCVALL to capture all IP packets.
  - Linux/macOS: run as root (e.g. with `sudo`). On Linux the script will try to use `AF_PACKET` to capture link-layer frames.
- Capturing may still be limited by the OS or network interface configuration.

How to run (Windows PowerShell)

1. Open PowerShell "Run as Administrator".
2. From the project folder run:

```powershell
python .\server.py
# or explicitly with py launcher if needed:
py -3 .\server.py
```

You can optionally pass a host/IP to bind to (Windows):

```powershell
python .\server.py 192.168.1.10
```

How to run (Linux/macOS)

```bash
sudo python3 server.py
```

What you should see

Lines like:

```
192.168.1.5 -> 8.8.8.8  proto=UDP ttl=64 ihl=5
```

If you see a permission error, ensure you started the shell with the required elevated privileges.

Security & privacy

- This script prints source/destination addresses of packets it receives. Use it only on networks where you are allowed to capture traffic.

Limitations

- Behavior varies across OSes and network drivers. Some platforms restrict raw sockets.

License

- Use as you like for learning and experimentation.

# labredest2

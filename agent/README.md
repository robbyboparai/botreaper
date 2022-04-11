# Botreaper
Botreaper is a Python program that requires a wireless network interface capable of monitor mode to operate.
It will automatically sniff the traffic of devices on a local network, sniff the traffic and enumerate host and destination IP addresses, and ports. The results will be written to a JSON file that will be automatically uploaded to an AWS bucket, which can then be parsed for evidence of devices contacting known malicious IP addresses, portscans, or any network activity that you might want to flag for any reason, though this is intended to discover devices that have been infected with a botnet.

The botreaper team has a system that already does this for our own uploads for demonstration purposes, accessible at `botreaper.com`

# Dependencies
This requires Python version 3.8.10
The required dependencies can be installed using the command `pip install -r requirements.txt`

# Configuration
All fields in the `config.txt` file must be populated in order for botreaper to run.

# Running it
Once the config.txt file has been fully populated with approprate data, simply run `sudo python botreaper.py`
Sniffed packets will be shown in the terminal in real time, and the final results will be printed to the terminal at the end in an easily readable format.

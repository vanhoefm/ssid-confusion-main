# 1. Introduction

# 2. Background & Motivation

- **Fill in when writing the rest of the paper**
- Enterprise authentication & networks with different SSID but same RADIUS server
- Usage of the SSID to enable/disable a VPN or not (eduroam vs university)
- 2.4 vs 5 GHz network, different management frame protection options
  2.4 AP may be older and vulnerable to KRACK/FragAttacks

# 3. SSID Confusion Attack

- Explain the attack
- Home networks:
	- WEP, WPA3 "hunting and pecking" vulnerable
	- WPA1/2, WPA3 "constant" secure
- Enterprise networks 802.1X
- Fast BSS Transition (won't now be detected)
- FILS Public Key
- SAE + AMPE / 802.1X

# 4. Optimization & evaluation

- Explain the idea so attack only briefly needs to interfere
- Discuss the impact of channel validation
- Evaluation: test using tool against various clients
- Telenet plaintext behavior, reply time
- Selected Enterprise scraping, citiwifi

# 5. Defense: beacon protection

- Fails to detect because SSID not checked
- Standard mentions post-check of pre-auth beacon
  Implement this and now detect the attack instantly
- Won't work with hidden networks
- Enterprise: use a different RADIUS server for each network
- Home: use a different password for each SSID
- Protocol update: the 4-way handshake should always verify the SSID.

# 6. Related work?

# 7. Conclusion


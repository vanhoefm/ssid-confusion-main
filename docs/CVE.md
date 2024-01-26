
The IEEE 802.11 standard that underpins Wi-Fi doesn't always authenticate the Service Set Identifier (SSID) that a client connects to. This may enable an adversary to trick a victim into connecting to an unintended or untrusted network. The affected authentication methods that are vulnerable are Wired Equivalent Privacy (WEP), Simultaneous Authentication of Equals with looping (SAE-Loop), 802.1X-based authentication, Authenticated Mesh Peering Exchange (AMPE), Fast Initial Link Setup (FILS), and Fast Transtition (FT).

(WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated. Against devices that support receiving non-SPP A-MSDU frames, which is mandatory as part of 802.11n, an adversary can abuse this to inject arbitrary network packets.

- Vulnerability Type: Other
- CWE-287: Improper Authentication
- Vendor of the produts: Institute of Electrical and Electronics Engineers (IEEE)
- Code base: The 802.11 standard underpinning Wi-Fi - IEEE Std 802.11-2020
- Component: The following network authentication methods in the IEEE 802.11 standard are affected: Wired Equivalent Privacy (WEP), Simultaneous Authentication of Equals with looping (SAE-Loop), 802.1X-based authentication, Authenticated Mesh Peering Exchange (AMPE), Fast Initial Link Setup (FILS), and Fast Transtition (FT).
- Type: remote
- Impact: An adversary can trick a victim into connecting to an unintended network.
- Vector: To exploit this vulnerability the attacker must be within radio range of the victim.
- Discovered: Mathy Vanhoef and Heloise Gollier


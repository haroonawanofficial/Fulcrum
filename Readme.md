# Fulcrum

**Turning the network's own foundation into a weapon for total compromise.**

Lan Fulcrum is an advanced, interactive penetration testing framework designed for offensive security professionals. It moves beyond simple vulnerability scanning to weaponize the very protocols that networks rely on, finding the critical pivot point to achieve total domain dominance, even in segmented, Vlan to Vlan (example; Palo Alto encrypted internal protected segments), encrypted or unencrypted or/and air-gapped environments even if the network is bugged/wired/cloud tapped, Guess what? Fulcrum will provide you in-depth details!

![GitHub](https://img.shields.io/badge/Python-3.x-%23FFD43B?logo=python)
![GitHub](https://img.shields.io/badge/License-GPLv3-blue)
![GitHub](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

## 🚀 Key Features

*   **L2/L3 Protocol Offense:** Advanced attacks against STP, DTP, DHCP, ARP, CDP/LLDP, HSRP/VRRP, and more.
*   **Active Directory Exploitation:** Automated discovery, enumeration, and exploitation of AD environments.
*   **Lateral Movement:** Integrated techniques for pivoting, remote command execution, and evidence planting.
*   **Firewall Evasion & Manipulation:** Techniques to bypass, blind, and exploit network security controls.
*   **Covert Channels:** Data exfiltration via custom EtherTypes and packet padding exploits.
*   **Interactive Chat Interface:** An intuitive, command-driven interface for guided network exploration and assault.

## ⚡ Why Fulcrum? The Competitive Edge

| Feature | Fulcrum | Yersinia | Other Tools |
|:---|:---|:---|:---|
| **Scope** | **L2 to L7** (Full Kill Chain) | **Purely L2** | **Often Siloed** (e.g., just scanning, just exploitation) |
| **Automation** | **`auto-mode`** sequences recon & attacks | **Manual** per-protocol attack | Requires manual tool chaining |
| **Post-Exploit** | **Built-in** lateral movement, evidence planting | **None** | Requires external tools (e.g., Metasploit, CME) |
| **Stealth & Evasion** | **Firewall DPI bypass**, log flooding, covert channels | Noisy, obvious attacks | Varies; often not a primary focus |
| **Usability** | **Interactive chat** with guided help | Complex CLI with multiple modes | Often complex, disjointed CLI arguments |

**Fulcrum a unified command center for total network dominance, seamlessly integrating the deep L2 exploitation of Yersinia with the post-exploitation power of frameworks like Metasploit.**

## ⚠️ Disclaimer

**I take zero responsibility, it was a challenege and it looks like I killed every Vlan/Switch/FW/Router in the world. Fulcrum is intended for authorized security testing and educational purposes only. Any use of this tool against a network without explicit, prior permission is strictly prohibited. The user assumes all responsibility for their actions.**

## 📦 Installation

1.  **Prerequisites:** Ensure you have Python 3 and `pip` installed.
    ```bash
    sudo apt update && sudo apt install python3 python3-pip
    ```

2.  **Clone the Repository:**
    ```bash
    git clone https://github.com/haroonawanofficial/fulcrum.git
    cd fulcrum
    ```

3.  **Install Python Dependencies:**
    ```bash
    pip3 install -r requirements.txt
    ```

4.  **Run with Root Privileges:**
    ```bash
    sudo python3 fulcrum.py --iface eth0 --cidr 192.168.1.0/24
    ```

## 🕹️ Usage
Run the tool and use the interactive chat prompt:
scan
auto-mode
help


## 📜 License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) file for details.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the [issues page](https://github.com/haroonawanofficial/fulcrum/issues).

---

## 👨‍💻 Author

**Haroon Awan** - [github.com/haroonawanofficial](https://github.com/haroonawanofficial)

*If Fulcrum gave you visible leverage, consider giving it a ⭐ on GitHub!*

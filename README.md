# 🔐 Secure VPN Tunnel

![Banner](banner.png)

## 🌟 Overview
A secure client-server communication prototype in Python. This project demonstrates ECDH key agreement, authenticated encryption, message framing, replay protection, and integrity verification. It is an educational encrypted messaging tunnel, not a full system-level VPN such as WireGuard or OpenVPN.

Developed by **Eng. Sajjad** 🚀

---

## 🛠 Features
- **⚡ Secure Key Exchange**: Uses **Elliptic Curve Diffie-Hellman (ECDH)** with the P-256 curve.
- **🛡 Strong Encryption**: **AES-256-CBC** provides message confidentiality.
- **🔍 Integrity Verification**: **HMAC-SHA256** authenticates every framed message.
- **🔁 Replay Protection**: Monotonic message counters reject replayed or reordered messages.
- **🎨 Interactive UI**: Beautifully colored terminal output for monitoring handshakes and data flow.
- **📂 Modular Design**: Clean separation between cryptography and networking logic.

---

## 🏗 Architecture
The system follows a classic Client-Server architecture:
1. **TCP Handshake**: Connection established over standard sockets.
2. **Key Agreement**: Public keys are exchanged; shared secret derived using ECDH.
3. **Key Derivation**: HKDF is used to split the secret into AES and HMAC keys.
4. **Encrypted Tunnel**: Length-prefixed encrypted JSON messages are transmitted over TCP.

---

## 🚀 Getting Started

### 📋 Prerequisites
- Python 3.8+
- PyCryptodome
- Colorama

### 🔧 Installation
```bash
# Clone the repository
git clone https://github.com/EngSajjad21/Secure-VPN-Tunnel.git
cd Secure-VPN-Tunnel

# Install dependencies
pip install pycryptodome colorama
```

### 🏃 Usage
1. **Start the VPN Server**:
   ```bash
   VPN_HOST=127.0.0.1 python server.py
   ```
2. **Run the VPN Client**:
   ```bash
   python client.py
   ```
3. Type your messages in the client terminal and watch them travel through the encrypted prototype tunnel. Keep `VPN_HOST` bound to a trusted interface unless remote access is required.

---

## 🧪 Testing
I've included a comprehensive test suite to verify the security parameters:
```bash
python test_crypto.py
```

---

## 📜 License
This project is licensed under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.

---

**Developed with ❤️ by Eng. Sajjad**  
[![GitHub](https://img.shields.io/badge/GitHub-EngSajjad21-blue?style=flat&logo=github)](https://github.com/EngSajjad21)

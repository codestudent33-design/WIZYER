#  WIZYER – WiFi Security Analyzer & Risk Assessment System

##  Overview

WIZYER is a Python-based intelligent WiFi security analyzer that scans nearby networks and evaluates their security risks using a **multi-layer risk assessment model**.

Unlike traditional tools, WIZYER does not rely only on encryption type — it analyzes **behavioral patterns, environmental anomalies, and configuration weaknesses** to detect threats such as **Evil Twin attacks and fake hotspots**.

---

##  Key Features

* 📡 Real-time WiFi network scanning
* 🔐 Intelligent risk classification (LOW / MEDIUM / HIGH)
* 📊 Final Security Score (/100)
* ⚠️ Detection of:

  * Open networks
  * Weak encryption (WEP, WPA2)
  * Duplicate SSIDs (Evil Twin)
  * Suspicious signal strength
* 📈 Graphical dashboard (Risk distribution)
* 📄 Auto-generated JSON security report
* 🖥️ User-friendly GUI (PyQt5)

---

##  Our Innovation

WIZYER introduces a **Multi-Layer Risk Analysis Model**:

1. **Cryptographic Strength Analysis**

   * Evaluates WPA2, WPA3, WEP, OPEN networks

2. **Network Configuration Risk**

   * Hidden SSID detection
   * Misconfigurations

3. **Environmental Risk**

   * Duplicate SSIDs → possible Evil Twin
   * Signal anomalies

4. **Behavioral Risk**

   * Suspicious network patterns

5. **Network Health Analysis**

   * Channel usage and congestion

👉 This makes WIZYER more **intelligent than basic WiFi scanners**

---

##  Tech Stack

* Python
* PyQt5 (GUI)
* Matplotlib (Visualization)
* ReportLab (Report generation)
* System Commands (netsh / nmcli)

---

##  Project Structure

```
WIZYER/
│
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
├── screenshots/
│   ├── scan.png
│   ├── dashboard.png
│
└── docs/
    └── report.pdf
```

---

## ⚙️ Installation & Setup

### 1. Clone Repository

```
git clone https://github.com/your-username/wizyer.git
cd wizyer
```

### 2. Install Dependencies

```
pip install -r requirements.txt
```

### 3. Run Project

```
python main.py
```

---

## 📸 Screenshots

* Live Scan Interface
* Risk Table
* Dashboard Graph
* Report Preview

---

## 📊 Sample Output

* Risk Level: HIGH / MEDIUM / LOW
* Security Score: XX/100
* Detailed Vulnerability Reasons
* Recommendations for each network

---

## ⚠️ Limitations

* Works primarily on Windows (`netsh`)
* Requires system permission for scanning
* Cannot detect encrypted traffic attacks

---

## 🚀 Future Improvements

* Cross-platform support (Linux, macOS)
* Real-time monitoring dashboard
* AI-based anomaly detection
* PDF report export
* Integration with mobile devices

---

## 📜 License

This project is licensed under the MIT License.

---

## 📄 Project Report
Detailed documentation is available in the docs folder.

## Download

👉 Download the latest version from Releases:
https://github.com/YOUR-USERNAME/YOUR-REPO/releases

## 👨‍💻 Author

Developed by **Ritik**
B.Tech CSE (Cyber Security)

---

## ⭐ Contribution

Feel free to fork this repository and improve the project!

---

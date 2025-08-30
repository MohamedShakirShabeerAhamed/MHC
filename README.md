# Malware Hash Clustering (MHC) Tool

The **Malware Hash Clustering (MHC) Tool** is designed to **collect, cluster, and evaluate malware samples** using hash-based analysis and threat intelligence data. 

---

## Features
- **Collect** recent malware samples from [MalwareBazaar](https://bazaar.abuse.ch/)
- **Cluster** malware samples using advanced graph-based techniques
- **Evaluate** clustering results against labeled threat intelligence
- **Custom CSV Labeling Support** for your own datasets
- Lightweight and **fully scriptable** for automation

---

## Requirements
Ensure you have the following installed:
- **Python 3.8+**
- Required libraries:
  ```bash
  pip install pandas networkx requests matplotlib
  ```

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/MohamedShakirShabeerAhamed/MHC.git
   cd mhc-tool
   ```
2. Install dependencies:
   ```bash
   pip install requests pandas numpy networkx matplotlib scikit-learn python-dateutil ssdeep tlsh
   ```

---

## API Key Setup
This tool fetches data from **MalwareBazaar**.  
Get your free API key from [https://bazaar.abuse.ch/api/](https://bazaar.abuse.ch/api/) and export it:

```bash
export MB_API_KEY="your_api_key_here"
```

---

## 🛠 Usage

### **1. Collect Malware Samples**
Fetch recent malware data:
```bash
python mhc-tool.py collect --days 7 --max 100
```

---

### **2. Cluster Samples**
Cluster the collected malware:
```bash
python mhc-tool.py cluster --input out/collected_samples.csv --output out/run1_clusters.csv
```

---

### **3. Evaluate Clusters**
Evaluate clustering using labels:
```bash
python mhc-tool.py evaluate --clusters out/run1_clusters.csv --labels data/cti_labels.csv --out out/run1_eval.json
```

If you don’t have `cti_labels.csv`, you can generate one manually or use the **Flagged Hash List** with labeling to create it.

---

## 🧪 Generating a Sample `cti_labels.csv`
To create a labeled dataset using the [Flagged Hash List](https://raw.githubusercontent.com/LGOG/Flagged_Hash_list/refs/heads/main/Flagged_Hash_List.csv):

```bash
python cti_labels.py
```
This generates a `data/cti_labels.csv` with **100 labeled samples**.

---

## Disclaimer
This tool is intended **for research and educational purposes only**.  
Do **not** use it for malicious purposes. The author assumes no liability for misuse.

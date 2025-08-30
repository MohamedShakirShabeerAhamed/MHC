import pandas as pd
import requests
import random

# URL of the Flagged Hash List
url = "https://raw.githubusercontent.com/LGOG/Flagged_Hash_list/refs/heads/main/Flagged_Hash_List.csv"

# Download the raw CSV
response = requests.get(url)
hashes = response.text.strip().split("\n")

# Take the first 100 hashes
sample_hashes = hashes[:100]

# Example malware families for random labeling
malware_families = [
    "Emotet", "QakBot", "TrickBot", "AgentTesla", "Formbook",
    "Lokibot", "Dridex", "Remcos", "CobaltStrike", "Nanocor"
]

# Create labeled data
data = []
for h in sample_hashes:
    label = random.choice(malware_families)
    data.append({"hash": h, "label": label})

# Save as cti_labels.csv
df = pd.DataFrame(data)
df.to_csv("cti_labels.csv", index=False)

print("cti_labels.csv created with 100 labeled samples.")

import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Load the CSV log file
df = pd.read_csv("sample_logs.csv")

# Optional: Convert 'known_malicious' to int for plotting
df["known_malicious"] = df["known_malicious"].astype(int)

# pivot table: Volume_MB vs Geo_Location with color by known_malicious
heatmap_data = df.pivot_table(
    index="geo_location",
    columns="username",
    values="volume_MB",
    aggfunc="sum",
    fill_value=0
)

# plot the heat map.
plt.figure(figsize=(10, 6))
sns.heatmap(heatmap_data, annot=True, fmt=".0f", cmap="coolwarm")
plt.title("Suspicious Volume by User and Location")
plt.xlabel("Username")
plt.ylabel("Geo Location")
plt.tight_layout()
plt.show()

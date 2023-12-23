import pandas as pd
import matplotlib.pyplot as plt

# Read the data into a DataFrame
data = pd.read_csv("/home/couto/Desktop/ndnSIM/ns-3/src/ndnSIM/examples/graphs/rate-trace.txt", sep="\t")

# Filter the data to include only relevant types
data = data[data['Type'].isin(["InInterests", "OutInterests", "InData", "OutData"])]

# Group the data by Time, Node, and Type, and sum the Kilobytes
data_combined = data.groupby(['Time', 'Node', 'Type'])['Kilobytes'].sum().reset_index()

# Create a function to plot data for a given Node
def plot_data(node_data, node_name):
    plt.figure(figsize=(10, 5))
    for data_type, data in node_data.groupby('Type'):
        # Filter out negative and null (0) values
        data = data[data['Kilobytes'] > 0]
        if not data.empty:
            # Apply a log scale to the Y-axis
            plt.semilogy(data['Time'], data['Kilobytes'], label=data_type)
    plt.xlabel("Time")
    plt.ylabel("Kilobytes (log scale)")
    plt.title(f"Node: {node_name}")
    plt.legend()
    plt.show()

# Plot data for all nodes
for node_name, node_data in data_combined.groupby('Node'):
    plot_data(node_data, node_name)


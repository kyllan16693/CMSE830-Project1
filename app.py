import streamlit as st
import pandas as pd
import altair as alt
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score


pd.option_context('mode.use_inf_as_na', True)

df = pd.read_csv('data/clean_dataset.csv')

#read in all datasets and preform linear regression on them
#put y_test and y_pred into a dictionary with the key being the dataset name
y_test_df = pd.DataFrame(columns=['subset','y_test', 'y_pred','x_test'])
#create a single pyplot figure with all the predictions
#display the dataframe and the figure with options to select which dataset to view 

df_flow = df.filter(regex='Flow|Label')
df_flags = df.filter(regex='Flags|Label')
df_byts = df.filter(regex='Byts|Label')
df_pkts = df.filter(regex='Pkts|Label')
df_iat = df.filter(regex='IAT|Label')
df_subflow = df.filter(regex='Subflow|Label')
df_flow_subflow = df.filter(regex='Flow|Subflow|Label')

df_scores = pd.DataFrame(columns=['subset', 'MSE', 'MAE', 'R2'])


#make a function that repeats this process for all the datasets
def linreg(df, name):
    #clean up data
    df = df.replace([np.inf, -np.inf], np.nan).dropna()

    #split data into train and test
    X = df.drop(columns=['Label'])
    y = df['Label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    #fit linear regression model
    model = LinearRegression()
    model.fit(X_train, y_train)

    st.write("## "+name)
    st.write(model.score(X_test, y_test))

    #predict on test data
    y_pred = model.predict(X_test)

    #add y_test and y_pred to the df
    #y_test in the format 23254     1\n
    #extract the number from the string

    y_test_df.loc[len(y_test_df)] = [name, y_test, y_pred, X_test]

    #calculate mse, mae, and r2 and add to df_scores
    mse = mean_squared_error(y_test, y_pred)
    mae = mean_absolute_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    
    df_scores.loc[len(df_scores)] = [name, mse, mae, r2]

    

linreg(df_flow, 'Flow')
linreg(df_flags, 'Flags')
linreg(df_byts, 'Byts')
linreg(df_pkts, 'Pkts')
linreg(df_iat, 'IAT')
linreg(df_subflow, 'Subflow')


st.write("## Predictions")
st.write(y_test_df)

st.write("## Scores")
st.write(df_scores)

#plot all the predictions on one figure that is interactive
fig, ax = plt.subplots()
for i in range(len(y_test_df)):
    ax.scatter(y_test_df['y_test'][i], y_test_df['y_pred'][i], label=y_test_df['subset'][i])
ax.set_xlabel('y_test')
ax.set_ylabel('y_pred')
ax.legend()
st.pyplot(fig)

#also plot using altair
st.write("## Predictions")
plot_altair = alt.Chart(y_test_df).mark_circle().encode(
    x='y_test',
    y='y_pred',
    color='subset'
).interactive()
st.altair_chart(plot_altair)




#plot the predictions for each dataset on a separate figure
for i in range(len(y_test_df)):
    fig, ax = plt.subplots()
    ax.scatter(y_test_df['y_test'][i], y_test_df['y_pred'][i])
    ax.set_xlabel('y_test')
    ax.set_ylabel('y_pred')
    ax.set_title(y_test_df['subset'][i])
    st.pyplot(fig)






""" st.header("Distribution Plots")
fig, ax = plt.subplots()
for column in df.select_dtypes(include='number').columns:
    try:
        st.write(f"## {column}")
        st.bar_chart(df[column])
    except:
        st.write(f"Could not create chart for {column}") """


""" 
st.header("Time Series Analysis")
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
st.write(df.set_index('Timestamp').resample('D').mean())
st.line_chart(df.set_index('Timestamp').resample('D').mean())

st.header("Attack Type Distribution")
st.write(df['Label'].value_counts())



st.header("Protocol Analysis")
st.write(df['Protocol'].value_counts())


st.header("Packet Length Analysis")
st.write(f"Minimum Packet Length: {df['Pkt Len Min'].min()}")
st.write(f"Maximum Packet Length: {df['Pkt Len Max'].max()}")
st.write(f"Mean Packet Length: {df['Pkt Len Mean'].mean()}")




st.header("Attack Patterns Over Time")
attack_data = df[df['Label'] != 'Normal']
st.line_chart(attack_data.groupby(attack_data['Timestamp'].dt.date).size())



st.header("Port Analysis")
st.write("Source Ports:")
st.write(df['Src Port'].value_counts())
st.write("Destination Ports:")
st.write(df['Dst Port'].value_counts())




#plot Down/Up Ratio    vs time
st.write("Down/Up Ratio    vs time")
st.line_chart(data, x='Timestamp', y='Down/Up Ratio')



data = df
st.header("Anomaly Detection")

# Select the feature for anomaly detection
feature = 'Pkt Len Mean'

# Fit the Isolation Forest model
model = IsolationForest(contamination=0.05)  # Adjust contamination as needed
model.fit(data[[feature]])

# Predict anomalies (1 for normal, -1 for anomaly)
anomalies = model.predict(data[[feature]])

# Visualize anomalies using a scatter plot
st.subheader("Anomaly Detection Results")
plt.figure(figsize=(8, 6))
plt.scatter(data.index, data[feature], c=anomalies, cmap='viridis')
plt.xlabel("Index")
plt.ylabel(feature)
plt.title("Anomaly Detection")
st.pyplot(plt)

# Display detected anomalies
st.subheader("Detected Anomalies")
anomalies_df = data[anomalies == -1]
st.write(anomalies_df)
 """

#df = pd.read_csv('data/final_dataset.csv')
#df = pd.read_csv('data/minidata.csv')

st.title("""
# DDoS Attack Data

This app visualizes attack anomolies on a network.
""")

#datasets: bruteforce, dos, ddos, infiltration, bot
#tab for each dataset

#bruteforce, dos, ddos = st.tabs(["Bruteforce", "DoS", "DDoS", "Infiltration", "Bot"])

#bruteforce
""" with bruteforce:
    bruteforce.title("Bruteforce")
    bruteforce.write("Tools used: FTP-Patator and SSH-Patator. Attacker: Kali linux Victim:	Ubuntu 16.4 (Web Server)")
    df_Bruteforce = pd.read_csv('data/Bruteforce.csv')

    #plot Fwd Pkts/s  and Bwd Pkts/s  vs time
    bruteforce.write("Fwd Pkts/s  and Bwd Pkts/s  vs time")
    bruteforce.line_chart(df_Bruteforce, x='Timestamp', y=['Fwd Pkts/s', 'Bwd Pkts/s', 'Flow Byts/s', 'Flow Pkts/s'])


    #plot Timestamp vs Flow Duration
    bruteforce.write("Timestamp vs Flow Duration")
    bruteforce.scatter_chart(df_Bruteforce, x='Timestamp', y='Flow Duration')

    #Down/Up Ratio    vs time
    bruteforce.write("Down/Up Ratio    vs time")
    bruteforce.line_chart(df_Bruteforce, x='Timestamp', y='Down/Up Ratio')

    #plot Src IP and Dst IP in network graph
    G = nx.Graph()
    for i in range(len(df_Bruteforce)):
        G.add_edge(df_Bruteforce['Src IP'][i], df_Bruteforce['Dst IP'][i], weight=1)

    bruteforce.write("Network Graph of Src IP and Dst IP")

    #put into plt figure
    fig = plt.figure(figsize=(20,20))
    nx.draw(G, with_labels=True)
    bruteforce.pyplot(fig)


#dos
with dos:
    dos.title("DoS")
    dos.write("Tools used: GoldenEye, Slowloris, SlowHTTPTest, Hulk. Attacker: Kali linux Victim:	Ubuntu 16.4 (Web Server)")
    df_DoS = pd.read_csv('data/DoS.csv')

    #plot Fwd Pkts/s  and Bwd Pkts/s  vs time
    dos.write("Fwd Pkts/s  and Bwd Pkts/s  vs time")
    dos.line_chart(df_DoS, x='Timestamp', y=['Fwd Pkts/s', 'Bwd Pkts/s', 'Flow Byts/s', 'Flow Pkts/s'])


    #plot Timestamp vs Flow Duration
    dos.write("Timestamp vs Flow Duration")
    dos.scatter_chart(df_DoS, x='Timestamp', y='Flow Duration')

    #Down/Up Ratio    vs time
    dos.write("Down/Up Ratio    vs time")
    dos.line_chart(df_DoS, x='Timestamp', y='Down/Up Ratio')

    #plot Src IP and Dst IP in network graph
    G = nx.Graph()
    for i in range(len(df_DoS)):
        G.add_edge(df_DoS['Src IP'][i], df_DoS['Dst IP'][i], weight=1)

    dos.write("Network Graph of Src IP and Dst IP")

    #put into plt figure
    fig = plt.figure(figsize=(20,20))
    nx.draw(G, with_labels=True)
    dos.pyplot(fig)


#ddos
with ddos:
    ddos.title("DDoS")
    ddos.write("Tools used: LOIC-HTTP, LOIC-UDP, HOIC. Attacker: Kali linux Victim:	Ubuntu 16.4 (Web Server)")
    df_DDoS = pd.read_csv('data/DDoS.csv')

    #plot Fwd Pkts/s  and Bwd Pkts/s  vs time
    ddos.write("Fwd Pkts/s  and Bwd Pkts/s  vs time")
    ddos.line_chart(df_DDoS, x='Timestamp', y=['Fwd Pkts/s', 'Bwd Pkts/s', 'Flow Byts/s', 'Flow Pkts/s'])


    #plot Timestamp vs Flow Duration
    ddos.write("Timestamp vs Flow Duration")
    ddos.scatter_chart(df_DDoS, x='Timestamp', y='Flow Duration')

    #Down/Up Ratio    vs time
    ddos.write("Down/Up Ratio    vs time")
    ddos.line_chart(df_DDoS, x='Timestamp', y='Down/Up Ratio')

    #plot Src IP and Dst IP in network graph
    G = nx.Graph()
    for i in range(len(df_DDoS)):
        G.add_edge(df_DDoS['Src IP'][i], df_DDoS['Dst IP'][i], weight=1)

    ddos.write("Network Graph of Src IP and Dst IP")

    #put into plt figure
    fig = plt.figure(figsize=(20,20))
    nx.draw(G, with_labels=True)
    ddos.pyplot(fig)

 """



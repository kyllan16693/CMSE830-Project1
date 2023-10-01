import streamlit as st
import seaborn as sns
import pandas as pd
import altair as alt
import matplotlib.pyplot as plt
import networkx as nx


#df = pd.read_csv('data/final_dataset.csv')
df = pd.read_csv('data/minidata.csv')

st.write("""
# DDoS Attack Data

This app visualizes the DDoS Attack Data
""")

col1, col2 = st.columns(2)

#print out top 10 src ip addresses
#st.write("Top 10 Source IP Addresses")
#st.write(df['Src IP'].value_counts().head(10))
col1.write("Top 10 Source IP Addresses")
col1.write(df['Src IP'].value_counts().head(10))

#st.write("Top 10 Destination IP Addresses")
#st.write(df['Dst IP'].value_counts().head(10))
col2.write("Top 10 Destination IP Addresses")
col2.write(df['Dst IP'].value_counts().head(10))

col1, col2 = st.columns(2)
#st.write("Top 10 Source IP and Port Pairs")
col1.write("Top 10 Source IP and Port Pairs")
col1.write(df[['Src IP', 'Src Port']].value_counts().head(10))
col1.write("Most source ports are random")

col2.write("Top 10 Destination IP and Port Pairs")
col2.write(df[['Dst IP', 'Dst Port']].value_counts().head(10))
col2.write("Most destination ports are 80 as it is the default port for HTTP")

#plot Timestamp vs Flow Duration
st.write("Timestamp vs Flow Duration")
st.scatter_chart(df, x='Timestamp', y='Flow Duration')


#plot Src IP and Dst IP in network graph 


G = nx.Graph()
for i in range(len(df)):
    G.add_edge(df['Src IP'][i], df['Dst IP'][i], weight=1)

st.write("Network Graph of Src IP and Dst IP")
#put into plt figure
fig = plt.figure(figsize=(20,20))
nx.draw(G, with_labels=True)
st.pyplot(fig)

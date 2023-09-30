import streamlit as st
import seaborn as sns
import pandas as pd
import altair as alt


df = pd.read_csv('data/final_dataset.csv')

#only keep the first 10000 rows
df = df.iloc[:10000]

#download the data to a csv file


st.write("""
# DDoS Attack Data

This app visualizes the DDoS Attack Data
""")

#print out top 10 src ip addresses
st.write("Top 10 Source IP Addresses")
st.write(df['Src IP'].value_counts().head(10))

st.write("Top 10 Destination IP Addresses")
st.write(df['Dst IP'].value_counts().head(10))

#plot Timestamp vs Flow Duration
st.write("Timestamp vs Flow Duration")
st.altair_chart(df['Timestamp'], df['Flow Duration'])

#plot Src IP and Dst IP in network graph 
import networkx as nx

G = nx.Graph()
for i in range(100000):
    if G.has_edge(df['Src IP'][i], df['Dst IP'][i]):
        G[df['Src IP'][i]][df['Dst IP'][i]]['weight'] += 1
    else:
        G.add_edge(df['Src IP'][i], df['Dst IP'][i], weight=1)

st.write("Network Graph of Src IP and Dst IP")
nx.draw(G, with_labels=False, node_size=10, font_size=8, width=0.5)


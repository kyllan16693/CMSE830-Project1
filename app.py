import streamlit as st
import seaborn as sns
import pandas as pd
import altair as alt
import matplotlib.pyplot as plt
import networkx as nx

#df = pd.read_csv('data/final_dataset.csv')
#df = pd.read_csv('data/minidata.csv')

st.write("""
# DDoS Attack Data

This app visualizes attack anomolies on a network.
""")

option = st.selectbox(
        'Which dataset would you like to use?',
        ('10k', '100k', '1m', '5m', 'full'))

@st.cache_data
def load_data(option):
    #choose option size of dataset defuatl 10k
    

    #load in the data
    if option == '10k':
        df = pd.read_csv('data/10kdata.csv')
    elif option == '100k':
        df = pd.read_csv('data/100kdata.csv')
    elif option == '1m':
        df = pd.read_csv('data/1mdata.csv')
    elif option == '5m':
        df = pd.read_csv('data/5mdata.csv')
    else:
        df = pd.read_csv('data/fulldata.csv')
    return df

df = load_data(option)



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


#make a bar chart of the protocols
st.write("Protocols Used")
st.bar_chart(df['Protocol'].value_counts())

#side by side bar chart of ports used
col1, col2 = st.columns(2)
col1.write("Source Ports Used")
col1.bar_chart(df['Src Port'].value_counts())

col2.write("Destination Ports Used")
col2.bar_chart(df['Dst Port'].value_counts())

#plot histogram of  'Fwd Pkt Len Mean' and 'Bwd Pkt Len Mean'
col1, col2 = st.columns(2)
col1.write("Histogram of forward packet length mean")
col1.bar_chart(df['Fwd Blk Rate Avg'])

col2.write("Histogram of backward packet length mean")
col2.bar_chart(df['Bwd Blk Rate Avg'])




#correration matrix remove all non numeric columns
@st.cache_data
def corr_matrix(df):
    df_corr = df.select_dtypes(include=[float, int])
    corr_matrix = df_corr.corr()
    fig, ax = plt.subplots()
    sns.heatmap(corr_matrix, ax=ax)
    return fig

st.write("Correlation Matrix")
#plt.figure(figsize=(20,20))
st.pyplot(corr_matrix(df))



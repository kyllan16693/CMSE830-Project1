import streamlit as st
import seaborn as sns
import pandas as pd
import altair as alt
import matplotlib.pyplot as plt
import networkx as nx

#df = pd.read_csv('data/final_dataset.csv')
#df = pd.read_csv('data/minidata.csv')

st.title("""
# DDoS Attack Data

This app visualizes attack anomolies on a network.
""")

#datasets: bruteforce, dos, ddos, infiltration, bot
#tab for each dataset

bruteforce, dos, ddos, infiltration, bot = st.tabs(["Bruteforce", "DoS", "DDoS", "Infiltration", "Bot"])

#bruteforce
with bruteforce:
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


#infiltration
with infiltration:
    infiltration.title("Infiltration")
    infiltration.write("Tools used: Nmap. Attacker: Kali linux Victim:	Ubuntu 16.4 (Web Server)")
    df_Infiltration = pd.read_csv('data/Infiltration.csv')

    #plot Fwd Pkts/s  and Bwd Pkts/s  vs time
    infiltration.write("Fwd Pkts/s  and Bwd Pkts/s  vs time")
    infiltration.line_chart(df_Infiltration, x='Timestamp', y=['Fwd Pkts/s', 'Bwd Pkts/s', 'Flow Byts/s', 'Flow Pkts/s'])


    #plot Timestamp vs Flow Duration
    infiltration.write("Timestamp vs Flow Duration")
    infiltration.scatter_chart(df_Infiltration, x='Timestamp', y='Flow Duration')

    #Down/Up Ratio    vs time
    infiltration.write("Down/Up Ratio    vs time")
    infiltration.line_chart(df_Infiltration, x='Timestamp', y='Down/Up Ratio')

    #plot Src IP and Dst IP in network graph
    G = nx.Graph()
    for i in range(len(df_Infiltration)):
        G.add_edge(df_Infiltration['Src IP'][i], df_Infiltration['Dst IP'][i], weight=1)

    infiltration.write("Network Graph of Src IP and Dst IP")

    #put into plt figure
    fig = plt.figure(figsize=(20,20))
    nx.draw(G, with_labels=True)
    infiltration.pyplot(fig)


#bot
with bot:
    bot.title("Bot")
    bot.write("Tools used: LOIC-HTTP, LOIC-UDP, HOIC. Attacker: Kali linux Victim:	Ubuntu 16.4 (Web Server)")
    df_Bot = pd.read_csv('data/Bot.csv')

    #plot Fwd Pkts/s  and Bwd Pkts/s  vs time
    bot.write("Fwd Pkts/s  and Bwd Pkts/s  vs time")
    bot.line_chart(df_Bot, x='Timestamp', y=['Fwd Pkts/s', 'Bwd Pkts/s', 'Flow Byts/s', 'Flow Pkts/s'])


    #plot Timestamp vs Flow Duration
    bot.write("Timestamp vs Flow Duration")
    bot.scatter_chart(df_Bot, x='Timestamp', y='Flow Duration')

    #Down/Up Ratio    vs time
    bot.write("Down/Up Ratio    vs time")
    bot.line_chart(df_Bot, x='Timestamp', y='Down/Up Ratio')

    #plot Src IP and Dst IP in network graph
    G = nx.Graph()
    for i in range(len(df_Bot)):
        G.add_edge(df_Bot['Src IP'][i], df_Bot['Dst IP'][i], weight=1)

    bot.write("Network Graph of Src IP and Dst IP")

    #put into plt figure
    fig = plt.figure(figsize=(20,20))
    nx.draw(G, with_labels=True)
    bot.pyplot(fig)

    
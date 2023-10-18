import streamlit as st
import pandas as pd
import altair as alt
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np

pd.option_context('mode.use_inf_as_na', True)

df = pd.read_csv('data/clean_dataset.csv')
df.drop(columns=['Unnamed: 0'], inplace=True)
df['Label'] = df['Label'].replace({0: 'Benign', 1: 'Attack'})

st.title("How to prevent Cyber Attacks")
st.header("Background")



st.header("Network Analysis Building Blocks: Exploring Components")
st.write("In the world of network analysis, understanding the intricate components is crucial. Explore the core components that play a pivotal role in deciphering network data and uncovering valuable insights for improved decision-making and network security.")


tab1, tab2, tab3, tab4, tab5 = st.tabs(["Packet Analysis", "Subflow Analysis", "Flow Analysis", "Byte Analysis", "IAT Analysis"])

with tab1:
    st.header("Packet Analysis")
    st.write("A packet is a unit of data that is routed between an origin and a destination on a network. Packet analysis is a crucial component of network traffic analysis, as it provides a comprehensive view of the network traffic behavior. In this section, we will explore the packet metrics and their relationship with cyber attacks.")
    df_packet = df.filter(regex='Pkts|Label')

    x_axis = st.selectbox('Select x-axis', df_packet.drop(columns=['Label']).columns)
    y_axis = st.selectbox('Select y-axis', df_packet.drop(columns=['Label']).columns)

    st.scatter_chart(df_packet,
        x=x_axis,
        y=y_axis,
        color='Label')
    st.write("The graphic above shows the relationship between the packet metrics and the label. The x and y variables can be manipulated to explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Pkt Len or Pkt Len Var might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")




with tab2:
    st.header("Subflow Analysis")
    st.write("In the analysis of network traffic data, understanding subflows is essential. Subflows represent distinct segments within established network connections, providing a closer look at the behavior of data transmission.")
    df_subflow = df.filter(regex='Subflow|Label')

    x_axis = st.selectbox('Select x-axis', df_subflow.drop(columns=['Label']).columns)
    y_axis = st.selectbox('Select y-axis', df_subflow.drop(columns=['Label']).columns)

    st.scatter_chart(df_subflow,
        x=x_axis,
        y=y_axis,
        color='Label')


    st.write("Analyzing subflow metrics such as forward packets, forward bytes, backward packets, and backward bytes plays a crucial role in detecting cyber attacks. These metrics provide valuable insights into network traffic behavior. Manipulating the x and y variables in the graphic, and explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Subflow Fwd Pkts or Bwd Byts might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")

with tab3:
    st.header("Flow Analysis")
    st.write("A flow is a sequence of packets that share the same source and destination IP addresses, the same source and destination ports, and the same protocol. Flow analysis is a crucial component of network traffic analysis, as it provides a comprehensive view of the network traffic behavior. In this section, we will explore the flow metrics and their relationship with cyber attacks.")
    df_flow = df.filter(regex='Flow|Label')

    x_axis = st.selectbox('Select x-axis', df_flow.drop(columns=['Label']).columns)
    y_axis = st.selectbox('Select y-axis', df_flow.drop(columns=['Label']).columns)

    st.scatter_chart(df_flow,
        x=x_axis,
        y=y_axis,
        color='Label')
    st.write("(IAT stands for Inter-Arrival Time, which refers to the time duration between the arrivals of consecutive network packets or events.)")
    st.write("The graphic above shows the relationship between the flow metrics and the label. The x and y variables can be manipulated to explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Flow Fwd Pkts or Flow Bwd Byts might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")


with tab4:
    st.header("Byte Analysis")
    st.write("Bytes are the fundamental units of data transmission in a network. Byte analysis is a crucial component of network traffic analysis, as it provides a comprehensive view of the network traffic behavior. In this section, we will explore the byte metrics and their relationship with cyber attacks.")
    df_byte = df.filter(regex='Byts|Label')

    x_axis = st.selectbox('Select x-axis', df_byte.drop(columns=['Label']).columns)
    y_axis = st.selectbox('Select y-axis', df_byte.drop(columns=['Label']).columns)

    st.scatter_chart(df_byte,
        x=x_axis,
        y=y_axis,
        color='Label')
    st.write("The graphic above shows the relationship between the byte metrics and the label. The x and y variables can be manipulated to explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Fwd Byts or Bwd Byts might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")

with tab5:
    st.header("IAT Analysis")
    st.write("Inter-Arrival Time (IAT) refers to the time duration between the arrivals of consecutive network packets or events. IAT analysis is a crucial component of network traffic analysis, as it provides a comprehensive view of the network traffic behavior. In this section, we will explore the IAT metrics and their relationship with cyber attacks.")
    df_IAT = df.filter(regex='IAT|Label')

    x_axis = st.selectbox('Select x-axis', df_IAT.drop(columns=['Label']).columns)
    y_axis = st.selectbox('Select y-axis', df_IAT.drop(columns=['Label']).columns)

    st.scatter_chart(df_IAT,
        x=x_axis,
        y=y_axis,
        color='Label')
    st.write("The graphic above shows the relationship between the IAT metrics and the label. The x and y variables can be manipulated to explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Fwd IAT Tot or Bwd IAT Tot might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")






st.header("Port Analysis")
col1, col2 = st.columns(2)

with col1:
    st.write("Source Ports:")
    st.write(df['Src Port'].value_counts())
with col2:
    st.write("Destination Ports:")
    st.write(df['Dst Port'].value_counts())
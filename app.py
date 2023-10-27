import streamlit as st
import pandas as pd
import altair as alt
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, mean_squared_error, r2_score
pd.option_context('mode.use_inf_as_na', True)

df = pd.read_csv('data/clean_dataset.csv')
df.drop(columns=['Unnamed: 0'], inplace=True)
df['Label'] = df['Label'].replace({0: 'Benign', 1: 'Attack'})
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()

# sidebar
st.sidebar.header("Network terms definitions:")
st.sidebar.write(
    "Packet (Pkts): A unit of data moving between network points.")
st.sidebar.write(
    "Byte (Byts): The basic data transmission unit in networks (8 bits).")
st.sidebar.write(
    "Flow: A series of packets sharing common IP addresses, ports, and protocol.")
st.sidebar.write(
    "Subflow: A distinct segment within an active network connection.")
st.sidebar.write(
    "Inter-Arrival Time (IAT): The time gap between consecutive network packet arrivals.")
st.sidebar.write(
    "Window (Win): A range in time in which packets can be accepted by a network device.")
st.sidebar.write("Activity (Act): The active state of a network connection.")
st.sidebar.write(
    "Segment (Seg): A data piece divided for network transmission.")
st.sidebar.write("Idle: The inactive state of a network connection.")
st.sidebar.write(
    "HTTP: A protocol that is the foundation of web data communication on the Internet.")
st.sidebar.write(
    "HTTPS: A more Secure version of HTTP protocol for safe online transactions.")
st.sidebar.write(
    "DNS: Translates domain names to IP addresses for web communication.")
st.sidebar.write(
    "IP Address: Unique label assigned to devices for network identification.")


# main page
st.markdown("<h1 style='text-align: center;'>Cyber Attack Data Explorer</h1>",
            unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: grey; font-style: italic;'>Kyllan Wunder</p>",
            unsafe_allow_html=True)

st.write("In the rapidly evolving digital landscape, cyberattacks have emerged as a persistent and formidable challenge. Among the most prevalent are Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks. DoS attacks involve a malicious actor overwhelming a targeted system, network, or service with a surge of traffic, often from a single source, rendering it inaccessible to legitimate users. DDoS attacks take this tactic to a more sophisticated level, orchestrating an onslaught from multiple sources, thereby increasing the magnitude of disruption. The primary goal in both cases is to cripple the target's functionality, causing inconvenience and potentially financial losses.")


# Illustrating DoS and DDoS Attacks
st.header("Illustrating DoS and DDoS Attacks")

dos_graph = nx.DiGraph()
dos_graph.add_edge("Attacker", "Target")

ddos_graph = nx.DiGraph()
ddos_graph.add_edge("Attacker", "Target")

servers = ["Server 1", "Server 2", "Server 3", "Server 4", "Server 5"]
for server in servers:
    ddos_graph.add_edge("Attacker", server)
    ddos_graph.add_edge(server, "Target")

node_positions = {
    "Attacker": (0, 0.5),
    "Target": (1, 0.5),
}
for server in servers:
    node_positions[server] = (
        0.5, (servers.index(server) + 1) / (len(servers) + 1))

fig, ax = plt.subplots(figsize=(12, 6))
plt.title("Denial of Service (DoS)\n(Single Attack Point)")
nx.draw(dos_graph, node_positions, with_labels=True,
        node_size=5000, node_color='lightblue')
st.pyplot(fig)

st.write("In a DoS scenario, a single attacker targets a single server to launch an attack. The visual representation highlights the simplicity of this approach, which involves a single point of attack and a single point of failure.")

fig, ax = plt.subplots(figsize=(12, 6))
plt.title("Distributed Denial of Service (DDoS)\n(Multiple Attack Points)")
nx.draw(ddos_graph, node_positions, with_labels=True,
        node_size=5000, node_color='lightblue')
st.pyplot(fig)

st.write("In a DDoS scenario, multiple attackers target multiple servers to launch an attack. The visual representation highlights the complexity of this approach, which involves multiple points of attack and could include multiple points of failure.")

# differences in attack vs benign traffic
st.header("Differences in Traffic")

col1, col2 = st.columns(2)

with col1:
    #st.header("Benign Traffic")
    #center
    st.markdown("<h3 style='text-align: center;'>Benign Traffic</h3>", unsafe_allow_html=True)
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.title("Benign Traffic Bytes per Second")
    plt.hist(np.log(df[df['Label'] == 'Benign']
             ['Flow Byts/s']).replace([np.inf, -np.inf], np.nan))
    st.pyplot(fig)
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.title("Benign Traffic Packets per Second")
    plt.hist(np.log(df[df['Label'] == 'Benign']
             ['Flow Pkts/s']).replace([np.inf, -np.inf], np.nan))
    st.pyplot(fig)

with col2:
    #st.header("Attack Traffic")
    #center
    st.markdown("<h3 style='text-align: center;'>Attack Traffic</h3>", unsafe_allow_html=True)
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.title("Attack Traffic Bytes per Second")
    plt.hist(np.log(df[df['Label'] == 'Attack']
             ['Flow Byts/s']).replace([np.inf, -np.inf], np.nan))
    st.pyplot(fig)
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.title("Attack Traffic Packets per Second")
    plt.hist(np.log(df[df['Label'] == 'Attack']
             ['Flow Pkts/s']).replace([np.inf, -np.inf], np.nan))
    st.pyplot(fig)

st.write("(Note: The log scale is used to better visualize the data, values are not represented accurately.)")
st.write("Looking at the distribution of bytes per second and packets per second, we can see that the benign traffic shows an almost normal distribution, while the attack traffic is skewed. This is because the attack traffic is much more concentrated than the benign traffic. This is a key difference between the two types of traffic, and can be used to identify attacks as it is much more uniform than benign traffic.")


# port analysis
st.header("Port Traffic Patterns")
col1, col2, col3 = st.columns(3)

with col1:
    st.write("Source Ports:")
    st.write(df['Src Port'].value_counts())
with col2:
    st.write("Destination Ports:")
    st.write(df['Dst Port'].value_counts())
with col3:
    st.write("Total Ports:")
    st.write((df['Dst Port'].value_counts() +
             df['Src Port'].value_counts()).sort_values(ascending=False))

st.markdown("Port analysis is fundamental for network traffic examination. It provides insights into communication patterns and security risks.\n- **Port 80** is HTTP (Hypertext Transfer Protocol), the protocol for the web. It is the most commonly used port for web traffic.\n - **Port 443** is HTTPS (Hypertext Transfer Protocol Secure), the protocol for secure web traffic. It is meant to replace HTTP with a more secure connection.\n- **Port 53** is for mapping domain names to IP addresses (DNS). \n- **Port 3389** is Remote Desktop Protocol, the protocol for remote access to a computer.\n- **Port 445** is used by Microsoft Directory Services for Active Directory and for the Server Message Block.")


# analysis tabs
st.header("Network Features Analysis")
st.write("In the world of network analysis, understanding the intricate components is crucial. Explore the core components that play a pivotal role in deciphering network data and uncovering valuable insights for improved decision-making and network security.")


tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["Packet Analysis", "Byte Analysis", "Flow Analysis", "Subflow Analysis", "IAT Analysis"])

with tab1:
    st.header("Packet Analysis")
    st.write("A packet is a unit of data that is routed between an origin and a destination on a network. Packet analysis is a crucial component of network traffic analysis, as it provides a comprehensive view of the network traffic behavior. In this section, we will explore the packet metrics and their relationship with cyber attacks.")
    df_packet = df.filter(regex='Pkts|Label')

    x_axis = st.selectbox(
        'Select x-axis', df_packet.drop(columns=['Label']).columns, index=0)
    y_axis = st.selectbox(
        'Select y-axis', df_packet.drop(columns=['Label']).columns, index=1)

    st.scatter_chart(df_packet,
                     x=x_axis,
                     y=y_axis,
                     color='Label')
    st.write("The graphic above shows the relationship between the packet metrics and the label. The x and y variables can be manipulated to explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Pkt Len or Pkt Len Var might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")


with tab2:
    st.header("Byte Analysis")
    st.write("Bytes are the fundamental units of data transmission in a network. Byte analysis is a crucial component of network traffic analysis, as it provides a comprehensive view of the network traffic behavior. In this section, we will explore the byte metrics and their relationship with cyber attacks.")
    df_byte = df.filter(regex='Byts|Label')

    x_axis = st.selectbox(
        'Select x-axis', df_byte.drop(columns=['Label']).columns)
    y_axis = st.selectbox(
        'Select y-axis', df_byte.drop(columns=['Label']).columns)

    st.scatter_chart(df_byte,
                     x=x_axis,
                     y=y_axis,
                     color='Label')
    st.write("The graphic above shows the relationship between the byte metrics and the label. The x and y variables can be manipulated to explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Fwd Byts or Bwd Byts might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")


with tab3:
    st.header("Flow Analysis")
    st.write("A flow is a sequence of packets that share the same source and destination IP addresses, the same source and destination ports, and the same protocol. Flow analysis is a crucial component of network traffic analysis, as it provides a comprehensive view of the network traffic behavior. In this section, we will explore the flow metrics and their relationship with cyber attacks.")
    df_flow = df.filter(regex='Flow|Label')

    x_axis = st.selectbox(
        'Select x-axis', df_flow.drop(columns=['Label']).columns, index=3)
    y_axis = st.selectbox(
        'Select y-axis', df_flow.drop(columns=['Label']).columns, index=4)

    st.scatter_chart(df_flow,
                     x=x_axis,
                     y=y_axis,
                     color='Label')
    st.write("The graphic above shows the relationship between the flow metrics and the label. The x and y variables can be manipulated to explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Flow Fwd Pkts or Flow Bwd Byts might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")


with tab4:
    st.header("Subflow Analysis")
    st.write("In the analysis of network traffic data, understanding subflows is essential. Subflows represent distinct segments within established network connections, providing a closer look at the behavior of data transmission.")
    df_subflow = df.filter(regex='Subflow|Label')

    x_axis = st.selectbox(
        'Select x-axis', df_subflow.drop(columns=['Label']).columns, index=1)
    y_axis = st.selectbox(
        'Select y-axis', df_subflow.drop(columns=['Label']).columns, index=2)

    st.scatter_chart(df_subflow,
                     x=x_axis,
                     y=y_axis,
                     color='Label')

    st.write("Analyzing subflow metrics such as forward packets, forward bytes, backward packets, and backward bytes plays a crucial role in detecting cyber attacks. These metrics provide valuable insights into network traffic behavior. Manipulating the x and y variables in the graphic, and explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Subflow Fwd Pkts or Bwd Byts might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")


with tab5:
    st.header("IAT Analysis")
    st.write("Inter-Arrival Time (IAT) refers to the time duration between the arrivals of consecutive network packets or events. IAT analysis is a crucial component of network traffic analysis, as it provides a comprehensive view of the network traffic behavior. In this section, we will explore the IAT metrics and their relationship with cyber attacks.")
    df_IAT = df.filter(regex='IAT|Label')

    x_axis = st.selectbox(
        'Select x-axis', df_IAT.drop(columns=['Label']).columns, index=0)
    y_axis = st.selectbox(
        'Select y-axis', df_IAT.drop(columns=['Label']).columns, index=1)

    st.scatter_chart(df_IAT,
                     x=x_axis,
                     y=y_axis,
                     color='Label')
    st.write("The graphic above shows the relationship between the IAT metrics and the label. The x and y variables can be manipulated to explore different aspects of the data, which can help identify patterns and anomalies associated with malicious activities. \n\nFor instance, a sudden and significant spike in Fwd IAT Tot or Bwd IAT Tot might indicate a distributed denial-of-service (DDoS) attack, where an abnormal amount of data is sent or received within a short period. Conversely, examining the ratio of these metrics and their patterns over time could reveal normal, benign traffic behavior. By empowering users to experiment with these variables, they can better understand network patterns and make informed decisions regarding potential threats or benign traffic.")


# below tabs


# using nearest neighbors to classify attack or benign
st.header("Using Nearest Neighbors to Classify Attack or Benign")
st.write("The nearest neighbors algorithm is a classification algorithm that classifies data points based on their proximity to other data points. In this case, the data points are network traffic data points, and the algorithm classifies them as either attack or benign. The algorithm works by calculating the distance between the data point in question and the k nearest neighbors. The algorithm then classifies the data point based on the majority class of the k nearest neighbors. The k value can be changed to see how it affects the classification.")

st.write("View the results of the model I have created then change the hyper parameters to see how it affects the model, see if you can improve the model!")

st.header("Model hyper parameters")
st.write("View the results of my model then change the hyper parameters to see how it affects the model, see if you can improve the model!")

col1, col2 = st.columns(2)

with col1:
    subsets = st.multiselect('Select data subsets to use', [
                             'Pkts', 'Byts', 'Flow', 'Subflow', 'IAT'], default=['Pkts', 'Byts'])
    regex = '|'.join(subsets) + '|Label'
    algorithm = st.selectbox(
        'Algorithm', ['auto', 'ball_tree', 'kd_tree', 'brute'])
    metric = st.selectbox(
        'Metric', ['minkowski', 'euclidean', 'manhattan', 'chebyshev'])
    weights = st.selectbox('Weights', ['uniform', 'distance'])
with col2:
    leaf_size = st.slider('Leaf Size', 1, 100, 30)
    p = st.slider('P', 1, 10, 2)
    neighbors = st.slider('Number of Neighbors', 1, 20, 5)
    test_size = st.slider('Test Size', 0.1, 0.5, 0.2)

df_nn = df.filter(regex=regex)
df_nn['Label'] = df_nn['Label'].replace({'Benign': 0, 'Attack': 1})
df_nn = df_nn.replace([np.inf, -np.inf], np.nan)
df_nn = df_nn.dropna()

X = df_nn.drop(columns=['Label'])
y = df_nn['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

model = KNeighborsClassifier(n_neighbors=neighbors, algorithm=algorithm,
                             leaf_size=leaf_size, p=p, metric=metric, weights=weights)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

st.header("Model results")

col3, col4 = st.columns(2)
with col3:
    confusion_df = pd.DataFrame(confusion_matrix(y_test, y_pred))
    confusion_df.rename(columns={0: 'True Benign', 1: 'True Attack'}, index={
                        0: 'predicted Benign', 1: 'predicted Attack'}, inplace=True)
    st.write(confusion_df)
    st.write("The confusion matrix shows the results of the classification, we want all of the values to land in the true positive and true negative quadrants. A true positive is when the data given is from an attack and the model predicts that it is an attack. A true negative is when the data given is benign and the model predicts that it is benign.")
with col4:
    st.write("Accuracy: ", round(model.score(X_test, y_test)*100,4), "%")
    st.write("Mean Squared Error: ", round(mean_squared_error(y_test, y_pred),4))
    st.write("R Squared: ", round(r2_score(y_test, y_pred),4))
    st.write("The accuracy of the model is the percentage of data points that were correctly classified. The mean squared error is the average of the squared differences between the predicted and actual values. The R squared is the proportion of the variance in the dependent variable that is predictable from the independent variable(s).")


st.header("Model details")

col5, col6 = st.columns(2)
with col5:
    st.write("This model used the following features: ", X.columns)
with col6:
    st.write("The model was trained on ", len(X_train), " or ",
             round(len(X_train)/len(X)*100, 3), "% of the data.")
    st.write("The model was tested on ", len(X_test), " or ",
             round(len(X_test)/len(X)*100, 3), "% of the data.")
    st.write("The model use the following parameters: ", model.get_params())


# data
st.header("About the Data")
st.write("The data is from a collaborative project between the Communications Security Establishment (CSE) & the Canadian Institute for Cybersecurity (CIC)")
st.write("The data is available at https://www.unb.ca/cic/datasets/ids-2018.html or https://registry.opendata.aws/cse-cic-ids2018/")
st.write("The attack data is from simulated attacks on a network, the benign data is from normal network traffic.")


# end
st.markdown("<p style='text-align: center;'><a href='https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png' target='https://github.com/kyllan16693/Cyber-Attack-Data-Explorer'><img src='https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png' width='100'></a></p>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'><a href='https://kyllan.dev' target='hhttps://kyllan.dev'>kyllan.dev</a></p>", unsafe_allow_html=True)

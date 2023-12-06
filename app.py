import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv('data/clean_dataset_v2.csv')
df = df.loc[:, ~df.columns.str.contains('Unnamed')]


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
    #Benign Traffic
    st.markdown("<h3 style='text-align: center;'>Benign Traffic</h3>", unsafe_allow_html=True)
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.title("Benign Traffic Bytes per Second")
    plt.hist(np.log(df[df['Label'] == 'Benign']
             ['Flow Byts/s']+1).replace([np.inf, -np.inf], np.nan))
    plt.ylim(0, 26000)
    st.pyplot(fig)
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.title("Benign Traffic Packets per Second")
    plt.hist(np.log(df[df['Label'] == 'Benign']
             ['Flow Pkts/s']+1).replace([np.inf, -np.inf], np.nan))
    plt.ylim(0, 20000)
    st.pyplot(fig)

with col2:
    #Attack Traffic
    st.markdown("<h3 style='text-align: center;'>Attack Traffic</h3>", unsafe_allow_html=True)
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.title("Attack Traffic Bytes per Second")
    plt.hist(np.log(df[df['Label'] == 'Attack']
             ['Flow Byts/s']+1).replace([np.inf, -np.inf], np.nan))
    plt.ylim(0, 26000)
    st.pyplot(fig)
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.title("Attack Traffic Packets per Second")
    plt.hist(np.log(df[df['Label'] == 'Attack']
             ['Flow Pkts/s']+1).replace([np.inf, -np.inf], np.nan))
    plt.ylim(0, 20000)
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
                     color="Label")
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
st.header("Using Machine Learning to Predict Attacks")
st.write("The k-nearest neighbors algorithm is a classification algorithm that classifies data points based on their proximity to other data points. In this case, the data points are network traffic data points, and the algorithm classifies them as either attack or benign. The algorithm works by calculating the distance between the data point in question and the k nearest neighbors (k being any nuber we want). The algorithm then classifies the data point based on the majority class of the k nearest neighbors. The k value can be changed to see how it affects the classification.")

st.subheader("KNN Model hyper parameters")
st.write("View the results of my model then change the hyper parameters to see how it affects the model, see if you can improve the model!")

col1, col2 = st.columns(2)

with col1:
    subsets = st.multiselect('Select data subsets to use', [
                             'Pkts', 'Byts', 'Flow', 'Subflow', 'IAT'], default=['Pkts', 'Byts'])
    regex = '|'.join(subsets) + '|Label.num'
    algorithm = st.selectbox(
        'Select the algorithm used to compute the nearest neighbors', ['auto', 'ball_tree', 'kd_tree', 'brute'])
    metric = st.selectbox(
        'Select the function used to compute distance between points', ['minkowski', 'euclidean', 'manhattan', 'chebyshev'])
    
with col2:
    neighbors = st.slider('Number of Neighbors used for classification', 1, 20, 5)
    test_size = st.slider('Percentage of data used for testing', 0.05, 0.5, 0.2)
    weights = st.selectbox('Select the function used in prediction', ['uniform', 'distance'])

df_nn = df.filter(regex=regex)

X = df_nn.drop(columns=['Label.num'])
y = df_nn['Label.num']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

knn_model = KNeighborsClassifier(n_neighbors=neighbors, algorithm=algorithm, metric=metric, weights=weights)
knn_model.fit(X_train, y_train)

y_pred = knn_model.predict(X_test)

tab1, tab2 = st.tabs(['KNN Model Results', 'KNN Model Details(for nerds)'])

with tab1:
    st.subheader("KNN Model results")

    data = {' ': ['predicted Benign', 'predicted Attack'],
        'True Benign': ['True Negative - This is when the model correctly predicts that the data it was given is benign. This model predicted this correctly '+ str(confusion_matrix(y_test, y_pred)[0][0]) +' times.', 'False Positive - This is when the data given is benign and the model incorrectly predicts that it is an attack. This model predicted this incorrectly '+ str(confusion_matrix(y_test, y_pred)[0][1]) +' times.'],
        'True Attack': ['False Negative - This is when the data given is an attack and the model incorrectly predicts that it is benign. This model predicted this incorrectly '+ str(confusion_matrix(y_test, y_pred)[1][0]) +' times.', 'True Positive - This is when the model correctly predicts that the data it was given is an attack. This model predicted this correctly '+ str(confusion_matrix(y_test, y_pred)[1][1]) +' times.']}
    df_confusion = pd.DataFrame(data)

    st.table(df_confusion.set_index(' '))
        
    st.write("This model can accurately predict if a data point is an attack or benign with an accuracy of ", round(knn_model.score(X_test, y_test)*100, 3), "%. This means that the model can correctly classify ", confusion_matrix(y_test, y_pred)[0][0] + confusion_matrix(y_test, y_pred)[1][1] , " out of ", len(X_test), " test data points.")

    st.write("While this model is very good it could be improved to reducde the number of false negatives (There is an attack happening but we think it is benign). This is the worst case scenario as it means that an attack could continue to happen without being detected.")

with tab2:
    st.subheader("KNN Model details")

    col5, col6 = st.columns(2)
    with col5:
        st.write("This model used the following features: ", X.columns)
    with col6:
        st.write("The model was trained on ", len(X_train), " datapoints or ",
                round(len(X_train)/len(X)*100, 3), "% of the data.")
        st.write("The model was tested on ", len(X_test), " datapoints or ",
                round(len(X_test)/len(X)*100, 3), "% of the data.")
        st.write("The model use the following parameters: ", knn_model.get_params())


st.write("While this model is very accurate it takes ", X.columns.shape[0], " features to achieve this accuracy. This is not ideal as it means that the model is very complex and would take awhile to run. If we want to predict attacks within a few seconds we need to reduce the number of features used.")

st.header("Reducing the number of features")

st.write("In order to reduce the number of features we need we can use principal component analysis (PCA). PCA is a technique that reduces the number of features by combining them into a smaller number of features. This is done by finding the features that have the most variance and combining them into a new feature. This is done until the desired number of features is reached. This is a good way to reduce the number of features as it combines features that are similar and removes features that are not useful.")

df_pca = df.select_dtypes(include=[np.number])

nums = np.arange(df_pca.shape[1])

var_ratio = []
for num in nums:
  pca = PCA(n_components=num)
  pca.fit(df_pca)
  var_ratio.append(np.sum(pca.explained_variance_ratio_))

fix, ax = plt.subplots(figsize=(10,6))
plt.grid()
plt.plot(nums,var_ratio,marker='o')
plt.xlabel('n_components')
plt.ylabel('Explained variance ratio')
plt.title('n_components vs. Explained Variance Ratio')
st.pyplot(plt)


pca = PCA(n_components=df_pca.shape[1])
pca.fit(df_pca)

df_pca_result = pd.DataFrame(pca.components_, columns=df_pca.columns)
df_pca_result.rename(index={0: "Percent of variance explained"}, inplace=True)

col7, col8 = st.columns(2)
with col7:
    st.write("From this PCA we can see which features explain the most variance in the data, here are the top 10:")
    st.write("Nine of the top ten are are Inter-Arrival Time(IAT) features. This makes sense as during an attack an influx of packets would be sent to the target, which would cause the IAT to change drasticly.")
with col8:
    st.table(df_pca_result.iloc[0].abs().sort_values(ascending=False).head(10))


#random forest model

st.header("Random Forest Model")

st.write("Using the top 3 features from the PCA above we can create a random forest model that can predict almost as well but is less complex.")

st.subheader("RF Model hyper parameters")
st.write("View the results of my model then change the hyper parameters to see how it affects the model, see if you can improve the model!")

col1, col2 = st.columns(2)
with col1:
    n_estimators = st.slider('Number of trees in the forest', 45, 75, 60)
    min_samples_split = st.slider('Minimum number of samples required to split an internal node', 1, 10, 2)
    min_samples_leaf = st.slider('Minimum number of samples required to be at a leaf node', 1, 10, 2)

with col2:
    test_size = st.slider('Percentage of data used for testing the model', 0.05, 0.5, 0.2)
    bootstrap = st.selectbox('Whether bootstrap samples are used when building trees', [True, False], index=1)
    n_jobs = st.slider('Number of jobs to run in parallel', 1, 100, 10)



X = df[df_pca_result.iloc[0].abs().sort_values(ascending=False).head(3).index]
y = df['Label.num']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size)

rf_model = RandomForestClassifier(n_estimators=n_estimators, max_depth=None, min_samples_split=min_samples_split, min_samples_leaf=min_samples_leaf, max_features=None, bootstrap=bootstrap, n_jobs=n_jobs)
rf_model.fit(X_train, y_train)


y_pred = rf_model.predict(X_test)


tab3, tab4 = st.tabs(['RF Model Results', 'RF Model Details(for nerds)'])

with tab3:
    st.subheader("RF Model results")
    data = {' ': ['predicted Benign', 'predicted Attack'],
        'True Benign': ['True Negative - This model predicted this correctly '+ str(confusion_matrix(y_test, y_pred)[0][0]) +' times.', 'False Positive - This model predicted this incorrectly '+ str(confusion_matrix(y_test, y_pred)[0][1]) +' times.'],
        'True Attack': ['False Negative - This model predicted this incorrectly '+ str(confusion_matrix(y_test, y_pred)[1][0]) +' times.', 'True Positive - This model predicted this correctly '+ str(confusion_matrix(y_test, y_pred)[1][1]) +' times.']}
    df_confusion = pd.DataFrame(data)

    st.table(df_confusion.set_index(' '))

    st.write("This model can accurately predict if a data point is an attack or benign with an accuracy of ", round(rf_model.score(X_test, y_test)*100, 3), "%. This means that the model can correctly classify ", confusion_matrix(y_test, y_pred)[0][0] + confusion_matrix(y_test, y_pred)[1][1] , " out of ", len(X_test), " test data points. I did some hyper parameter tuning to decrease the number of false negatives (There is an attack happening but we think it is benign).")
    st.write("This model is much less complex than the previous model as it only uses the top ", X.columns.shape[0], " features from above which are: " + ', '.join(X.columns) + ".")

with tab4:
    st.subheader("RF Model details")
    st.write("The model was trained on ", len(X_train), " datapoints or ", round(len(X_train)/len(X)*100, 3), "% of the data and was tested on ", len(X_test), " datapoints or ", round(len(X_test)/len(X)*100, 3), "% of the data.")
    st.write("The model use the following parameters: ", rf_model.get_params())



st.header("Final Thoughts")

st.write("It is hard to find a balance between the number of features and the accuracy of the model, not to mention what model to use and what hyper parameters to use. Below is a graph of 5 different models using an increasing number of features, which were ranked in order of explained variation in the data from the PCA above.")

st.image('images/model_comparison.png')

st.write("Using just 3 features random forest, k-nearist neighbors, and decision tree models can all achieve an accuracy of around 90%. This is very good as reducing the number of features allows these models to run faster and have the ability to decet attacks in real time.")
st.write("And with only 23 features the random forest and decision tree models can achieve an accuracy better than my previous k-nearest neighbors model which used all the data.")

st.write("With new and more powerful monitoring and analysis tools emerging, network traffic analysis is becoming more accessible and efficient. The ability to analyze network traffic data in real-time is crucial for detecting and preventing cyber attacks. By leveraging the power of machine learning, we can detect and prevent cyber attacks in real-time, thereby improving network security and reducing the risk of data breaches.")


# data
st.header("About the Data")
st.write("The data is from a collaborative project between the Communications Security Establishment (CSE) & the Canadian Institute for Cybersecurity (CIC)")
st.write("The data is available at https://www.unb.ca/cic/datasets/ids-2018.html or https://registry.opendata.aws/cse-cic-ids2018/")
st.write("The attack data is from simulated attacks on a network, the benign data is from normal network traffic.")


# end
st.markdown("<p style='text-align: center;'><a href='https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png' target='https://github.com/kyllan16693/Cyber-Attack-Data-Explorer'><img src='https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png' width='100'></a></p>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'><a href='https://kyllan.dev' target='hhttps://kyllan.dev'>kyllan.dev</a></p>", unsafe_allow_html=True)
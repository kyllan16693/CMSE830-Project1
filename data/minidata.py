import pandas as pd
df = pd.read_csv('final_dataset.csv')


#only keep the first 10000 rows
#df[:10000].to_csv('10kdata.csv')
#only keep the first 100000
#df[:100000].to_csv('100kdata.csv')
#only keep the first 1000000
#df[:1000000].to_csv('1mdata.csv')
#only keep the first 5000000
#df[:5000000].to_csv('5mdata.csv')
#all data
#df.to_csv('fulldata.csv')


#data is split by days where different types of attacks are simulated
# FTP-BruteForce, Wed-14-02-2018
# SSH-Bruteforce, Wed-14-02-2018
# DoS-GoldenEye, Thurs-15-02-2018
# DoS-Slowloris, Thurs-15-02-2018
# DoS-SlowHTTPTest, Fri-16-02-2018
# DoS-Hulk, Fri-16-02-2018
# DDoS attacks-LOIC-HTTP, Tues-20-02-2018
# DDoS-LOIC-UDP, Tues-20-02-2018
# DDOS-LOIC-UDP, Wed-21-02-2018
# DDOS-HOIC, Wed-21-02-2018
# Brute Force -Web, Thurs-22-02-2018
# Brute Force -XSS, Thurs-22-02-2018
# SQL Injection, Thurs-22-02-2018
# Brute Force -Web, Fri-23-02-2018
# Brute Force -XSS, Fri-23-02-2018
# SQL Injection, Fri-23-02-2018
# Infiltration, Wed-28-02-2018
# Infiltration, Wed-28-02-2018
# Infiltration, Thursday-01-03-2018
# Infiltration, Thursday-01-03-2018
# Infiltration, Thursday-01-03-2018
# Bot, Friday-02-03-2018
# Bot, Friday-02-03-2018


#split the data into the different attacks filtering by date in the dataframe it is called timestamp and includes the time
df_Bruteforce = df[df['Timestamp'].str.contains('14/02/2018|22/02/2018|23/02/2018')]
df_DoS = df[df['Timestamp'].str.contains('15/02/2018|16/02/2018')]
df_DDoS = df[df['Timestamp'].str.contains('20/02/2018|21/02/2018')]
df_Infiltration = df[df['Timestamp'].str.contains('28/02/2018|01/03/2018')]
df_Bot = df[df['Timestamp'].str.contains('02/03/2018')]

#write these to csv files
df_Bruteforce.to_csv('Bruteforce.csv')
df_DoS.to_csv('DoS.csv')
df_DDoS.to_csv('DDoS.csv')
df_Infiltration.to_csv('Infiltration.csv')
df_Bot.to_csv('Bot.csv')




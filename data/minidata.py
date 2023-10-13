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
# DoS-GoldenEye, Thurs-15-02-2018 *
# DoS-Slowloris, Thurs-15-02-2018 *
# DoS-SlowHTTPTest, Fri-16-02-2018 *
# DoS-Hulk, Fri-16-02-2018 *
# DDoS attacks-LOIC-HTTP, Tues-20-02-2018 *
# DDoS-LOIC-UDP, Tues-20-02-2018 *
# DDOS-LOIC-UDP, Wed-21-02-2018 *
# DDOS-HOIC, Wed-21-02-2018 *
# Brute Force -Web, Thurs-22-02-2018 *
# Brute Force -XSS, Thurs-22-02-2018 *
# SQL Injection, Thurs-22-02-2018 *
# All other data is benign
#12/06/2010' '13/06/2010' '15/02/2018' '21/02/2018' '22/02/2018'
#'20/02/2018' '16/02/2018' '04/07/2017' '03/07/2017'



""" #split the data into the different attacks filtering by date in the dataframe it is called timestamp and includes the time
df_Bruteforce = df[df['Timestamp'].str.contains('14/02/2018|22/02/2018|23/02/2018')]
df_DoS = df[df['Timestamp'].str.contains('15/02/2018|16/02/2018')]
df_DDoS = df[df['Timestamp'].str.contains('20/02/2018|21/02/2018')]
df_Benign = df[df['Timestamp'].str.contains('12/06/2010|13/06/2010|04/07/2017|03/07/2017')]

#write these to csv files
df_Bruteforce.to_csv('Bruteforce.csv')
df_DoS.to_csv('DoS.csv')
df_DDoS.to_csv('DDoS.csv')
df_Benign.to_csv('Benign.csv') """



#make a subset of the data only with columns that have the word 'Flag' in them and the label column and the timestamp column
""" namelist = ["Flow", "Flags", "Byts", "Pkts", "IAT", "Subflow"]
for name in namelist:
    df_subset = df.filter(regex=name+'|Label')
    #df_subset = df_subset.drop(columns=['Unnamed: 0'])
    df_subset['Label'] = df_subset['Label'].map({'Benign': 0, 'ddos': 1})
    df_subset.to_csv(name+'_subset.csv')
    print(name+'_subset.csv'+ ' created')
 """



df = df.drop(columns=['Unnamed: 0'])
df = df.drop(columns=['Flow ID'])
df = df.dropna()
df['Label'] = df['Label'].eq('ddos').mul(1)
df.sample(n=200000).to_csv('clean_dataset.csv')
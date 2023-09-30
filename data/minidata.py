import pandas as pd
df = pd.read_csv('final_dataset.csv')

#only keep the first 10000 rows
df = df.iloc[:10000]

#download the data to a csv file
df.to_csv('minidata.csv')

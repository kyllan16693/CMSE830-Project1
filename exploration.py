import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
import hiplot as hip


#df = pd.read_csv('data/final_dataset.csv')
df = pd.read_csv('data/1mdata.csv')


#print column names
print(df.columns)

#print counts of each column
#print(df.count())
#print all of them non shortened
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
pd.set_option('display.width', None)
#print(df.head())
#print(df.count())

#print num of rows
#print(len(df))



#print all the unique days 
#print(df['Timestamp'].str.split(' ').str[0].unique())
print(df['Label'].unique()) 

#print haed of columns that dont contain Avg, Min, Max, Std, Mean, Tot
#print(df.columns[~df.columns.str.contains('Avg|Min|Max|Std|Mea|Tot')])

hip.Experiment.from_dataframe(df).display()
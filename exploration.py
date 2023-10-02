import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx


df = pd.read_csv('data/final_dataset.csv')
#df = pd.read_csv('data/minidata.csv')

#print column names
print(df.columns)

#print counts of each column
#print(df.count())
#print all of them non shortened
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
print(df.count())
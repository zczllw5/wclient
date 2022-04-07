import csv
import pandas as pd

with open("1_3_connected.txt") as fin, open("1_3_connected.csv", 'w') as fout:
    o=csv.writer(fout)
    for line in fin:
        o.writerow(line.split())

df = pd.read_csv('1_3_connected.csv')
df1 = df.T
df1.to_csv('1_3_connected_output.csv')
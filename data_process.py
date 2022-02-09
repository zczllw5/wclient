import csv
import pandas as pd

with open("top_1h.txt", "w") as my_output_file:
    with open("top_1h.csv", "r") as my_input_file:
        [ my_output_file.write(" ".join(row)+ " ") for row in csv.reader(my_input_file)]
    my_output_file.close()
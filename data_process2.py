import csv
import pandas as pd

with open("non_forward_secrecy_ciphers.txt", "w") as my_output_file:
    with open("non_(EC)DHE_ciphers.txt", "r") as my_input_file:
        ciphers = my_input_file.read().split(":")
        substring = "DHE"
        for cipher in ciphers:
            if substring not in cipher:
                my_output_file.write(cipher + ":")

with open("forward_secrecy_ciphers.txt", "w") as my_output_file:
    with open("non_(EC)DHE_ciphers.txt", "r") as my_input_file:
        ciphers = my_input_file.read().split(":")
        substring = "DHE"
        for cipher in ciphers:
            if substring in cipher:
                my_output_file.write(cipher + ":")
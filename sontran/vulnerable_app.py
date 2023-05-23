import os, subprocess, sqlite3
import requests
import time
import math

###############################
# CWE-1041: Use of Redundant Code
# CWE-561: Dead Code
# CWE-570: Expression is Always False
def calculate_surface_area(s, r, d):
    pi = 3.14159
    surface_area = 0
    result = 0
    isSValid = False
    isRValid = False

    if(s > 2.0 and r > 0.0):
        isRValid = True
        isRValid = True # set wrong variable
        surface_area = (pi * r * s + pi * pow(r, 2))/d
        if (isRValid and isSValid):
            print("This is dead code !!!")
    elif(s > 0.0 and r > 1.0):
        isRValid = True
        isRValid = True # set wrong variable
        surface_area = (pi * r * s + pi * pow(r, 2))/d
        if (isSValid):
            print("This is also dead code !!!")
    
    if (isRValid and isSValid):
        print("This is also another dead code !!!")
        result = surface_area

    return result

###############################
# CWE-732: Incorrect Permission Assignment for Critical Resource
def create_some_file(filename, mode):
    f = open(filename, "w")
    f.write("Secret phase: YOLO")
    f.close()
    os.chmod(filename, 0x777)

###############################
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# attack by inject command "--option_a --option_b; chmod 777 ./injection_command.sh; ./injection_command.sh"
def execute_internal_script():
    internal_script_name = "example_script.sh"
    options = input("Enter a options to execute: ")
    os.system(internal_script_name + " " + options)

###############################
# CWE-94: Improper Control of Generation of Code ('Code Injection')
# attack by inject "__import__('subprocess').getoutput('rm -r *')"
# CWE-190: Integer Overflow or Wraparound
# overflow of exp()
def calc_sum_of_exp_value():
    sum = 0
    numbers = eval(input("Enter a comma-separated list of numbers: "))
    for num in numbers:
        sum = sum + math.exp(num)
    print(f"Sum of {numbers} = {sum}")

###############################
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
def execute_user_query():
    user_query = input("Enter a SQL query: ")
    execute_sql_query("SELECT * FROM users WHERE username = '" + user_query + "';")

###############################
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
# CWE-703: Improper Check or Handling of Exceptional Conditions
def read_file():
    try:
        file_path = input("Enter the file path to read: ")
        with open(file_path, "r") as file:
            content = file.read()
            print("File content:", content)
    except:
        pass

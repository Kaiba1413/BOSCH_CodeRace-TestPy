import pandas as pd
import requests
import subprocess
from django.db import connection

###############################
table_name = "orders"
df = pd.read_sql(sql='''
    SELECT * FROM {};
'''.format(table_name))

###############################
secret = "1283712938721983721"
def encryptInTheNewbieWay(text):
    return text ^ secret

###############################
data = requests.get("https://www.sciencedirect.com/", verify = False)
print(data.status_code)

###############################
domain = input("Enter the Domain: ")
output = subprocess.check_output(f"nslookup {domain}", shell=True, encoding='UTF-8')
print(output)

###############################
def find_user(username):
    with connection.cursor() as cur:
        cur.execute(f"""select username from USERS where name = '%s'""" % username)
        output = cur.fetchone()
    return output

###############################
# CWE-1041: Use of Redundant Code
# CWE-561: Dead Code
# CWE-570: Expression is Always False
def calculate_surface_area(s, r):
    pi = 3.14159
    surface_area = 0
    result = 0
    isSValid = False
    isRValid = False

    if(r > 0.0 and s > 0.0):
        isRValid = True
        isSValid = True
        surface_area = pi * r * s + pi * pow(r, 2)
        if (not isRValid or not isSValid):
            print("This is dead code !!!")

    if(r > 1.0 and s > 0.0):
        isRValid = True
        isRValid = True
        surface_area = pi * r * s + pi * pow(r, 2)
    
    if (isRValid and isSValid):
        result = surface_area

    return result

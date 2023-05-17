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
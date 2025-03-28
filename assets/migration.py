import psycopg2
import os
from dotenv import load_dotenv

load_dotenv('../.env')
PSQL_PASSWORD = os.getenv('PSQL_PASSWORD')

connection = psycopg2.connect(
    host='localhost',
    user='postgres',
    password=PSQL_PASSWORD
)
cur = connection.cursor()

sql1 = "CREATE TABLE users ( \
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY, \
    username text NOT NULL UNIQUE, \
    password text NOT NULL, \
    nodetype text \
);"
sql2 = "CREATE TABLE sessions ( \
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY, \
    session_token text NOT NULL \
);"
sqls = [sql1, sql2]
for sql in sqls:
    cur.execute(sql)

connection.commit()
cur.close()
connection.close()
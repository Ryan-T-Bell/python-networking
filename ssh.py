import pymysql
import pandas as pd
import pymysql as pymysql

ip_address = '208.67.249.102'
user = 'stockread'
pwd = 'Deloitte'
port = '3306'
database = 'StockAnalysis'

connection = pymysql.connect(
			host=ip_address,
			port=port,
			user=user,
			password=pwd,
			db=database,
			charset='utf8mb4',
			cursorclass=pymysql.cursors.DictCursor
			)

cursor = connection.cursor()

sql = r'SELECT TOP 10 * FROM RealTime_StockData '

cursor.execute('USE ()'.format(database))
cursor.execute('SHOW TABLES')
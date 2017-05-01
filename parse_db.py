MySQLServer = {"db1":{"tb1":["col1", "col2", "col3"], "tb2":["col1","col2"]}, "db2":{"tb1":[], "tb2":["col1","col2", "col3"]}}

for database, table_dictionnary in MySQLServer.iteritems():
    print "Database: " + str(database)

    for table, column_list in table_dictionnary.iteritems():
        print "Table: " + str(table)

        for column in column_list:
            print column

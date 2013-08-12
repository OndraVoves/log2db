#!/usr/bin/env python

import datetime
import pygeoip
import sqlite3
import os.path
import hashlib
import argparse

def create_db( connection, filename ):
    cursor = connection.cursor()

    # create a table
    cursor.execute("""CREATE TABLE ip_log
                      (in_ip text,
                       in_port text,
                       out_port_type text,
                       out_port text,
                       datetime text, 
                       geoip_country_code text,
                       hash text )
                   """)

    pass

def main():
    parser = argparse.ArgumentParser(description='Read SMC log file and write it to sqlite db with geoip support' )
    parser.add_argument( 'dbfile', metavar='dbfile', type=str, help='sqlite db file' )
    parser.add_argument( 'logfile', metavar='logfile', type=str, help='log file' )
    args = parser.parse_args()
    
    if not os.path.isfile( args.logfile ):
        print( 'Log file \'{}\' does not exist.'.format(args.logfile) )
        return 1
    
    with open( args.logfile ) as f:
        if not os.path.exists(args.dbfile):
            conn = sqlite3.connect(args.dbfile)
            create_db( conn, args.dbfile )
        else:
            conn = sqlite3.connect(args.dbfile)

        gi4 = pygeoip.GeoIP('/usr/share/GeoIP/GeoIP.dat', pygeoip.MEMORY_CACHE)
        
        c = conn.cursor()
        
        line_n = 0
        for line in f:
            line_n += 1
            
            ls = line.split()
            if len( ls ) != 14:
                print( "Skiping invalid log line {0}".format(line_n) )
                continue
            
            date_str = " ".join(ls[1:5])
            in_ip = ls[9].split(":")[0]
            geoip_country_code = gi4.country_code_by_addr(in_ip)
            
            entry = { "in_ip":in_ip,
                      "in_port":ls[9].split(":")[1],
                      "out_port_type":ls[11],
                       "out_port":ls[13],
                       "datetime": datetime.datetime.strptime(date_str, '%b %d %H:%M:%S %Y'),
                       "geoip_country_code": geoip_country_code }

            hash = hashlib.sha256( line ).hexdigest( )

            sql = "insert into ip_log select '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}' where Not Exists (select hash from ip_log where hash = '{6}')"
            
            c.execute( sql.format(
                        entry[ 'in_ip' ],
                        entry[ 'in_port' ],
                        entry[ 'out_port_type' ],
                        entry[ 'out_port' ],
                        entry[ 'datetime' ],
                        entry[ 'geoip_country_code' ],
                        hash ) )
            pass
        conn.commit()
    pass

if __name__ == "__main__":
    exit( main() )

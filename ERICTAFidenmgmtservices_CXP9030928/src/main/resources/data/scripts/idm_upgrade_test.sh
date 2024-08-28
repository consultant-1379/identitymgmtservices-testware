#!/bin/sh

# The script invokes IdentityManagementService Rest Interface to confirm
# that IdentityManagementService is functioning during the time period when IDMService package gets upgraded.
#
# Usage: ./idm_upgrade_service.sh [<number in minutes>]
# Example Usage: ./idm_upgrade_service.sh
#    Description: Script will run for 10 minutes
#
# Example Usage: ./idm_upgrade_service.sh 5
#    Description: Script will run for 5 minutes
#

LOG_FILE=/tmp/idm_update_test_`date '+%Y_%m_%d_%H_%M'`.log

###############################################
# Function Log
# Arguments: message to log
###############################################
Log()
{
   /bin/echo `date '+%B %d %Y %T' `": $1" >> $LOG_FILE
}

###############################################
# Function LogAndDisplay
# Arguments: message to log
###############################################
LogAndDisplay()
{
   /bin/echo "$1"
   /bin/echo `date '+%B %d %Y %T' `": $1" >> $LOG_FILE
}


GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
. $GLOBAL_PROPERTY_FILE

SECADMIN_PASSKEY=/ericsson/tor/data/idenmgmt/secadmin_passkey
SECADMIN_PWD=TestPassw0rd

# obtaining security admin password
if [ -r "${SECADMIN_PASSKEY}" ]; then
   SECADMIN_PWD=`echo ${default_security_admin_password} | openssl enc -a -d -aes-128-cbc -salt -kfile ${SECADMIN_PASSKEY}`
fi

# figuring out httpd hostname
APACHE_HOST=`getent hosts httpd`
APACHE_HOST=`echo ${APACHE_HOST} | awk '{print $NF}' `

Log "INFO: APACHE_HOST=$APACHE_HOST"

# obtaining cookies by sending a request to ENM login page
curl -c /tmp/upgrade_cookies.txt --insecure -X POST "https://${APACHE_HOST}/login?IDToken1=administrator&IDToken2=${SECADMIN_PWD}" >/dev/null

if [ ! -f /tmp/upgrade_cookies.txt ]; then
    LogAndDisplay "ERROR:Cookie creation failed"
    exit 1
fi

# attempt to validate service by sending a rest interface for removePosixAttributes invoke against non-exist user.
# it will return a json string with error code 404 which is indicating IDM Service is working.
REQUEST="curl -b /tmp/upgrade_cookies.txt --cacert /ericsson/tor/data/certificates/sso/ssoserverapache.crt -X DELETE https://${APACHE_HOST}/idmservice/people/userdoesnotexist/posixattributes"

# invoking a curl command using REST interface to IdentityManagementService to see it is functioning..
result=`$REQUEST 2> /dev/null`
Log "INFO: Result from curl command=$result"

if [[ "$result" = *"404"* ]]; then
    REQUEST_STRING=${REQUEST}
fi

Log "INFO: Request string=${REQUEST_STRING}"
if [ "${REQUEST_STRING}" == "" ]; then
    LogAndDisplay "ERROR:SERVICE UNAVAILABLE or COOKIE IS NOT VALID, check /tmp/upgrade_cookies.txt file.."
    exit 1
fi

#RUN the command for ? minutes
count=0
success=0
failure=0
total_execution=120

LogAndDisplay ""
if [ $# -gt 0 ]; then
    total_execution=$(($1*60/5))
    LogAndDisplay "Script will run for $1  minutes, $total_execution times"
else
    LogAndDisplay "Script will run for 10 minutes... "
fi

LogAndDisplay "Refer to the log file ${LOG_FILE} to see the detail"

while [ $count -le $total_execution ]
do
    result=`$REQUEST_STRING`
    count=`expr $count + 1`

    if [[ "$result" = *"404"* ]]; then
        success=`expr $success + 1`
    else
        failure=`expr $failure + 1`
        LogAndDisplay "TOTAL EXECUTION : $count, SUCCESS : $success, FAILURE : $failure"
    fi
    Log "TOTAL EXECUTION : $count, SUCCESS : $success, FAILURE : $failure"
    sleep 5
done

LogAndDisplay "TOTAL EXECUTION : $count, SUCCESS : $success, FAILURE : $failure"

rm -rf /tmp/upgrade_cookies.txt
exit 0

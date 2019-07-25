#!/usr/bin/python
#
# This script triggers a scan to launch through SecurityCenter.
# It will either prompt for information, read from the command line
# or read from environment variables.  It will not read passwords
# from the command line.
#
# Version 1.1a
#		Add functionality to determine if scan has completed.
#
# Version 1.1 - 2019-03-14
#        Updated to use pytenable library, use argparse, and support launching scans in Tenable.io
#
# Version 1.0 - Initial version, written by James Smith
#
# Requires the following:
#   pip install pytenable docker
#
# Sample usage:
#
# TIO_ACCESS_KEY=*****************************
# TIO_SECRET_KEY=*****************************
# DOCKER_USERNAME=*************
# DOCKER_PASSWORD=*************
# ./tdup.py --image java:latest



import sys
import os
import json
import argparse
from tenable.io import TenableIO



################################################################
# Description: Launches a scan by name
################################################################
# Input:
#        conn = the connection handle to Tenable.sc or Tenable.io
#        scan = The name of the scan to launch
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#        Put the scan name in the scan list filter
#
################################################################
def LaunchScan(DEBUG,conn,scanname,scanid):
    if DEBUG:
        if scanid == "":
            print("Launching scan", scanname)
        else:
            print("Launching scan",scanid)

    #Determine if we connected to Tenable.io or Tenable.sc
    TIO = False
    if str(type(conn)) == "<class 'tenable.io.TenableIO'>":
        TIO = True

    if TIO:
        if scanid == "":
            for scan in conn.scans.list():
                if scan['name'] == scanname:
                    print("Found scan ID",scan['id'],"for scan name",scan['name'])
                    scanid=int(scan['id'])
        conn.scans.launch(scanid)
        return(True)
    else:
        if scanid == "":
            for scan in conn.scans.list():
                if scan['name'] == scanname:
                    print("Found scan ID",scan['id'],"for scan name",scan['name'])
                    scanid=int(scan['id'])
        conn.scans.launch(scanid)
        return(True)

    return(False)

#Return codes:
# 2 = other
# 1 = running
# 0 = completed
# -1 = error
#Does not currently work for Tenable.sc
def CheckScanStatus(DEBUG,conn,scanname,scanid):
    if DEBUG:
        if scanid == "":
            print("Checking scan status for ", scanname)
        else:
            print("Checking scan status for",scanid)

    #Determine if we connected to Tenable.io or Tenable.sc
    TIO = False
    if str(type(conn)) == "<class 'tenable.io.TenableIO'>":
        TIO = True

    if TIO:
        if scanid == "":
            for scan in conn.scans.list():
                if scan['name'] == scanname:
                    print("Found scan ID",scan['id'],"for scan name",scan['name'])
                    scanid=int(scan['id'])
        result=conn.scans.status(scanid)
        if DEBUG:
            print("Scan status:",result)
        if result == "completed":
            return(0)
        elif result == "running" or result == "stopping":
            return(1)
        elif result == "scheduled":
            return(2)

    return(-1)


#Attempts to make a connection to Tenable.io
def ConnectIO(DEBUG,accesskey,secretkey,host,port):
    #Create the connection to Tenable.io
    try:
        tio=TenableIO(accesskey, secretkey)
    except:
        print("Error connecting to Tenable.io")
        return(False)

    return(tio)


def testInCloud(DEBUG,conn):
    x=0
    #If the image isn't already on this system, get it
    client = docker.from_env()
    print(client.containers.list())


    #Push the image to the Tenable.io cloud.

    #Wait for the Tenable.io cloud to complete analysis

    #Download the results


def testInOnprem(DEBUG,conn):
    x=0

def checkResults(DEBUG,results,maxcrit,maxhigh,maxmed,maxlow,maxmalware,maxrisk,email):


################################################################
# Start of program
################################################################
#Set debugging on or off
DEBUG=False
parser = argparse.ArgumentParser(description="Uploads a Docker container to Tenable.io and handles the results")
parser.add_argument('--accesskey',help="The Tenable.io access key",nargs=1,action="store")
parser.add_argument('--secretkey',help="The Tenable.io secret key",nargs=1,action="store")
parser.add_argument('--dockerusername',help="The Docker Hub username",nargs=1,action="store")
parser.add_argument('--dockerpassword',help="The Docker Hub password",nargs=1,action="store")
parser.add_argument('--tenablerepo',help="The name of the Tenable.io repository where the image and/or results should be stored.",nargs=1,action="store")
parser.add_argument('--tenabletag',help="The name of the tag to give this image in Tenable.io.",nargs=1,action="store")
parser.add_argument('--host',help="The Tenable host. (Default for Tenable.io is cloud.tenable.com)",nargs=1,action="store",default=["cloud.tenable.com"])
parser.add_argument('--port',help="The Tenable port. (Default is 443)",nargs=1,action="store",default=["443"])
parser.add_argument('--image',help="The image name and tag",nargs=1,action="store")
parser.add_argument('--debug',help="Turn on debugging",action="store_true")
parser.add_argument('--onprem',help="Use the on-prem scanner.  Assumes \"tenableio-docker-consec-local.jfrog.io/cs-scanner:latest\" is downloaded",action="store_true")
parser.add_argument('--maxcrit',help="The maximum number of critical vulnerabilities before a failure is given (Defaults to 0, can be \"any\")",nargs=1,action="store_true",default=["0"])
parser.add_argument('--maxhigh',help="The maximum number of high vulnerabilities before a failure is given (Defaults to 0, can be \"any\")",nargs=1,action="store_true",default=["0"])
parser.add_argument('--maxmed',help="The maximum number of medium vulnerabilities before a failure is given (Defaults to 0, can be \"any\")",nargs=1,action="store_true",default=["0"])
parser.add_argument('--maxlow',help="The maximum number of low vulnerabilities before a failure is given (Defaults to 0, can be \"any\")",nargs=1,action="store_true",default=["0"])
parser.add_argument('--maxmalware',help="The maximum number of malware detected before a failure is given (Defaults to 0, can be \"any\")",nargs=1,action="store_true",default=["0"])
parser.add_argument('--maxrisk',help="The maximum risk score before a failure is given (Defaults to 0, can be \"any\")",nargs=1,action="store_true",default=["0"])
parser.add_argument('--email',help="Send the results to these emails. A comma separated list of emails (Assumes a mail transfer agent is running on system)",nargs=1,action="store_true",default=[""])
args=parser.parse_args()


DEBUG=False
ONPREM=False
if args.debug:
    DEBUG=True
    print("Debugging is enabled.")

if args.onprem:
    ONPREM=True
    print("Using the on-prem scanner.")


# Pull as much information from the environment variables about the system to which to connect
# Where missing then initialize the variables with a blank or pull from command line.
if os.getenv('TIO_ACCESS_KEY') is None:
    accesskey = ""
else:
    accesskey = os.getenv('TIO_ACCESS_KEY')

# If there is an access key specified on the command line, this override anything else.
try:
    if args.accesskey[0] != "":
        accesskey = args.accesskey[0]
except:
    nop = 0

if os.getenv('TIO_SECRET_KEY') is None:
    secretkey = ""
else:
    secretkey = os.getenv('TIO_SECRET_KEY')
# If there is an  secret key specified on the command line, this override anything else.
try:
    if args.secretkey[0] != "":
        secretkey = args.secretkey[0]
except:
    nop = 0


username=""
#Look for a Tenable.io username
if os.getenv('DOCKER_USERNAME') is None:
    username = ""
else:
    username = os.getenv('DOCKER_USERNAME')
    if DEBUG:
        print("Detected Docker username")
try:
    if args.username[0] != "":
        username = args.username[0]
        if DEBUG:
            print("Detected Docker username")
        #Since a specific username was found on the command line, assume the user does not want to poll Tenable.io
        secretkey = ""
        accesskey = ""
except:
    username=""

#Look for a SecurityCenter password
scpassword=""
if os.getenv('DOCKER_PASSWORD') is None:
    scpassword = ""
else:
    scpassword = os.getenv('DOCKER_PASSWORD')
    if DEBUG:
        print("Detected DOCKER password")
try:
    if args.password[0] != "":
        if DEBUG:
            print("Detected DOCKER password")
        scpassword = args.password[0]
except:
    scpassword=""

#Look for a port
port="443"
try:
    if args.port[0] != "":
        port = args.port[0]
except:
    port = "443"

#Look for a host
host="cloud.tenable.com"
try:
    if args.host[0] != "":
        host = args.host[0]
except:
    host = "cloud.tenable.com"


image=""
try:
    if args.image[0] != "":
        scanname = args.image[0]
except:
    scanname = ""




if accesskey != "" and secretkey != "":
    print("Connecting to cloud.tenable.com with access key", accesskey, "to report on assets")
    try:
        if args.host[0] != "":
            host = args.host[0]
    except:
        host = "cloud.tenable.com"
    conn = ConnectIO(DEBUG, accesskey, secretkey, host, port)

if conn == False:
    print("There was a problem connecting.")
    exit(-1)

#Upload demo dashboards
if OMPREM == False:
    print("Testing the image using the Tenable.io cloud")
    results=testInCloud(DEBUG,conn)
else:
    print("Testing the image using the Tenable.io on-premise inspector")
    results=testInOnprem(DEBUG,conn)

checkResults(DEBUG,results,args.maxcrit[0],args.maxhigh[0],args.maxmed[0],args.maxlow[0],args.maxmalware[0],args.maxrisk[0],args.maxemail[0])
#!/usr/bin/python
import csv
import json
import pprint
import datetime
import re
import sys
import time
import configparser
import adal
import requests
from argparse import ArgumentParser
from urllib.parse import urlparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

"""
 This is setup to use certificate based authentication.  It is possible to use a self signed cert.
 Create an application registration in Azure -> App Registrations -> New application registration.
 The Endpoints button next to new is helpful.

 You'll need to upload your certificate, and note your thumbprint.
 The application will also require an azure admin to assign the following required application permissions:
    * Read mail in all mailboxes

You'll also need to fill out config.template and save as config.ini	
	
Usage:
  get-read-links -u pwnd@contoso.com -c cert1.pem -s 2018-08-01T6:00:00Z -e 2018-08-03T20:00:00Z

  This will scan pwnd@contoso.com for all messages received between the two date times (inclusive)
  and return URLs or Fileshare links in the messages read, along with the message metadata all in csv.

 Requires python3
 Other useful permissions might be:
    * read and write all user mailbox settings (inbox rules)
    * read all usage reports
    * read all identity risk information
    * read your organizations security events

 Please see the python cryptography package's website for installation instructions.
 Once these application permissions have ben granted by an admin in azure, you should be able to run this against any
 user mailbox.
 

 The information inside such file can be obtained via app registration.
 https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki/Register-your-application-with-Azure-Active-Directory
"""

def get_paged_data(r, headers):
    """ Handle API query data retrieval that could be paginated or throttled
        We assume an initial query has already been made, with response object r.
        We check this response and fetch additional response pages as needed.
    """

    data = []

    if r.status_code == 429:
        print("WARNING throttling imposed! waiting " + str(r.headers['Retry-After']) + " seconds.\n")
        time.sleep(int(r.headers['Retry-After']))

    elif r.status_code != 200:
        print("ERROR " + str([r.status_code, r.text]) + "\n" + str(r.url))
        sys.exit(1)

    response = r.json()

    if 'value' not in response and 'body' not in response:
        # paginated queries have value attribute, single message queries do not
        print("ERROR no data response\n " + str(r.url))
        sys.exit(1)

    elif 'value' in response:

        for message in response['value']:
            data.append(message)

        while '@odata.nextLink' in response:
            r = requests.get(response['@odata.nextLink'], headers=headers)

            if r.status_code == 429:
                print("WARNING throttling imposed! waiting " + str(r.headers['Retry-After']) + " seconds.\n")
                time.sleep(int(r.headers['Retry-After']))
                # sys.exit(0)

            elif r.status_code != 200:
                print("ERROR " + str([r.status_code, r.text]) + "\n" + str(r.url))

            response = r.json()

            if 'value' not in response and 'body' not in response:
                print("ERROR no data response from " + str(r.url))
                sys.exit(1)
            else:
                for message in response['value']:
                    data.append(message)
        return data

    elif 'body' in response:
        data.append(r.json())

        while '@odata.nextLink' in response:
            r = requests.get(response['@odata.nextLink'], headers=headers)

            if r.status_code == 429:
                print("WARNING throttling imposed! waiting " + str(r.headers['Retry-After']) + " seconds.\n")
                time.sleep(int(r.headers['Retry-After']))
                # sys.exit(0)

            elif r.status_code != 200:
                print("ERROR " + str([r.status_code, r.text]) + "\n" + str(r.url))

            response = r.json()

            if 'value' not in response and 'body' not in response:
                print("ERROR no data response from " + str(r.url))
                sys.exit(1)
            else:
                data.append(r.json())
        return data

def get_links(body):
    """ Find all url or fileshare links in message body

    :param body: body of message in text format
    :return: list of links
    """
    MATCH_LINK = re.compile("<(\S*\:\/\/\S*)>")
    MATCH_SHARE = re.compile("(\S*\\\\\S*)")

    links = re.findall(MATCH_LINK, body)
    shares = re.findall(MATCH_SHARE, body)

    return links + shares


def main():
    parser = ArgumentParser()
    parser.add_argument('-r', '--resource', default='config.ini',
                        help='resource file with info unique to your environment')
    parser.add_argument('-u', '--user', help='upn to run queries against')
    parser.add_argument('-s', '--start', help='start time: ex 2018-01-02T01:00:00Z - Jan 2 2018, 1 AM GMT')
    parser.add_argument('-e', '--end', help='end time: ex 2018-01-02T01:00:00Z - Jan 2 2018, 1 AM GMT. Default=now')
    parser.add_argument('-o', '--output', help='output .csv to write.  Defaults to user+timestamp.csv')
    parser.add_argument('-c', '--certificate', help='certificate file you uploaded to azure and registered with app')
    parser.add_argument('-p', '--cert-password', help='password to read your certificate file')
    parser.add_argument('--silent', help='squelch all cli output', action="store_true")
    parser.add_argument('-t', '--token-only', help='print out token and quit', action="store_true")
    parser.add_argument('--token-only-outlook', help='print out token to legacy outlook api and quit',
                        action="store_true")
    args = parser.parse_args()

    # Ensure enough paramters are specified
    if not (args.token_only or args.token_only_outlook):
        if not (args.user and args.start and args.certificate):
            print("ERROR: When not running in --token-only, the following arguments are required:")
            print("--user, --start, --certificate")
            sys.exit(1)

    elif args.token_only or args.token_only_outlook:
        if not args.certificate:
            print("ERROR: When running --token-only you must specify --certificate as well")
            sys.exit(1)

    # Load variables

    QUERY_TIME_START = args.start
    QUERY_TIME_END = args.end
    QUERY_USER = args.user
    # manifest_file = args.manifest
    resource_file = args.resource
    TOKEN_ONLY = args.token_only
    SILENT = args.silent
    CERT_FILE = args.certificate
    CERT_PWD = args.cert_password

    # define query constants
    url1 = '/messages?$filter=receivedDateTime ge '
    url2 = ' and receivedDateTime le '
    urlFolderFilter = ' and parentFolderId ne '
    url4 = '&$select=id,lastModifiedDateTime,receivedDateTime,hasAttachments,internetMessageId,subject,isRead,sender,' \
           'from,toRecipients,replyTo'


    if args.end:
        QUERY_TIME_END = args.end
    else:
        QUERY_TIME_END = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.output:
        OUTPUT_FILE = args.output
    elif not (args.token_only or args.token_only_outlook):
        OUTPUT_FILE = QUERY_USER.split('@')[0] + datetime.datetime.now().strftime("%Y-%m-%dT%H-%M") + ".csv"

    if resource_file:
        config = configparser.ConfigParser()
        try:

            config.read(filenames='config.ini')
        except IOError:
            print("ERROR reading resource file")
            sys.exit(1)

        AUTHORITY_URL = config.get('DEFAULT', 'authority_url')
        TENANT_GUID = config.get('DEFAULT', 'tenant_guid')
        GRAPH_URL = config.get('DEFAULT', 'graph_url')
        OUTLOOK_URL = config.get('DEFAULT', 'outlook_url')
        CERTIFICATE_KEY = config.get('DEFAULT', 'certificate_key')
        API_VERSION = config.get('DEFAULT', 'api_version')
        URL_FILTER = config.get('DEFAULT', 'url_filter')
        APPLICATION_GUID = config.get('DEFAULT', 'application_guid')
    else:
        raise ValueError('ERROR Please provide config file with resource information.')

    ## load cert file

    try:

        with open(CERT_FILE, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=CERT_PWD, backend=default_backend())

    except IOError:
        print("ERROR unable to open " + CERT_FILE + " or certificate problem")
        sys.exit(1)
    except TypeError:
        print("ERROR Invalid filename specified for certificate")
        sys.exit(1)

    # Main logic begins

    if not SILENT:
        print(time.ctime() + ": Authorizing")

    context = adal.AuthenticationContext(AUTHORITY_URL, validate_authority=TENANT_GUID != 'adfs')

    # Get the GRAPH token or legacy Outlook token if requested.
    if args.token_only_outlook:
        token = context.acquire_token_with_client_certificate(OUTLOOK_URL, APPLICATION_GUID, key, CERTIFICATE_KEY)
    else:
        token = context.acquire_token_with_client_certificate(GRAPH_URL, APPLICATION_GUID, key, CERTIFICATE_KEY)

    if TOKEN_ONLY or args.token_only_outlook:
        print(token)
        print("Done")
        sys.exit(0)

    # get FolderID of SentItems folder
    headers = {'Authorization': 'Bearer ' + token['accessToken']}
    r = requests.get(GRAPH_URL + '/' + API_VERSION + '/users/' + QUERY_USER +
                     '/mailFolders?$filter=displayName eq \'Sent Items\'&$select=id', headers=headers)

    if r.status_code != 200:
        print("ERROR failed to retrieve mailFolders for user " + QUERY_USER)
        print("  query: " + str(r.url))
        sys.exit(1)
    sentFolderId = r.json()['value'][0]['id']
    urlFolderFilter += '\'' + sentFolderId + '\''


    endpoint_url = GRAPH_URL + '/' + API_VERSION + '/users/' + QUERY_USER + url1 + QUERY_TIME_START + \
                   url2 + QUERY_TIME_END + urlFolderFilter + url4

    if not SILENT:
        print(time.ctime() + ": Fetching list of emails")

    r = requests.get(endpoint_url, headers=headers)
    data = get_paged_data(r, headers)

    if not SILENT:
        print(time.ctime() + ": " + str(len(data)) + " messages found.")

    read = []  # list of read messages
    read_data = []  # body of read messages

    for message in data:
        if message['isRead']:
            read.append(message)

    if not SILENT:
        print(time.ctime() + ": " + str(len(read)) + " messages read.")

    headers['Prefer'] = "outlook.body-content-type=\"text\""

    for email in read:

        # Need to filter out SENT messages!



        endpoint_url = GRAPH_URL + '/' + API_VERSION + '/users/' + QUERY_USER + '/messages/' + \
                       email['id'] + \
                       '?$select=id,lastModifiedDateTime,receivedDateTime,hasAttachments,internetMessageId,subject,' \
                       'parentFolderId,isRead,isDraft,inferenceClassification,sender,from,toRecipients, ccRecipients,' \
                       'bccRecipients,replyTo,body'

        r = requests.get(endpoint_url, headers=headers)
        read_data.append(get_paged_data(r, headers))

    if not SILENT:
        print(time.ctime() + ": " + str(len(read_data)) + " messages retrieved.")

    emailswithlinks = 0  # number of discrete emails with URLS discovered
    all_links = []  # list of [URL, domain, email rx time, message id, subject, from address]

    # parse out the URLs from the message body
    for message in read_data:
        # scan for a URL in the message
        if "://" in message[0]['body']['content']:
            emailswithlinks += 1

            try:

                links = get_links(message[0]['body']['content'])
            except:
                print("call to get_links failed: " + str(message))

            for item in links:
                urlobj = urlparse(item)

                all_links.append([item, urlobj.netloc, message[0]['receivedDateTime'], message[0]['id'], message[0]['subject'],
                                  message[0]['from']['emailAddress']])

    if not SILENT:
        print(" Found " + str(emailswithlinks) + " emails with links and " + str(len(all_links)) + " links")

    numberfilteredlinks = 0
    filteredlinks = {}  # dict of domain, [link ane email info from above]

    for link in all_links:
        urlobj = urlparse(link[0])

        # if domain is not in filter and parent domain + TLD is not in filter
        # ex: if link domain is api.www.gmail.com, and www.gmail.com is in filter... skip link.
        if (urlobj.netloc not in URL_FILTER) and '.'.join(urlobj.netloc.split('.')[-2::]) not in URL_FILTER:
            # skip if domain is in filter
            numberfilteredlinks += 1

            # if we've already scanned this link AND domain+path is not already present, append
            if urlobj.netloc in filteredlinks and urlobj.netloc + urlobj.path not in filteredlinks[urlobj.netloc]:
                filteredlinks[urlobj.netloc].append(link)

            # otherwise, if we don't have this link domain yet, insert
            elif urlobj.netloc not in filteredlinks:
                filteredlinks[urlobj.netloc] = [link]


    if not SILENT:
        pp = pprint.PrettyPrinter(width=80)
        print("  filtered out " + str(len(all_links) - len(all_links)) + " out of " + str(len(all_links)))

        for key in sorted(filteredlinks.items()):
            x = [key[0], filteredlinks[key[0]]]
            pp.pprint(x)
        print(str(len(filteredlinks)) + " domains and " + str(numberfilteredlinks) + " links output")

    # no file output if no results
    if len(filteredlinks) > 0:
        with open(OUTPUT_FILE, 'w', encoding="utf-8") as f:
            fieldnames = ['url', 'domain', 'receivedDateTime', 'mailId', 'subject', 'sender']
            w = csv.writer(f, lineterminator='\n')
            w.writerow(fieldnames)

            for key, value in filteredlinks.items():
                for item in value:
                    w.writerow(item)
    else:
        if not SILENT:
            print("INFO No results, output file omitted")

    if not SILENT:
        if len(filteredlinks) > 0:
            print("INFO wrote output " + OUTPUT_FILE)

        print(time.ctime() + ": Done.")
    # check failures for permission full delegation on mailbox???


if __name__ == "__main__":
    main()



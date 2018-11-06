import os
import re
import sys
import datetime
from urllib.parse import urlparse
import click
import json


@click.command()
@click.option('-n', '--no-junk', is_flag=True, help='Skip items in junk folders.')
@click.option('-p', '--path', required=True, help='Path to exported Emails')
@click.option('-u', '--unique', is_flag=True, help='Return unique URLs only.')
def main(no_junk, path, unique):
    """

    :return:
    """
    if no_junk:
        print("Will skip junk email folder items")

    startime = datetime.datetime.now()
    print("started execution: " + str(startime))
    pathroot = path
    items = []
    urls = []
    errors = []

    for root, dirs, files in os.walk(pathroot):
        for name in files:
            items.append([os.path.join(pathroot,root), name])

    with click.progressbar(items, label="Parsing Emails") as data:
        for path, file in data:
            os.chdir(path)

            try:
                with open(file, "r", encoding="latin-1") as email:

                    content = email.read()
                    content = clean(content)
                    links = get_links(content)

                    if len(links) > 0:

                        MATCH_FROM = re.compile("From:[^A-Z]*([^<]*)")
                        MATCH_TIME = re.compile("Sent:[<\/b>\s]*([^<]*)")

                        m = re.search(MATCH_FROM, content)
                        if not isinstance(m, type(None)):
                            sender = m.group(0)
                        else:
                            sender = "None"
                        m = re.search(MATCH_TIME, content)

                        if not isinstance(m, type(None)):
                            send_time = m.group(0)
                        else:
                            send_time = "None"
                        urls.append([email.name, path.split(pathroot)[1], sender, send_time, links])

                    else:
                        pass

            except UnicodeDecodeError:
                    error = sys.exc_info()[1]
                    errors.append([file, path, error.args[1]])
                    continue

            except FileNotFoundError:
                    error = sys.exc_info()[1]
                    errors.append([file, path, error.args[1]])
                    continue

            except:
                    error = sys.exc_info()
                    print("error finding urls in message content: " + email.name + " " + str(error))
                    sys.exit(1)

    results = format_results(urls, unique, no_junk, errors)
    print("\nurls extracted:\n")
    print("encountered " + str(len(errors)) + " errors")
    print("collected " + str(len(items)) + " emails")
    print("collected " + str(len(urls)) + " urls")
    print("collected urls on " + str(len(results)) + " unique domains")

    with open(pathroot + '\data.json', 'w') as outfile:
        json.dump(results, outfile)
    print("wrote file " + pathroot + '\data.json')

    with open(pathroot + '\errors.json', 'w') as outfile2:
        #print(errors)
        json.dump(errors, outfile2)


    print("wrote file " + pathroot + '\errors.json')
    endtime = datetime.datetime.now()

    del results
    del urls
    del items

    print("execution took " + str(endtime - startime))
    sys.exit(0)


def format_results(metadata, unique, no_junk, errors):
    """
    reformat results into this format:
        [url netloc part [url_description, upn, subject, email_path, sender, timestamp, etc]]

        from this format:
         [subject, message_path, sender, send_time, links]

    :param urls: subject, path, list of url + description (if any)
    :return:
    """

    data = []

    for link in metadata:
        # clean subject line of html encoding

        subject = link[0]
        if "%3A" in subject:
            subject = subject.replace("%3A", ":")
        if "%" in subject:
            subject = subject.replace("%20", " ")
            subject = subject.replace("%21", "!")
            subject = subject.replace("%22", "\"")
            subject = subject.replace("%23", "#")
            subject = subject.replace("%24", "$")
            subject = subject.replace("%25", "%")

        subject = subject.replace(".msg", "")
        username = link[1].split("@")[0].strip("\\")
        upn = link[1][1:link[1].find(".")+4]
        email_path = link[1]
        email_path = email_path.replace(upn + " (Primary)", "")
        email_path = email_path.replace(upn + " (Archive)", "")
        email_path = email_path.replace(upn, "")
        email_path = email_path.replace("Top of Information Store", "")
        email_path = re.sub(r'\\{1,}', '/', email_path)

        sender = link[2]
        send_time = link[3]

        try:
            for url, text in link[4]:
                if "Junk" in email_path and no_junk:
                    continue

                urlobj = urlparse(url)
                url_domains = [x[0] for x in data]
                if urlobj.netloc not in url_domains:
                    # dedup URL based on domain
                    data.append([urlobj.netloc, [text, url, upn, subject, email_path, sender, send_time]])

                elif (urlobj.netloc in url_domains) and not unique:
                    match_index = url_domains.index(urlobj.netloc)
                    data[match_index][1].append([text, url, upn, subject, email_path, sender, send_time])


        except ValueError:
            print("error iterating over " + str(link[4]))
            print("there are " + str(len(link[4])) + " elements here")
            print(sys.exc_info())
            error = sys.exc_info()[1]
            errors.append([url, error.args])


        except IndexError:
            print("error on index value used")
            print(sys.exc_info())
            print("match index: " + str(match_index) + " for domain " + str(urlobj.netloc))
            error = sys.exc_info()[1]
            errors.append([url, error])

    return data


def get_links(body):
    """ Find all url or fileshare links in message body

    :param body: body of message in text format
    :return: list of links
    """
    if "x-apple-data-detectors" in body:
        pass

    #MATCH_LINK = re.compile("<(\S*\:\/\/\S*)>")
    MATCH_LINK = re.compile("href=\"(\S*\:\/\/\S*)\".*>([^\>]*)<\/a>")
    #MATCH_SHARE = re.compile("(\S*\\\\\S*)")

    links = re.findall(MATCH_LINK, body)
    #shares = re.findall(MATCH_SHARE, body)

    newlinks=[]

    for item in links:
        if "schemas.openxmlformats.org" in item or "w3.org" in item or "schemas.microsoft.com" in item:
            continue
        else:
            #print(item)
            #newlinks.append(item)
            newlinks.append([item[0], item[1]])

    #return newlinks + shares
    return newlinks


def clean(content):
    """

    :param content:
    :return:
    """
    start = content.find("<body")
    end = content.find("/body>")
    data = content[start:end+6]

    # check for encoded data that made it into body content
    data = ''.join(i for i in data if 128 > ord(i) > 31)

    return data


if __name__ == "__main__":
    main()

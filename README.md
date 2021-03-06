 The get-read-links tool has a few uses:
  * Return a token to microsoft graph for manual investigation in Postman or other API tool
  * Export a CSV with all url links in the specified user's office 365 mailbox.  Caveat:  Messages permanently deleted
    by the user will not have data available to us.
  * Output a list of urls and email metadata from a directory containing .msg files, recursively using parsefiles.
    
 For using the parsefiles utility, here are the reccomended options to use when exporting your Content Search results:
   * Output options: All items, excluding ones that have unrecognized format..
   * Export Exchange content as: Individual messages (enable de-dupe if you wish)
   * Export files in a compressed zip folder if you wish.  Option for single zip file is preferred, if available.

 Usage:
 get-read-links -u pwnd@contoso.com -c cert1.pem -s 2018-08-01T6:00:00Z -e 2018-08-03T20:00:00Z

 This will scan pwnd@contoso.com for all messages received between August first, 6 AM GMT and August third, 8PM GMT, 
 inclusive, and return URLs or fileshare links in the messages read, along with the message metadata all in csv.

 -r, --resource         Specify filename for configuration settings.  Default config.ini  
 -u, --user             Username of the Office 365 mailbox to investigate.  
 -s, --start            Start time to compare against message received timestamp  Format YYYY-MM-DDTHH:MM:SSZ  
 -e, --end              End time to compare against message received timestamp. Format YYYY-MM-DDTHH:MM:SSZ  
 -o, --output           Output filename to write.  Defautls to user+timestamp.csv  
 -c, --certificate      Local copy of certificate file for authentication.  
 -p, --cert-password    Certificate password   
 -s, --silent           No console output  
 -t, --token-only       print out token and quit  
 --token-only-outlook   print out token for legacy outlook api and quit  
 --nopii                supress output of email addresses  

 CSV File format is: url,domain,receivedDateTime,mailId,subject,sender
    url: the full url in the body of a message marked as read
    domain: the domain of the url
    receivedDateTime:   received timestamp of message
    mailId:             the outlook id of the message.  Can be used for followup investigation.
    subject:            subject line of message.
    sender:             sender of message.
    
 Requirements:
  * Python packages in requirements.txt must be installed
  * An ApplicationId must be registered with Azure
  * A certificate must be associated with this Application -- note thumbprint.
  * The applicationId will need "Read mail in all mailboxes" application permission which requires an 
    azure administrator to grant.
  * Fill out config.template with details for your tenancy and save as config.ini  
  * The parsefiles script does not require a certificate nor an Azure Application/permissions.
 
 This script is setup to use certificate based authentication.  It is possible to use a self signed cert.
 Create an application registration in Azure -> App Registrations -> New application registration.
 The Endpoints button next to new is helpful if you need to verify your tenant guid, graph url, or authority urls.

 You'll also need to fill out config.template and save as config.ini	

 Once these application permissions have ben granted by an admin in azure, you should be able to run this against any
 user mailbox.

 Tested on python 3 running on windows 10.

References:
* https://docs.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis
    
    Walk through registering an Azure Application with certificate authentication


* https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki/Register-your-application-with-Azure-Active-Directory
    
    Info on Azure Authentication library
    

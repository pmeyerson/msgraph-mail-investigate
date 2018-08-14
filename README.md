 This script has a few functions:
  * return a token to microsoft graph for manual investigation in Postman or other API tool
  * Export a CSV with all url links in the specified user's office 365 mailbox.  Caveat:  Messages permanently deleted
    by the user will not have data available to us.
  
 
 This script is setup to use certificate based authentication.  It is possible to use a self signed cert.
 Create an application registration in Azure -> App Registrations -> New application registration.
 The Endpoints button next to new is helpful if you need to verify your tenant guid, graph url, or authority urls.

 The application will also require an azure admin to assign the following required application permissions:
    * Read mail in all mailboxes

 You'll also need to fill out config.template and save as config.ini	

 Once these application permissions have ben granted by an admin in azure, you should be able to run this against any
 user mailbox.

 You'll also need to install the python packages listed in the requirements.txt file with pip or python package
 manager of your choice.

Tested on python 3 running on windows 10.

References:
* https://docs.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis
    
    Walk through registering an Azure Application with certificate authentication


* https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki/Register-your-application-with-Azure-Active-Directory
    
    Info on Azure Authentication library
  
 
 Other useful permissions might be:
 
    * read and write all user mailbox settings (inbox rules)
    * read all usage reports
    * read all identity risk information
    * read your organizations security events

# VirusTotal Helper
VirusTotal Helper is a website that allows users to upload a text file as a list of hashes (MD5 or Sha256) and generates a simple report using information provided by querying VirusTotal's public API for the hashes.

# Run the Program
In the top-level folder of the application

```shell
    cd virustotal-web
```

run command

```shell
	python run.py
```

Open the browser and the service is running at http://locallhost:5000

![Login](wiki/login_page.png)

# Key Python Modules Used (Dependencies)
- Flask(0.12) web framework
- flask-sqlalchemy(2.1) database ORM
- flask-login(0.4.0) user management
- flask-bcrypt(0.7.1) password hashing
- flask-wtf(0.14.2) simplifies forms

The application is written using python 2.7.12

# Services 
Service                                   | Description
--------------------------------------------- | ------------------------------------------------------
[User service](wiki/Users.md)               |      User registration/login/logout       |
[Report service](wiki/Reports.md)             |        File upload/report generation         |

# Data Model
Data Model                                   | Description
--------------------------------------------- | ------------------------------------------------------
[User Data Model](wiki/user_model.md)               |     Data model for the users      |
[Report Data Model](wiki/report_model.md)             |        Data model for the reports         |




# Technology stack
- Front-end: html, js, css (bootstrap)
- Back-end server: flask framework (python)
- Database: sqlite
- Platform: Linux/OSX/Windows

# Issues Encountered

Since I am using the free basic API key, which only allows for 4 requests/minute maximum, the program will sleep for 16s each time making a VirusTotal's public API call. This however will result in slow processing speed especially when we have large amount of hashes. 

### Reference  ###
* [VirusTotal's public API](https://www.virustotal.com/en/documentation/public-api/)
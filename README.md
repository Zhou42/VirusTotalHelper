# VirusTotal Helper
VirusTotal Helper is a website that allows users to upload a text file as a list of hashes (MD5 or Sha256) and generates a simple report using information provided by querying VirusTotal's public API for the hashes.

# Steps to run the program
In the top-level folder, run command

'''shell
	python run.py
'''

Open the browser and the service is running at http://locallhost:5000

# Key Python Modules Used
- Flask==0.12
- flask-sqlalchemy==2.1
- flask-login==0.4.0
- flask-bcrypt==0.7.1
- flask-wtf==0.14.2 
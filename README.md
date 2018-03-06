# getsploit

[![Current Release](https://img.shields.io/github/release/vulnersCom/getsploit.svg "Current Release")](https://github.com/vulnersCom/getsploit/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/vulnersCom/getsploit/total.svg "Downloads")](https://github.com/vulnersCom/getsploit/releases) [![PayPal](https://img.shields.io/badge/donate-PayPal-green.svg)](https://paypal.me/videns)

# Description
Command line search and download tool for [Vulners Database](https://vulners.com) inspired by [searchsploit](https://github.com/offensive-security/exploit-database/blob/master/searchsploit).
It allows you to search online for the exploits across all the most popular collections: *Exploit-DB*, *Metasploit*, *Packetstorm* and others.
The most powerful feature is immediate *exploit source download* right in your working path.

# Python version
Utility was tested on a *python2.6*, *python2.7*, *python3.6* with SQLite FTS4 support. If you have found any bugs, don't hesitate to open issue

# How to use

Install: `pip install getsploit`

[![asciicast](https://asciinema.org/a/ObuaXdpxNO0nAo6o821fLCLxZ.png)](https://asciinema.org/a/ObuaXdpxNO0nAo6o821fLCLxZ?autoplay=1)

# Search
```
# git clone https://github.com/vulnersCom/getsploit
# cd getsploit
# ./getsploit.py wordpress 4.7.0
Total found exploits: 8
Web-search URL: https://vulners.com/search?query=bulletinFamily%3Aexploit%20AND%20wordpress%204.7.0
+----------------------+--------------------------------+----------------------------------------------------+
|          ID          |         Exploit Title          |                        URL                         |
+======================+================================+====================================================+
|  PACKETSTORM:141039  | WordPress 4.7.0 / 4.7.1 Insert | https://vulners.com/packetstorm/PACKETSTORM:141039 |
|                      | PHP Code Injection             |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|     EDB-ID:41308     | WordPress 4.7.0/4.7.1 Plugin   |     https://vulners.com/exploitdb/EDB-ID:41308     |
|                      | Insert PHP - PHP Code          |                                                    |
|                      | Injection                      |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|     EDB-ID:41223     | WordPress 4.7.0/4.7.1 -        |     https://vulners.com/exploitdb/EDB-ID:41223     |
|                      | Unauthenticated Content        |                                                    |
|                      | Injection (PoC)                |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|  PACKETSTORM:140893  | WordPress 4.7.0 / 4.7.1 REST   | https://vulners.com/packetstorm/PACKETSTORM:140893 |
|                      | API Privilege Escalation       |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|  PACKETSTORM:140902  | WordPress 4.7.0 / 4.7.1        | https://vulners.com/packetstorm/PACKETSTORM:140902 |
|                      | Content Injection / Code       |                                                    |
|                      | Execution                      |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|  PACKETSTORM:140901  | WordPress 4.7.0 / 4.7.1        | https://vulners.com/packetstorm/PACKETSTORM:140901 |
|                      | Content Injection Proof Of     |                                                    |
|                      | Concept                        |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|     EDB-ID:41224     | WordPress 4.7.0/4.7.1 -        |     https://vulners.com/exploitdb/EDB-ID:41224     |
|                      | Unauthenticated Content        |                                                    |
|                      | Injection Arbitrary Code       |                                                    |
|                      | Execution                      |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|      SSV-92637       | WordPress REST API content     |        https://vulners.com/seebug/SSV-92637        |
|                      | injection                      |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
```

# Save exploit files
```
# ./getsploit.py -m wordpress 4.7.0
Total found exploits: 8
Web-search URL: https://vulners.com/search?query=bulletinFamily%3Aexploit%20AND%20wordpress%204.7.0
+----------------------+--------------------------------+----------------------------------------------------+
|          ID          |         Exploit Title          |                        URL                         |
+======================+================================+====================================================+
|  PACKETSTORM:141039  | WordPress 4.7.0 / 4.7.1 Insert | https://vulners.com/packetstorm/PACKETSTORM:141039 |
|                      | PHP Code Injection             |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|     EDB-ID:41308     | WordPress 4.7.0/4.7.1 Plugin   |     https://vulners.com/exploitdb/EDB-ID:41308     |
|                      | Insert PHP - PHP Code          |                                                    |
|                      | Injection                      |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|     EDB-ID:41223     | WordPress 4.7.0/4.7.1 -        |     https://vulners.com/exploitdb/EDB-ID:41223     |
|                      | Unauthenticated Content        |                                                    |
|                      | Injection (PoC)                |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|  PACKETSTORM:140893  | WordPress 4.7.0 / 4.7.1 REST   | https://vulners.com/packetstorm/PACKETSTORM:140893 |
|                      | API Privilege Escalation       |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|  PACKETSTORM:140902  | WordPress 4.7.0 / 4.7.1        | https://vulners.com/packetstorm/PACKETSTORM:140902 |
|                      | Content Injection / Code       |                                                    |
|                      | Execution                      |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|  PACKETSTORM:140901  | WordPress 4.7.0 / 4.7.1        | https://vulners.com/packetstorm/PACKETSTORM:140901 |
|                      | Content Injection Proof Of     |                                                    |
|                      | Concept                        |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|     EDB-ID:41224     | WordPress 4.7.0/4.7.1 -        |     https://vulners.com/exploitdb/EDB-ID:41224     |
|                      | Unauthenticated Content        |                                                    |
|                      | Injection Arbitrary Code       |                                                    |
|                      | Execution                      |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+
|      SSV-92637       | WordPress REST API content     |        https://vulners.com/seebug/SSV-92637        |
|                      | injection                      |                                                    |
+----------------------+--------------------------------+----------------------------------------------------+

# ls
LICENSE         README.md       getsploit.py    wordpress-470
# cd wordpress-470
# ls
edb-id41223.txt         edb-id41224.txt         edb-id41308.txt         packetstorm140893.txt   packetstorm140901.txt   packetstorm140902.txt   packetstorm141039.txt   ssv-92637.txt
```

# Local database
If your Python supports sqlite3 lib(builtin) you can use *--update* and *--local* commands to download whole exploit database to your PC.
After update you can perform local offline searches.

```
# ./getsploit.py --update
Downloading getsploit database archive. Please wait, it may take time. Usually around 5-10 minutes.
219642496/219642496 [100.00%]
Unpacking database.
Database download complete. Now you may search exploits using --local key './getsploit.py -l wordpress 4.7'
```

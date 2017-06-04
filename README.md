# getsploit
# Description
Command line search and download tool for Vulners Database.
It that also you to search online for the exploits across all the most popular collections: Exploit-DB, Metasploit, Packetstorm and others.
The most powerful feature is immediate exploit download right in your working path.


# Python version
Utility was tested on a python2.6, python2.7, python3.5. If you found any bugs, don't hesitate to open issue

# How to use

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
Ubuntu, Postfix, Dovecot IMAP, MySQL virtual mail server setup
==============================================================

Prerequisites
-------------

This article assumes that you are familiar with network terminology and the Linux system. You need to be able to use the terminal and most tasks require root access. You should also have a basic understanding about mail delivery systems, protocols used and TLS/SSL.

Introduction
------------

This article describes the procedures for configuring Postfix and Dovecot to handle mail delivery and IMAP access for virtual users on virtual domains, as well as working as a backup relay for third party domains. Virtual users means that the users don't require Unix user accounts on the system, but are managed separately, here as a list in a MySQL database. Virtual domains mean that the system can handle mail for other domain names than its own domain. Backup relaying is useful for taking care of mail to other systems when they are temporarily down. This guide is based on Ubuntu 10.04 LTS but it has also been tested on
10.10.

Postfix is used as the core mail server for sending and receiving mail. Virtual mailbox accounts and virtual aliases are listed in a MySQL database. Passwords for mail users will be stored as SHA-1 hash values for extra protection. Dovecot is used for IMAP server and authentication for both IMAP and SMTP using TLS/SSL.

The system will handle all mail for the domain **mail.com**, including mailboxes, aliases and lists. The server itself is located behind a NAT/router/firewall and has a local IP address (typical home server setup). The NAT has a public IP address which is associated with the domain name **mail.server.com** and forwards ports **25** (SMTP) and **143** (IMAP) to the server. The DNS record for **mail.com** must have its primary MX record pointing at **mail.server.com**.

Spam is a big concern when setting up a mail server. We want anyone to be able to connect to the server and deliver mail to the domains we are managing, but to send mail to any address using our server, the user must authenticate itself. If spammers can use the system as a relay to any host, it will not only cost you a lot of traffic, but there is also a risk of your server being blacklisted. There are many spam filters, virus scanners and blacklists that can be used to filter out unwanted mail. Here we will make sure that relaying is limited to the locally handled domains and backup relaying to some third party domains. There is also a section describing how to set up Postgrey to eliminate some of the spam.

MySQL Setup
-----------

First install **mysql-server**. This will install the command line client as well.

apt-get install mysql-server

You will be prompted to enter a password for the MySQL **root** user. Choose it wisely. If you are not prompted for a password, set one using:

mysqladmin -u root password secretpassword

Then we will create a database called **maildb** and a user called **mailuser** with password **mailpasswd**. Log in to MySQL as **root**.

mysql –u root –p

Enter password and then go on to create the database.

CREATE DATABASE maildb;

Then create a user with access to the database

CREATE USER 'mailuser'@'localhost' IDENTIFIED BY 'mailpasswd';\
GRANT SELECT,INSERT,UPDATE,DELETE ON maildb.\* TO
'mailuser'@'localhost';

Next we need to create tables for use with the mail server.

CREATE TABLE maildb.relay\_domains (\
'ID' int NOT NULL AUTO\_INCREMENT,\
'domain' varchar(255) NOT NULL,\
'enabled' tinyint(1) NOT NULL DEFAULT '1',\
PRIMARY KEY ('ID'),\
UNIQUE KEY 'domain' ('domain')\
);\
CREATE TABLE maildb.virtual\_aliases (\
'ID' int NOT NULL AUTO\_INCREMENT,\
'address' varchar(255) NOT NULL,\
'destination' varchar(255) NOT NULL,\
'enabled' tinyint(1) NOT NULL DEFAULT '1',\
PRIMARY KEY ('ID'),\
UNIQUE KEY 'address' ('address')\
);\
CREATE TABLE maildb.vmailbox\_domains (\
'ID' int NOT NULL AUTO\_INCREMENT,\
'domain' varchar(255) NOT NULL,\
'enabled' tinyint(1) NOT NULL DEFAULT '1',\
PRIMARY KEY ('ID'),\
UNIQUE KEY 'domain' ('domain')\
);\
CREATE TABLE maildb.vmailbox\_users (\
'ID' int NOT NULL AUTO\_INCREMENT,\
'username' varchar(64) NOT NULL,\
'domain' varchar(255) NOT NULL,\
'password' varchar(64) NOT NULL,\
'enabled' tinyint(1) NOT NULL DEFAULT '1',\
PRIMARY KEY ('ID'),\
UNIQUE KEY 'username' ('username')\
);

The table **relay\_domains** lists all domains that our server will serve as a backup MX for. The second table **virtual\_aliases** lists all virtual mail addresses that forward to other addresses. The third table **vmailbox\_domains** lists all domains that our server will provide mailboxes for and the last table **vmailbox\_users** lists all users with mailboxes on the server.

Basic Postfix configuration
---------------------------

First install the Postfix mail server and the MySQL connector plugin.

apt-get install postfix postfix-mysql

You will be asked to choose an initial configuration template. Choose **Internet site**. Then it will ask you for the **mail name**, enter **mail.server.com**.

First we need to specify identity and network settings in the **/etc/postfix/main.cf** configuration file. After changes has been made to the configuration files, run **/etc/init.d/postfix restart** to read the new settings. Some settings are already set to default values. Just change them or add them if they don't already exist. The order of the lines in the configuration files doesn't matter. For more information about individual settings, see **http://www.postfix.org/postconf.5.html**.

myhostname = mail

This specifies the server's local hostname. It should be set to the name in **/etc/hostname** and this would preferably be the first part of **mail.server.com**, but since the server itself is on a local network, it doesn’t really matter.

alias\_maps = hash:/etc/aliases\
alias\_database = hash:/etc/aliases

These specify aliases for mail to the local domain (local Unix users). We won't be using this but keep them as is to enable **postmaster@localhost**.

myorigin = /etc/mailname

This should be the fully qualified domain name of the mail server itself. Change the first line of **/etc/mailname** to **mail.server.com** or specify the name directly here.

mydestination = localhost.localdomain, localhost

These are the domains that the server will use for mail to the local Unix users. We are not using this so make sure that only the local hostnames are listed here.

relayhost = smtp.isp.com

If we want all outgoing mail to be relayed through a single server, for example if the ISP blocks SMTP access to other servers than its own or if you have a centralized virus scanner. Otherwise, leave it blank.

mynetworks = 127.0.0.0/8 \[::1\]/128 192.168.1.0/24

This lists the trusted networks for the server. Here we have set **localhost** (IPv4 & IPv6) and the local network behind the NAT.

inet\_interfaces = all

Listen to all network interfaces.

proxy\_interfaces = mail.server.com

List the external IP adresses/domain names of all NAT/firewalls to prevent the server from forwarding to itself.

smtpd\_recipient\_restrictions = reject\_unauth\_pipelining,
permit\_mynetworks, permit\_sasl\_authenticated,
reject\_non\_fqdn\_recipient, reject\_unknown\_recipient\_domain,
reject\_unauth\_destination, permit

This is a list of restrictions that controls which messages are allowed to pass through the server. These restrictions are enforced directly after the client has sent the **RCPT TO** command. Unauthorized pipelining is when the client sends commands ahead of time. Some spammers do this to save time and we do not want their mail. Clients connecting from **mynetworks** are always allowed and so are authenticated users. If the recipient address does not have a fully qualified domain name or if the domain doesn’t have a valid MX or A record, then the mail is rejected. Mail to domains that are not handled by our server are rejected. The mail is allowed if no of the above restrictions apply.

Some other settings regarding the basic functionality of Postfix that you might want to set:

smtpd\_banner = \$myhostname ESMTP \$mail\_name (Ubuntu)

The message sent to clients when connecting to the server.

biff = no

This turns off local user mail notification, which we are not using anyway.

append\_dot\_mydomain = no

The server will not append a domain (.server.com) to sender addresses. That is up to the client program to do.

delay\_warning\_time = 24h

Send a mail to the sender, notifying that the mail has been delayed for various reasons, if not delivered within 24 hours.

maximal\_queue\_lifetime = 7d

This sets how long Postfix should try before bouncing a mail if the remote server is unavailable.

minimal\_backoff\_time = 300s\
maximal\_backoff\_time = 7200s

Set the minimal and maximal time between attempts to deliver a queued mail.

smtpd\_require\_helo = yes

Require the client to introduce itself before sending mail through the server. May annoy spammers and allows us to reject funny servers trying to use false identities.

smtpd\_delay\_reject = yes

Don't reject messages before the **RCPT TO** command. This will ensure that Postfix knows whose mail has been rejected and prevents unexpected behavior in some buggy clients.

disable\_vrfy\_command = yes

Disable the **VRFY** command that can be used to harvest email addresses or usernames.

smtpd\_recipient\_limit = 50

Limit the number of recipients of a single mail. This can be used to prevent mass mailings, but may also prevent intentional mass announces.

All lines not discussed here can be commented out using **\#**. Read the documentation and find out for yourself if you want to keep them.

Configuring alias maps
----------------------

Maps are used to map aliases to addresses and virtual users to their mailboxes. Postfix is configured to use MySQL to make lookups since this is the easiest way to handle users and it can easily scale up to thousands of users and a simple web interface can be used to manage users.

Postfix mappings work by querying a domain, user or complete address and receiving a list of destination addresses or a mailbox directory for local delivery. The alias map is a table called **virtual\_aliases** with columns

ID (int), address (text), destination (text), enabled (bool)

In **main.cf** we specify that we are using MySQL for this mapping and refer to a file containing the database connection:

virtual\_alias\_maps = mysql:/etc/postfix/mysql\_valias\_maps.cf

The file **mysql\_valias\_maps.cf** contains:

user = mailuser\
password = mailpasswd\
dbname = maildb\
hosts = 127.0.0.1\
query = SELECT destination FROM virtual\_aliases WHERE address = '%s'
AND enabled = 1;

This will return the field **destination** from the row where **address** is the requested alias address. Here **‘%s’** is the full address (name@mail.com). We can also use the username and domain separately in the query,**’** **%u’** (name) or **‘%d’** (mail.com). If we want more ways to specify aliases, for example if we want to set up mailing lists, we can add additional mappings to Postfix.

virtual\_alias\_maps = mysql:/etc/postfix/mysql\_valias\_maps.cf,
mysql:/etc/postfix/mysql\_list\_maps.cf

You would then have to create the necessary tables and queries to enable lists. The return value Postfix expects from MySQL is a one-column table with a list of all recipient addresses.

You can add an alias with whatever address you like, as long as the domain of the address is handled by your server. Don’t add aliases to **relay domains** or **default domains** (see section Domains below) as it will lead to unexpected results. There is no restriction to the destination address, it can be a local address, external address or another alias.

Now restart Postfix using **/etc/init.d/postfix restart**.

Testing the mail server
-----------------------

Add an alias to the alias table.

INSERT INTO maildb.virtual\_aliases VALUES
(NULL,'test@mail.com','your.other@address.com',1);

Use **telnet localhost 25** to connect to the SMTP server and give these commands to send a test message:

EHLO localhost\
MAIL FROM:root@mail.server.com\
RCPT TO:test@mail.com\
DATA\
Subject: Test\
\
Just testing.\
How are you?\
.\
QUIT

Then check the log file using **tail /var/log/mail.log** to see if the message has been sent. Postfix will allow any recipient address since you are connecting from **localhost**, which is on a trusted network.

Domains
-------

When Postfix receives a message, it decides what to do with it depending on the address domain. Postfix distinguishes between five classes of domains. The first three are managed by our server and the last two are for messages that will be forwarded to its destination somewhere on the internet. A domain should not be added to more than one of these classes. Doing so may cause unexpected behavior.

-   **Local domains** are domains for which Postfix should forward the message to the local Unix user. We will not be using this since it requires each user to have an account with access to the file system, shell, etc. if not necessary precautions are taken.

-   **Virtual alias domains** are domains for which there exist no mailboxes, but messages are forwarded to other addresses using an alias table.

-   **Virtual mailbox domains** are domains for which Postfix handles all mailboxes, but they are not tied to a Unix user. This class is more flexible than **virtual alias domains** since it can handle both aliases and mailboxes. We will define all our domains as **virtual mailbox domains** even if there are no mailboxes for them.

-   **Relay domains** are domains that Postfix are acting as a backup for. Messages to these domains are queued until the primary mail server for the domain (the MX pointer with highest priority) is available.

-   **Default domains** are all other domains on the internet. Postfix will forward messages to these domains only if the sender is authorized to do so. Either if the user authenticates itself or if the connection is made from a trusted computer (**localhost** and the local network listed in **mynetworks**).

Relay domains
-------------

If you have your mail server at home, it may not be as reliable as a server in a data center with redundant power supply and internet connections. Thus it is a good idea to have a backup relay that takes care of the mail and queues them when your server is not available. If your friend also has a mail server at home, you can set up your servers to be backup relays for each other's domains. First you need to add a MX pointer to your friend's server for **mail.com**. The backup MX should have a lower priority (higher number) than the primary **mail.server.com**. Then you need to tell Postfix to forward mail to the other domain. We do this with a MySQL table containing a list of domains that the server should serve as a backup for. This table is called **relay\_domains** and contains three columns:

ID (int), domain (text), enabled (bool)

Add this line to **main.cf**:

relay\_domains = mysql:/etc/postfix/mysql\_relay\_domains.cf

And **mysql\_relay\_domains.cf** contains the same database connection
settings as previously but with another query.

user = mailuser\
password = mailpasswd\
dbname = maildb\
hosts = 127.0.0.1\
query = SELECT domain FROM relay\_domains WHERE domain = '%s' AND
enabled = 1;

Virtual mailboxes
-----------------

Virtual mailboxes are not associated with a local Unix user. Instead, they are associated with a list of users in our database. We do however need a local Unix user that will be the owner of the mailbox files. For this we create a user named **vmail**, belonging to group **vmail** with **uid** and **gid** **5000** and home directory **/var/vmail** (this could also be **/home/vmail** if you want to have the mailboxes under **/home**).

groupadd -g 5000 vmail\
useradd -m -d /var/vmail -u 5000 -g 5000 -s /bin/false vmail

Then we configure postfix to use MySQL to lookup users, domains and mailbox directories. This is done using two tables, **vmailbox\_domains** and **vmailbox\_users**. The first table tells which domains the server should provide mailboxes for and has a simple layout with three columns:

ID (int), domain (text), enabled (bool)

We configure Postfix to use this table by adding this line in **main.cf**:

virtual\_mailbox\_domains =
mysql:/etc/postfix/mysql\_vmailbox\_domains.cf

And in **mysql\_vmailbox\_domains.cf** we provide the usual database connection and the query:

user = mailuser\
password = mailpasswd\
dbname = maildb\
hosts = 127.0.0.1\
query = SELECT domain FROM vmailbox\_domains WHERE domain = '%s' AND
enabled = 1;

The second table contains a list of users and their domains and passwords:

ID (int), username (text), domain (text), password (text), enabled (bool)

A user's mail address is then composed as **username@domain** and we will store the mailbox in **/var/vmail/domain/username/mail**. Only one address and one domain are associated with each user but several aliases can be created to forward mail to a single mailbox. We add the following lines to **main.cf**:

virtual\_mailbox\_base = /var/vmail\
virtual\_uid\_maps = static:5000\
virtual\_gid\_maps = static:5000

This tells Postfix to add all mailboxes as sub-directories to **/var/vmail** and that all mailbox files are owned by **uid** and **gid** **5000** (the **vmail** user). Next we specify the mailbox mappings:

virtual\_mailbox\_maps = mysql:/etc/postfix/mysql\_vmailbox\_maps.cf

And the content of **mysql\_vmailbox\_maps.cf** is:

user = mailuser\
password = mailpasswd\
dbname = maildb\
hosts = 127.0.0.1\
query = SELECT concat(domain, '/', username, '/mail/') FROM
vmailbox\_users WHERE username = '%u' AND domain = '%d' AND enabled = 1;

If the user **username@domain** exists, this will return **'domain/username/mail/'**, which is the subdirectory in which to put that user's mailbox. The last **'/'** after mail is important since it tells Postfix to use the **Maildir** mailbox format, which stores each message in a separate file. If the **'/'** is omitted, Postfix will use the **mbox** format, which stores all messages in a single file.

Now test the server by adding a virtual domain:

INSERT INTO maildb.vmailbox\_domains VALUES (NULL, 'mail.com', 1);

And add a virtual user:

INTO maildb.vmailbox\_users VALUES (NULL, 'someone', 'mail.com', SHA('secret'), 1);

Then send a message to **someone@mail.com**. The directory **/var/vmail/mail.com/someone/mail** should be created and in the folder **new** you should find a file containing the message.

Authentication and TLS/SSL
--------------------------

Commonly, SSL has been used to provide an encrypted channel when authentication using passwords. SSL encrypts the whole connection before any data has been sent, which means that the option of using encryption lies on the client to choose a port on the server where encryption is used. Using SSL it is required to use two separate ports for encrypted (authenticated) connections and unencrypted (incoming mail from other mail servers). However, using TLS (basically the same encryption technique as SSL) one can have a single unencrypted port that everyone connects to. Those clients requiring encryption for authentication can send the **STARTTLS** command to initiate an encrypted channel before sending the password. This is supported by most modern mail clients and is the preferred option since there is only one port to remember and manage.

First you need a certificate for the server so that users can identify and trust the server. The certificate should be signed by a trusted third party, such as VeriSign or StartSSL, but for now we will generate a self-signed certificate to get started. First we need to create our own CA certificate.

/usr/lib/ssl/misc/CA.pl -newca

This will ask for some information and create a folder named **demoCA** where the necessary files are located. Then we create a certificate for use with the mail server.

openssl req -new -nodes -keyout mail-key.pem -out mail-req.pem -days 365

Finally we need to sign the server certificate with the CA certificate.

openssl ca -out mail-cert.pem -infiles mail-req.pem

We now have a CA certificate, a signed server certificate and a private server key. We also need to create a combined certificate for Dovecot, containing both the CA certificate and the server certificate.

cat mail-cert.pem demoCA/cacert.pem &gt; combined-cert.pem

Put all these files in **/etc/postfix/ssl** and make sure that **mail-key.pem** is only readable by root.

cp demoCA/cacert.pem mail-cert.pem mail-key.pem combined-cert.pem /etc/postfix/ssl/

To enable TLS in Postfix we add these lines to **main.cf**:

smtpd\_tls\_cert\_file = /etc/postfix/ssl/mail-cert.pem\
smtpd\_tls\_key\_file = /etc/postfix/ssl/mail-key.pem\
smtpd\_tls\_CAfile = /etc/postfix/ssl/cacert.pem\
smtpd\_tls\_session\_cache\_database =
btree:\${data\_directory}/smtpd\_scache\
smtpd\_tls\_session\_cache\_timeout = 600s\
smtpd\_tls\_security\_level = may\
smtpd\_tls\_auth\_only = yes

The first three lines specify the paths to the certificate, the private key and the CA certificate. The next three lines specify where the session cache is located and how long each session should be open before timing out. The last two lines specify that TLS is optional, but the client is not allowed to authenticate without first enabling TLS.

Then we specify how Postfix will connect to Dovecot for user authentication.

smtpd\_sasl\_type = dovecot\
smtpd\_sasl\_path = private/auth-client\
smtpd\_sasl\_auth\_enable = yes

First we specify that we are using the Dovecot SASL plugin for authentication. Then we specify the path to a socket connecting to Dovecot, the full path will be **/var/spool/postfix/private/auth-client**. Finally we enable the SASL authentication.

Setting up Dovecot
------------------

We will set up Dovecot to provide IMAP service as well as authentication for both SMTP and IMAP. For this we need dovecot-common and dovecot-imapd.

apt-get install dovecot-common dovecot-imapd

The main configuration file is **/etc/dovecot/dovecot.conf**. The default configuration file lists hundreds of settings with comments about what they do. Look through the file and then make a copy of it for reference. We will start with an empty file so that we don’t have to comment out every line we are not using.

protocols = imap

This specifies that we will use Dovecot for IMAP on the standard port, 143. There is no need to use the encrypted **imaps** protocol as **STARTTLS** takes care of security just as for the SMTP server.

disable\_plaintext\_auth = yes\
ssl = required\
ssl\_cert\_file = /etc/postfix/ssl/combined-cert.pem\
ssl\_key\_file = /etc/postfix/ssl/mail-key.pem

This enables TLS for the IMAP protocol and requires the client to initiate a secure connection before authenticating. All connections from **localhost** are considered secure so a local webmail system does not require TLS. The two last lines specify the path to the certificates and the private key. Here the CA certificate and the server's certificate are combined into one file.

Next we specify where the mailboxes are stored:

mail\_location = maildir:%h/mail

The **'maildir:'** part specifies that messages are stored in the **Maildir** format, and **'%h/mail'** specifies that they are found in the **mail** sub folder in the home directory. Every user has a home directory at **/var/vmail/domain/username** where Dovecot might want to save some special files. To avoid naming conflicts with sub folders in the user's inbox, we save all messages in a sub folder to the home directory.

mail\_privileged\_group = vmail

This specifies which group to use for temporary privileged operations.

By default Dovecot logs everything to the mail.log file. We want to separate the authentication and IMAP logs from the mail delivery logs so we let Dovecot use another log file. The syslog daemon handles rotation of log files quite neatly so we can use the **local0** syslog facility for Dovecot logging.

syslog\_facility = local0

We must then tell rsyslog where to output the **local0** logs by creating the configuration file **/etc/rsyslog.d/dovecot.conf** with the contents:

local0.\* -/var/log/dovecot.log

This file will be automatically added to the rsyslog configuration once it has been restarted.

/etc/init.d/rsyslog restart

Then we specify some settings in **dovecot.conf** for the IMAP server.

protocol imap {\
imap\_client\_workarounds = tb-extra-mailbox-sep delay-newmail\
}

These settings will help to improve functionality with Thunderbird and Outlook Express in some situations.

Now we have come to the authentication mechanism.

auth default {\
mechanisms = plain login\
user = postfix\
passdb sql {\
args = /etc/dovecot/dovecot-sql.conf\
}\
userdb sql {\
args = /etc/dovecot/dovecot-sql.conf\
}\
socket listen {\
client {\
user = postfix\
group = postfix\
path = /var/spool/postfix/private/auth-client\
mode = 0660\
}\
}\
}

This might need some explanation. First we enable plain text password login. Since we are only using secure connections this is not a problem and in simplifies authentication in the database. The **plain** mechanism is the default, but **login** is used by Outlook and we want those people to be able to connect as well. Both methods use plain text passwords. Then we specify the user that will run the authentication process, this can be any user allowed to connect to MySQL. The default is **root** but that is only necessary when using system user passwords so a non-privileged user is preferred. We can’t use the **dovecot** user since that is used for other purposes and the **vmail** user could read users’ mail if there is an intrusion. The **postfix** user should pose no threat to the system and we are too lazy to create a new user just for this. Next we say that both passwords and users can be found using an SQL query specified in **/etc/dovecot/dovecot-sql.conf**. Finally we create a socket with the right permissions that Postfix can connect to.

The default **dovecot-sql.conf** also contains a lot of commented settings. It is not as big as the main configuration file so comment out everything or start from scratch. The file **dovecot-sql.conf** contains the database connection and queries, and this is where everything happens.

driver = mysql\
connect = host=localhost user=mailuser password=mailpasswd dbname=maildb

This provides the connection to the database.

default\_pass\_scheme = PLAIN

We want all passwords in plain text so that we can compare them with the database. This password query will authenticate the user **'%n'** with password **'%w'**:

password\_query = SELECT NULL AS password, 'Y' AS nopassword, username AS user, domain AS domain FROM vmailbox\_users WHERE username = '%n' AND password = SHA('%w') AND enabled = 1

By default, Dovecot wants the query to return the password in plain text so that it can do the authentication. However, we don't want the passwords to be saved in plain text anywhere, to protect the users in the case of a hacked server. Instead, one can return **password** with value **NULL** and **nopasswd** with value **'Y'** if the match was successful. We let MySQL do the authentication by searching for a line where username is **'%n'** and password is the **SHA** hash value of **'%w'**.

user\_query = SELECT 5000 AS uid, 5000 AS gid, concat('/var/vmail/', domain, '/', username) AS home FROM vmailbox\_users WHERE username = '%n' AND domain = '%d' AND enabled = 1

The user query returns the location and owner of the user's home directory (where the mailbox is located). Since all mailboxes are owned by **vmail**, we return a static **5000** for **uid** and **gid**. The home field is concatenated to **/var/vmail/domain/username**.

Testing
-------

Now restart Dovecot and Postfix and try your server with a mail client (e.g. Thunderbird) from an untrusted computer (i.e. a computer outside **mynetworks**). IMAP settings should be **mail.server.com** on port **143** with **STARTTLS** and plain-text password. SMTP settings should be **mail.server.com** on port **25** with **STARTTLS** and plain-text password.

If (or when) you encounter problems, have a look at the log files and try to figure out in which component the problem occurs.

tail /var/log/mail.log\
tail /var/log/dovecot.log

Spelling errors in the configuration files is the single most common problem. Also make sure that all daemons are running (Postfix, Dovecot and MySQL). Remember that Postfix handles its own TLS settings but the authentication lies in Dovecot.

Postgrey
--------

A simple to set up but yet effective way of stopping spam is to use greylisting. When a client connects to the server, a triplet is constructed containing the address of the client, the sender of the mail and the receiver of the mail. If it is the first time that triplet is seen, the server will say that the recipient mailbox is temporarily unavailable. If the client tries to send the mail again after a few minutes, it will be allowed to do so. Most spammers don’t have time to try again and will miss out on the fun. Clients that try again will be added to a whitelist and the next message will be allowed to pass immediately.

Postgrey is a simple greylist for use with postfix. First install the Postgrey server.

apt-get install postgrey

This will install and start the Postgrey daemon. The configuration file **/etc/default/postgrey** is very simple. Note the port number in this file (it differs between Ubuntu 10.04 and 10.10) and use the same in the Postfix configuration.

POSTGREY\_OPTS=”--inet=10023 --delay=300 --max-age=365”

Allow if the client reconnects after five minutes and delete whitelisted triplets that have not been used for a year. Restart Postgrey to apply the settings.

/etc/init.d/postgrey restart

Finally configure Postfix to check with Postgrey before allowing mail to pass.

smtpd\_recipient\_restrictions = reject\_unauth\_pipelining,
permit\_mynetworks, permit\_sasl\_authenticated,
reject\_non\_fqdn\_recipient, reject\_unknown\_recipient\_domain,
reject\_unauth\_destination, check\_policy\_service
inet:127.0.0.1:10023, permit

Troubleshooting
---------------

The first place to look for errors is **/var/log/mail.log** and **/var/log/dovecot.log**. Use the **tail** command to look at the last lines of the log file after each action to see what happens.

References
----------

<http://www.postfix.org/documentation.html>

<http://wiki2.dovecot.org/>

<http://flurdy.com/docs/postfix/>

<http://postfix.pentachron.net>

<https://help.ubuntu.com/community/Postfix>

<https://help.ubuntu.com/community/PostfixBasicSetupHowto>

<https://help.ubuntu.com/community/PostfixCompleteVirtualMailSystemHowto>

<https://help.ubuntu.com/community/PostfixVirtualMailBoxClamSmtpHowto>

<https://help.ubuntu.com/community/Dovecot>

<https://help.ubuntu.com/community/PostfixDovecotSASL>

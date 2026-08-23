1. OWASP ModSecurity Core Rule Set (CRS) — Best for HTTP / WAF
The OWASP Core Rule Set is the gold standard used by almost all open-source and commercial Web Application Firewalls (like Cloudflare WAF, Nginx WAF, etc.).

Where to find it: GitHub: coreruleset/coreruleset
The Signature Files: Go to the rules/ folder in the repository. You will see configuration files containing standard regular expressions (regex) for attacks:
SQL Injection: REQUEST-942-APPLICATION-ATTACK-SQLI.conf
XSS: REQUEST-941-APPLICATION-ATTACK-XSS.conf
Remote Code Execution: REQUEST-932-APPLICATION-ATTACK-RCE.conf
2. Emerging Threats (ET) Open Rules — Best for General Network (DNS, ICMP, TCP)
Emerging Threats provides a massive, community-maintained collection of rules for network monitoring systems (like Suricata and Snort).

Where to find it: rules.emergingthreats.net/open
The Signature Files: Look inside the rules/ directory (e.g. emerging-dns.rules or emerging-web_server.rules).
How to read them: The rules look like this:
text
alert dns any any -> any any (msg:"ET EXPLOIT DNS Tunneling Attempt"; content:"|03|foo|03|bar";)
You can extract the hex or text inside the content:"..." tag. That is the exact byte pattern to load into your Aho-Corasick match engine!
3. PayloadsAllTheThings — Best for Raw Lists of Payloads
If you want raw text lists of attacks (without regex or config files) to easily copy/paste into a C-array, this repository is the best resource.

Where to find it: GitHub: swisskyrepo/PayloadsAllTheThings
How to use it: Go to directories like SQL Injection/Intruders or XSS/ to find flat .txt files containing lists of malicious strings like ' OR 1=1 -- or <script>alert(1)</script>. You can feed these text lists directly into your code.

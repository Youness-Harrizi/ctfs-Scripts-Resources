### **1. Service Triage (Analyze Scan Results)**

Don't just look at ports; look at versions.

* **Web (80, 443, 8080, 8443):** Run **Aquatone** or **EyeWitness** to screenshot everything. Look for:
* Administrative panels (Tomcat, Jenkins, ESXi, Printers).
* Directory listing enabled.
* Default installation pages.


* **Management (22, 23, 3389, 5900):** Check for VNC (no auth), Telnet (cleartext), and SSH (outdated versions).
* **Databases (1433, 3306, 5432, 6379):** Check for default accounts (sa/password, root/no-pass) or unauthorized access (Redis often has no auth).

### **2. Automated Vulnerability Scanning**

* **Run Nessus/OpenVAS:** Launch a scan immediately.
* **Manual Validation:** While it scans, grep your Nmap results for "Critical" CVEs (e.g., Log4j, Heartbleed, EternalBlue) using scripts:
* `nmap --script vuln -p <ports> <target>`



### **3. The "Low Hanging Fruit" (Manual Checks)**

* **Default Credentials:** Test generic defaults on *every* login portal found.
* *Examples:* `admin/admin`, `root/root`, `admin/password`, `tomcat/s3cret`.


* **SNMP Enumeration (UDP 161):**
* Run `snmp-check` or `onesixtyone` with public/private strings.
* *Goal:* Extract routing tables, ARP cache, or process lists.


* **NFS/SMB Shares:**
* Check for open NFS mounts: `showmount -e <IP>`
* Check for anonymous SMB access: `smbclient -L //<IP> -N`



### **4. Network Traffic Analysis**

* **MITM (Man-in-the-Middle):** Even without AD, you can capture cleartext credentials (HTTP, FTP, POP3, IMAP).
* **ARP Spoofing:** If allowed by RoE (Rules of Engagement), use `Ettercap` or `Bettercap` to intercept traffic between key servers and gateways.

### **5. Exploitation (RCE)**

* **Metasploit/Searchsploit:** Map specific service versions to public exploits.
* *Priority:* Remote Code Execution (RCE) > Auth Bypass > Denial of Service.


* **Brute Force:** If you find SSH or Web portals with no lockout policy, run `Hydra` with a top-1000 wordlist.

### **Summary Checklist**

1. [ ] **Screenshots:** All web ports captured?
2. [ ] **Defaults:** Tried admin/admin on every portal?
3. [ ] **Open Shares:** Checked NFS/SMB for sensitive files?
4. [ ] **Scanning:** Validated Nessus "High/Critical" findings?
5. [ ] **Traffic:** Sniffed for cleartext passwords?

**Would you like a list of common default credential pairs for infrastructure devices (Cisco, HP, Dell)?**

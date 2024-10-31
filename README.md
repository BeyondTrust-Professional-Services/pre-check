# BeyondTrust Professional Services Pre-Check toolkit

BeyondTrust Professional / Implementation Services (ProServe) may sometimes 
request customers run certain scripts to gather information about the customer 
environment for project scoping, analysis, or product deployment purposes. 
Many customers ask about the required uses of these scripts, so this document 
will attempt to answer those questions.

# Script Overview

There are 2 scripts in scope for this discussion – pbis-pre-check.sh and 
ad-info.vbs.  They are available directly from BeyondTrust in a single zip 
file in the Releases section of this site.

## pbis-pre-check.sh

This script needs to be run on a representative set of UNIX systems.  It will 
provide a series of compatibility checks for the BeyondTrust software and 
better allow our Professional Services team the ability to plan for your 
environment. 

The script should normally be run with no parameters. However, should there be 
any environmental or security concerns, the `--help` switch will display 
options to filter out the various tests and data collection options.  These 
options should be made to match your security/management restrictions on 
data/information sharing with us.  For example, the script can skip running 
processes and skip internet connectivity tests when run with the 
`--no_ps --no_internet` parameters. Professional Services recommends including 
all tests (i.e. no parameters).  We specifically request that whenever possible
you do not choose the `--no_lug` (no local user/group information) as we 
require this information to audit your current accounts and prepare them for 
migration with your other directory services.  

Because account remediation is a major task in the deployment process, it is 
highly recommended that the script is run on all boxes which have local 
user/group accounts.  Since most systems have local accounts that are often in 
conflict with other systems or directory services, the more information we 
have, the better we can help in consolidating and migrating to Active 
Directory.

The script should not need root execution unless file permissions have been 
restricted.

For each system, a `hostname-pbis-health-check.srf` file will be created 
in `/tmp`.  

## ad-info.vbs

This script should be run on a Windows workstation joined to the same forest 
that will authenticate and authorize PBIS clients.  If multiple forests are 
involved, then it should be run on each.  The script needs at least Domain 
User privileges to collect all information.  If possible, the script should be 
run in the Forest Root.

ad-info.vbs is run from a command prompt as follows:

`cscript ad-info.vbs > %userdnsdomain%-ad-info.out`

NOTE: If you have never run VB scripts on the host box, you may need to set up 
console output to be captured using the following: 

`cscript //h:cscript //s`

# Unix Data Captured and purposes

|Section | Product | Purpose | Option  | Risk if Excluded |
|--------|---------|---------|---------|------------------|
|AD Domain|ADB| Firewall tests to AD DCs |True| Customer must certify firewall themselves. |
|AD Domain|ADB| Tells ADB Engineer the expected domain of the endpoint | True |Project Manager must assign domain for each server in the report |
|Date/Script Info |All| Tells engineer the data capture date |   False |  Old data can cause analysis errors if multiple script runs are performed|
|Options| All| Tells engineer and analysis tools what data to expect (to know if a file is complete or not)  |  False |  All hosts will show an error as being incomplete|
Host/Kernel All Tells engineer which platforms to check for supportability  False   Customer must self-certify platform supportability
Uname/OS Version    All Tells engineer which platforms to check for supportability  False   Customer must self-certify platform supportability
Disk Space  All Is there enough disk space for the installer and/or variable files  True    Customer must self-certify disk space for install and logs
Mounted Filesystems All Tells analysis tool which install/variable folders are attached to each disk for the disk space analysis    False   Customer must self-certify disk space for install and logs
Mounted Filesystems ADB Tells analysis tool which hosts share NFS file systems for server grouping (install planning, ID migration planning)    False   Customer must group servers with no ADB team data points (time commitment)
DHCP    PMUL    Tells engineer if hostname validation needs to be disabled  False   Hostname validation provides additional PMUL security against rogue client machines
Network Info    ADB AD Site awareness validation    False   AD Team must manually validate all AD sites that Unix systems are joined to. Unix team must prepare lists of subnets for the AD team to validate.
Route info  ADB AD Site awareness validation (more often used)  False   AD Team must manually validate all AD sites that Unix systems are joined to. Unix team must prepare lists of subnets for the AD team to validate.
Default Router  ADB Validates primary subnet in multi-homed servers False   Analysis tool won’t know which subnet in multi-homed servers will be used for AD site awareness testing, test will fail.
NSSwitch    ADB Validation of which hosts come from which identity providers    False   Cannot perform proper user logon rights analysis without knowing which servers a user can access
Resolv  ADB
PMUL    Validate that DNS resolution is available.
Validation of default DNS domain names  False   Customer must self-certify DNS resolution.
Disjointed DNS joining cannot be tested nor supported. 90% of customers require disjointed DNS support.
AIX Security (security /login /methods /aixpert /etc. files)    ADB Discovery of user logons and user logon rights  False   Cannot migrate local users into AD.

Cannot validate ID conflicts across identity zones for cell merge operations.
FQDN / hosts    ADB Validation of DNS domain names  False   Disjointed DNS joining cannot be tested nor supported. 90% of customers require disjointed DNS support
System Utility Versions ADB
PMUL    Check for installer supportability  False   Older OSes can ship with libraries that do not support PAM. Modern Linux systems installed as “minimal” installs may not have some required libraries installed. Customer must self-certify installation compatibility.
System File Locations   ADB Many customers may have multiple versions of the same software component installed – one via package manager, one via self-compile. We attempt to find them to validate that the appropriate one will be configured by the join operation   False   Customer must self-certify compatibility
OS Patch Information    ADB Validate customer is running a supported sub-version of the requested OS (not checked on Linux) False   Customer must self-certify platform supportability
Sudo information    ADB PAM supportability of sudo  False   Validate that the installed Sudo is compiled with PAM support (the default on non-Linux is not)
Sudoers contents    PMUL    Migration of sudo rules to PMUL policy  True (run as non-root)  Used in scripted migrations to capture sudoers rules for building initial PMUL policy if requested by customer.
Smb.conf info   ADB Pre-validation of settings for samba-interop-install    False   Samba options cannot be validated for integration with ADB
Kerberos Files  ADB
PMUL    Used to determine potential overlap/integration requirements with non-AD Kerberos Realms for ADB.
Used to determine KRB5 configuration settings for PMUL
    

False   ADB domain join may break existing Kerberos enabled applications
Cannot use safely configure krb5 with PMUL if excluded.
PAM config  ADB Determination of non-standard PAM modules that domainjoin-cli may not recognize/support that may require customer PAM delivery  False   Users may not be able to log in post-migration if system is running a non-standard PAM stack AND the migration kit is not prepared for it.
Local Users and Groups  ADB Find any local users who need to be moved into AD.
Find any surprise backdoor admin accounts that should be deleted.
Find any conflicting UID / GID values across identity domains that may cause compliance failures.   True    Compliance failure.
Security failure missing users in the migration or analysis.
Network Users   ADB Find any network users and their logon rights   True    Cannot perform role analysis of users’ current access rights.
Security Configuration  ADB Find any logon rights settings native to Unix   True    Cannot perform role analysis of users’ current access rights.
Previous Versions   ADB Check for upgrade issues from prior versions of Likewise/PBIS/ADB   True    Some versions of Likewise do not seamlessly upgrade to ADB, and must follow “leave/purge/install”. The scripts can do this, but it is not the default. Turning it on adds per-host migration delays.
Previous ADB Config ADB Check for cell/configuration, so that new GPO can be built with already-tested configurations.  True    ADB Engineer will not know of the previous join status or GPO settings that the customer may be expecting, which can cause endpoint service outage if set wrong.
NSCD Cache  ADB Nscd for user/group information is supported, but not suggested enabled for ADB installations: double-caching of information causes negative lookup performance problems    True    May end up in poor-performing configuration on endpoints.
AltFiles    ADB
PMUL
PWS Disabled by Default. Allows gathering of additional data for more manual processing. Often used in PWS migrations for A2A account discovery True    Variable by customer, but disabled by default, so normally no risk to exclude
PBUL    PMUL    Gathers existing PMUL configuration for pre-configuration of new version packages   True    Cannot lift-and-shift from older PMUL
Cron    ADB
PWS Allows identification of accounts which have crontabs configured, for determination of human vs. service vs. application IDs for PWS and ADB migration  True    Automatic identification of service vs. human accounts will be less accurate. More customer time spent reviewing account reports.
PS output   ADB
PWS Allows identification of accounts logged in interactively vs. accounts running background services (started via init or other)  True    Automatic identification of service vs. human accounts will be less accurate. More customer time spent reviewing account reports.
NIS ADB Determination of system NIS domain for identity migration into ADB Cells    True    User / group migration into cells and logon rights analysis will be wrong.
NTP ADB Kerberos is a time-sensitive protocol. Time must be synchronized across the environment. ADB can do this natively, but this can cause service outages with some applications. This information is combined with the Package and PS outputs to determine if a system does NOT have synchronized time *and* runs a time-sensitive application that could fail with ADB time sync enabled (which is the default)   True    Service outage if time synch is left to the defaults.
Installed Software  ADB Used to look for applications which have known incompatibilities with ADB default settings. Allows preparing the ADB environments with the appropriate non-default settings before software is installed, avoiding introducing problems into the customer environment   True    May cause service outage if incompatible settings are applied to endpoints.
Environment Variables   ADB ADB does not support LD_PRELOAD, LD_LIBRARY_PATH and similar environmental variables set globally. These should be configured in the application startup script. The migration script can work around this if the existence is known in advance.    True    Customer has to self-certify supportability
Active Directory    ADB Validate that Unix hosts can do proper DNS lookups and route to AD domain controllers   True    Customer must self-certify DNS and routability and AD site awareness
AD Firewall ADB Validate Unix hosts can talk to AD on all testable TCP ports    True    Disabled by Default due to complexities with site awareness and shell scripting. Customer must self-certify network firewall settings
Internet    ADB
PMUL    Validates that there are default routes and internet accessible DNS.
ADB used for potential installation from public ADB repo    True    Extremely low. It’s used as a sanity check, and an option check, but communication with project and networking teams performs the same value.
Services    ADB Migrate and validate /etc/services into ADB GPO True    Disabled by Default. No risk if /etc/services will remain local post installation
End Time    All Used by analysis tool to know a particular server’s output was fully completed  False   All hosts will fail as incomplete
Zones   All Used to descend into Solaris 10 and 11 Zones to re-run the script and gather 100% output on each child zone False   Customer must manually run the script on each child zone independently
Active Directory Information
Active Directory Map
Multi-tree forests create additional requirements for Single-Sign-On and DNS setup to properly enumerate from UNIX hosts.  Additionally, the Schema Master in a multi-forest setup may not be in the same domain as the Cell will be created.
Forest Info
PBIS Directory Integrated Mode only works on forests at Windows 2003 Forest Level or higher.
RFC2307 Attributes
Determines the work required to move to Directory Integrated Mode, or discover issues before running the DI wizard.
Domain List
List all domains and their NT4 and FQDN names. Used for Disjointed DNS discovery or DNS/NT4 name mismatches.
Trust List
One-way trusts are only supported by PBIS Named Cells. Non-transitive two-way trusts can create troubleshooting difficulties with the PBIS Default Cell.
PBIS Cells
List of existing PBIS Cells, used to identify servers to identity maps.
If no cell is found, but Likewise Open clients exist, care must be taken to not break those clients when creating the cell (Likewise Open can operate in Cell mode, but PBIS Open cannot).
Active Directory Sites and Subnets
Map Unix system IP addresses to the Active Directory Site they will be joined to.
DCs by Site
Helps PBIS team determine if any sites might need more Domain Controller / Global Catalog coverage when UNIX systems are joined to  their default sites.




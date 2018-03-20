#!/bin/sh

# Script to run some basic checks on the health of the system environment
#
# Anthony Ciarochi
# November, 2007
# (c) 2007-2010 Likewise Software
# (c) 2011-2018 BeyondTrust Software
#
# Revisions at bottom

# TODO: Add DNS/tcp check against nameserver(s).  This can detect DDNS
# update issues when UDP is sufficient for DNS lookups (small AD domain).

script_version=1.7.0

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
ECHO=echo
OUTFILE_NAME=`hostname |cut -d. -f1`-pbis-health-check.srf

DEFAULT_DO_DF=1
DEFAULT_DO_LUG=1
DEFAULT_DO_SECURITY=1
DEFAULT_DO_FIND=1
DEFAULT_DO_SUDOERS=1
DEFAULT_DO_PS=1
DEFAULT_DO_NIS=1
DEFAULT_DO_NTP=1
DEFAULT_DO_AD=1
DEFAULT_DO_AD_FIREWALL=
DEFAULT_DO_DNS_ROOT=1
DEFAULT_DO_INTERNET=1
DEFAULT_DO_SOFTWARE=1
DEFAULT_DO_ENV=1
DEFAULT_DO_SERVICES=
DEFAULT_DO_CONFIG=1
DEFAULT_DO_CACHE=1
DEFAULT_DO_ALTFILES=
DEFAULT_DO_PBUL=1
DEFAULT_DO_CRON=1
ALTFILES=""
ALTFILES_PASSFIELD=3
ALTFILES_FIELDSEP=":"

DO_LOG=1
DO_DF=$DEFAULT_DO_DF
DO_LUG=$DEFAULT_DO_LUG
DO_SECURITY=$DEFAULT_DO_SECURITY
DO_FIND=$DEFAULT_DO_FIND
DO_SUDOERS=$DEFAULT_DO_SUDOERS
DO_PS=$DEFAULT_DO_PS
DO_NIS=$DEFAULT_DO_NIS
DO_NTP=$DEFAULT_DO_NTP
DO_AD=$DEFAULT_DO_AD
DO_AD_FIREWALL=$DEFAULT_DO_AD_FIREWALL
DO_DNS_ROOT=$DEFAULT_DO_DNS_ROOT
DO_INTERNET=$DEFAULT_DO_INTERNET
DO_SOFTWARE=$DEFAULT_DO_SOFTWARE
DO_ENV=$DEFAULT_DO_ENV
DO_SERVICES=$DEFAULT_DO_SERVICES
DO_CONFIG=$DEFAULT_DO_CONFIG
DO_CACHE=$DEFAULT_DO_CACHE
DO_ALTFILES=$DEFAULT_DO_ALTFILES
DO_PBUL=$DEFAULT_DO_PBUL
DO_CRON=$DEFAULT_DO_CRON

if [ -d /tmp ] ; then
    OUTFILE_DIR="/tmp"
else
    OUTFILE_DIR="/"
fi
OUTFILE_PATH=$OUTFILE_DIR/$OUTFILE_NAME

OStype=""
kernel=`uname -s`
case "$kernel" in
    Linux)
        test=`which rpm | grep -v "no rpm"`
        if [ $test ]; then
            OStype=linux-rpm
        fi
        test=`which apt-cache | grep -v "no apt-cache"`
        if [ $test ]; then
            OStype=linux-deb
        fi
        ;;
    Darwin)
        OStype=darwin
        ;;
    HP-UX)
        OStype=hpux
        ;;
    SunOS)
        OStype=solaris
        ;;
    AIX)
        OStype=aix
        ;;
    FreeBSD)
        OStype=freebsd
        ;;
    *)
        $ECHO "ERROR: Unknown kernel: $kernel"
        exit 1
        ;;
esac
if [ -z "$OStype" ]; then
    $ECHO "ERROR: Unknown OS type (kernel = $kernel)"
    exit 1
fi	

get_on_off()
{
    if [ -z "$1" ]; then
        echo "off"
    else
        echo "on"
    fi
}

usage()
{
    $ECHO "usage: `basename $0` [options] [activeDirectoryDomainName]"
    $ECHO ""
    $ECHO "  Options to enable/disable checks:"
    $ECHO ""
    $ECHO "    --df          - Do disk space check (default is `get_on_off $DEFAULT_DO_DF`)"
    $ECHO "    --lug         - Do local users and groups check (default is `get_on_off $DEFAULT_DO_LUG`)"
    $ECHO "    --security    - Do file checks for security-managing files (default is `get_on_off $DEFAULT_DO_SECURITY`)"
    $ECHO "    --find        - Do find files check (default is `get_on_off $DEFAULT_DO_FIND`)"
    $ECHO "    --sudoers     - Do 'cat /etc/sudoers' (default is `get_on_off $DEFAULT_DO_SUDOERS`)"
    $ECHO "    --ps          - Do 'ps -elf' output (default is `get_on_off $DEFAULT_DO_PS`)"
    $ECHO "    --nis         - Do nis domain and server lookup (default is `get_on_off $DEFAULT_DO_NIS`)"
    $ECHO "    --ntp         - Do 'ntp -q' (default is `get_on_off $DEFAULT_DO_NTP`)"
    $ECHO "    --ad          - Do AD ping check (default is `get_on_off $DEFAULT_DO_AD`)"
    $ECHO "    --ad_firewall - Do AD firewall check (default is `get_on_off $DEFAULT_DO_AD_FIREWALL`)"
    $ECHO "    --dns_root    - Do DNS root lookup check (default is `get_on_off $DEFAULT_DO_DNS_ROOT`)"
    $ECHO "    --internet    - Do internet ping check (default is `get_on_off $DEFAULT_DO_INTERNET`)"
    $ECHO "    --services    - Do /etc/services output (default is `get_on_off $DEFAULT_DO_SERVICES`)"
    $ECHO "    --config      - Do /opt/{likewise|pbis}/{lw-config|config} --dump (default is `get_on_off $DEFAULT_DO_CONFIG`)"
    $ECHO "    --cache       - Do /etc/nscd.conf (or similar) output  (default is `get_on_off $DEFAULT_DO_CACHE`)"
    $ECHO "    --altfiles    - Gather additional files from pre-defined array (default is `get_on_off $DEFAULT_DO_ALTFILES`)"
    $ECHO "    --pbul        - Gather PBUL files from no-prefix directory /etc/pb* (default is `get_on_off $DEFAULT_DO_PBUL`)"
    $ECHO "    --cron        - Gather crontab owners (accounts with cron jobs) (default is `get_on_off $DEFAULT_DO_CRON`)"
    $ECHO ""
    $ECHO "    To disable a check, prefix option with 'no_' (eg. --no_lug)"
    $ECHO ""
    $ECHO "  Other options:"
    $ECHO ""
    $ECHO "    --no_log   - Do not create a log file (default is to"
    $ECHO "                 log to $OUTFILE_PATH)"
    $ECHO ""
    $ECHO "  Script Version: $script_version"
}

if [ $OStype = "darwin" ]; then
    TRUEPATH=/usr/bin/true
elif [ $OStype = "freebsd" ]; then
    TRUEPATH=/usr/bin/true
else
    TRUEPATH=/bin/true
fi

PASS_OPTIONS=
while $TRUEPATH; do
    case "$1" in
        --help|-h)
            usage
            exit 1
            ;;
        --no_log)
            DO_LOG=
            # Do not pass through
            ;;
        --df)
            DO_DF=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_df)
            DO_DF=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --lug)
            DO_LUG=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_lug)
            DO_LUG=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --security)
            DO_SECURITY=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_security)
            DO_SECURITY=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --find)
            DO_FIND=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_find)
            DO_FIND=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --sudoers)
            DO_SUDOERS=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_sudoers)
            DO_SUDOERS=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --ps)
            DO_PS=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_ps)
            DO_PS=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --nis)
            DO_NIS=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_nis)
            DO_NIS=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --ntp)
            DO_NTP=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_ntp)
            DO_NTP=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --ad)
            DO_AD=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_ad)
            DO_AD=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --ad_firewall)
            DO_AD_FIREWALL=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_ad_firewall)
            DO_AD_FIREWALL=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --dns_root)
            DO_DNS_ROOT=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_dns_root)
            DO_DNS_ROOT=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --internet)
            DO_INTERNET=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_internet)
            DO_INTERNET=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --software)
            DO_SOFTWARE=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_software)
            DO_SOFTWARE=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --env)
            DO_ENV=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_env)
            DO_ENV=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --services)
            DO_SERVICES=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_services)
            DO_SERVICES=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --config)
            DO_CONFIG=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_config)
            DO_CONFIG=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --cache)
            DO_CACHE=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_cache)
            DO_CACHE=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --altfiles)
            DO_ALTFILES=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_altfiles)
            DO_ALTFILES=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --pbul)
            DO_PBUL=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_pbul)
            DO_PBUL=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --cron)
            DO_CRON=1
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --no_cron)
            DO_CRON=
            PASS_OPTIONS="$PASS_OPTIONS $1"
            ;;
        --*)
            $ECHO "Unsupported option: $1"
            exit 1
            ;;
        *)
            break
            ;;
    esac
    shift 1
done

ADdom="$1"
if [ -n "$2" ]; then
    $ECHO "ERROR: Too many arguments.  Did not expect '$2'."
    usage
    exit 1
fi


###########################################
# Support Functions
###########################################

pline()
{
    $ECHO "#####################################"
}

pblank()
{
    $ECHO ""
}

pfile_pass()
{
    pline
    $ECHO "//Contents of $1:"
    $awk -F: '{print $1 ":x:" $3 ":" $4 ":" $5 ":" $6 ":" $7}' $1 | grep -vi "password =" 2>&1
    pblank
}
pfile()
{
    pline
    $ECHO "// Contents of $1:"
    grep -vi "password " "$1" 2>&1
    pblank
}

pfile_cond()
{
    if [ -f "$1" ]; then
        pfile "$1"
    fi
}
pfile_alt()
{
    if [ -f "$1" ]; then
        $ECHO "//Contents of AltFile $1:"
        $awk -F$ALTFILES_FIELDSEP 'BEGIN{OFS="'$ALTFILES_FIELDSEP'"}; $'$ALTFILES_PASSFIELD'="x" { print }' $1 2>&1
        pblank
    fi
}

pfile_nc()
{
    pline
    $ECHO "// Contents of $1 (comments removed):"
    cat "$1" 2>&1 | egrep -v '^#'
    pblank
}

lsfile()
{
    pline
    $ECHO "// Listing of $1:"
    ls -ld "$1"
    pblank
    if [ -h "$1" ]; then
        pline
        $ECHO "// Listing of $1 (through symlink):"
        ls -ldL "$1"
        pblank
    fi
}

xping()
{
    case "$OStype" in
        aix|linux*)
            ping -c 1 -w 20 $1 2>&1
            ;;
        hpux)
            ping $1 -n 4 2>&1
            ;;
        solaris)
            ping $1 2 2>&1
            ;;
        darwin|freebsd)
            ping -c 1 -i 20 "$1" 2>&1
            ;;
    esac
}

check_port_telnet()
{
    $ECHO test | telnet $1 $2 2>&1
}

check_port()
{
    pline
    $ECHO "// port $1 ($2)"
    check_port_telnet $3 $1
    pblank
}

grab_adplugin_userinfo()
{
    if [ "x$ADdom" = "x" ]; then
        return 0
    fi
    if [ "$OStype" = "darwin" ]; then
        echo "Attempting to grab user information stored in the $ADdom/Users container"
        for i in `dscl "/Active Directory/$ADdom" -list /Users`;
        do dscl "/Active Directory/$ADdom" -read /Users/$i sAMAccountName userPrincipalName NFSHomeDirectory UniqueID PrimaryGroupID SMBSID SMBPrimaryGroupSID UserShell;
            pblank;
        done
    fi
}

grab_adplugin_alldomains_userinfo()
{
    if [ "$OStype" = "darwin" ]; then
        echo "Attempting to grab user information stored in the All Domains/Users container"
        for i in `dscl "/Active Directory/All Domains" -list /Users`;
        do dscl "/Active Directory/All Domains" -read /Users/$i RealName sAMAccountName userPrincipalName NFSHomeDirectory UniqueID PrimaryGroupID SMBSID SMBPrimaryGroupSID UserShell;
            pblank;
        done
    fi
}

grab_localplugin_userinfo()
{
    if [ "$OStype" = "darwin" ]; then
        for i in `dscl "/Local/Default" -list /Users | egrep -v "_|daemon|nobody"`;
        do echo `dscl "/Local/Default" -read /Users/$i RecordName | sed 's/RecordName: //g'`:*:`dscl "/Local/Default" -read /Users/$i UniqueID | sed 's/UniqueID: //g'`:`dscl "/Local/Default" -read /Users/$i PrimaryGroupID | sed 's/PrimaryGroupID: //g'`:`dscl "/Local/Default" -read /Users/$i RealName | sed -e 's/RealName://g' -e 's/^ //g' | awk '{printf("%s", $0 (NR==1 ? "" : ""))}'`:/Users/$i:`dscl "/Local/Default" -read /Users/$i UserShell | sed 's/UserShell: //g'`
        done
    fi
}

grab_localplugin_groupinfo()
{
    if [ "$OStype" = "darwin" ]; then
        for i in `dscl "/Local/Default" -list /Groups | egrep -v "_|daemon|nobody|accessibility|authedusers|bin|consoleusers|dialer|everyone|group|interactusers|localaccounts|mail|netaccounts|netusers|network|nogroup|owner|smmsp|utmp"`;
        do echo `dscl "/Local/Default" -read /Groups/$i RecordName | sed 's/RecordName: //g'`:`dscl "/Local/Default" -read /Groups/$i PrimaryGroupID | sed 's/PrimaryGroupID: //g'`:`dscl "/Local/Default" -read /Groups/$i GroupMembership | sed -e 's/GroupMembership: //g' -e 's/ /,/g'`;
        done
    fi
}

check_darwin_adplugin_usage()
{
    if [ "$OStype" = "darwin" ]; then
        pline
        echo "// Mac OS X/Darwin only: Checking to see if Active Directory Plugin is being used."
        echo "If script is run without sudo or not as root, it may prompt for your password."
        sudo /usr/sbin/dsconfigad -show | grep "You are not bound to Active Directory" > /dev/null
        if [ "$?" = "0" ]; then
            echo "dsconfigad reports that the AD plugin is NOT bound to Active Directory."
            pblank
        else
            /usr/bin/dscl "/Active Directory/$ADdom" -read . | grep "not valid" > /dev/null
            if [ "$?" = "0" ]; then
                pblank
                echo "$ADdom is not the valid domain that this OS X machine is bound to; Attempting 'All Domains'."
                /usr/bin/dscl "/Active Directory/All Domains" -read . | grep "not valid" > /dev/null
                if [ "$?" = "0" ]; then
                    pblank
                    echo "Something isn't right with the dsconfigad config, attempting to output some information:"
                    sudo /usr/sbin/dsconfigad -show
                    pblank
                    /usr/bin/dscl "/Active Directory" -read .
                    pblank
                else
                    pblank
                    echo "Information for 'All Domains' has been detected:"
                    sudo /usr/sbin/dsconfigad -show
                    pblank
                    grab_adplugin_alldomains_userinfo
                    pblank
                fi		
                pblank
            else
                pblank
                echo "Information for $ADdom has been detected:"
                sudo /usr/sbin/dsconfigad -show
                pblank
                grab_adplugin_userinfo
                pblank
            fi			
        fi		
    fi
}

check_darwin_localplugin_usage()
{
    if [ "$OStype" = "darwin" ]; then
        pblank
        echo "// Mac OS X/Darwin only: Grabbing information from Local Directory service."
        pblank
        echo "// Contents of /etc/passwd (via dscl in OS X):"
        grab_localplugin_userinfo
        pblank
        echo "// Contents of /etc/group (via dscl in OS X):"
        grab_localplugin_groupinfo
        pblank
    fi
}

find_files_cond()
{
    if [ -d "$1" ]; then
        pline
        $ECHO "// Contents of $1"
        find "$1" 2>&1
        pblank
    fi
}

show_in_path()
{
    _show_in_path=
    _bins=`echo "$1" | sed -e 's/:/ /g'`
    _dirs=`echo "$2" | sed -e 's/:/ /g'`
    for _bin in $_bins ; do
        for _dir in $_dirs ; do
            _file="$_dir/$_bin"
            if [ -f "$_file" ]; then
                _x=""
                if [ -x "$_file" ]; then
                    _x=" (x)"
                fi
                echo "Found: ${_file}${_x}"
                _show_in_path="$_show_in_path $_file"
            fi
        done
    done
}

if [ -z "$ADdom" ]; then
    $ECHO "ERROR: Missing AD domain argument"
    $ECHO "Will not perform AD tests."
    DO_AD=""
    #disable AD checks if no AD domain
fi

case "$ADdom" in
    "")
        # this is ok because it's blank
        ;;
    *.)
        $ECHO "Domain name name should not end with a dot"
        exit 1
        ;;
    .*)
        $ECHO "Domain name name should not start with a dot"
        exit 1
        ;;
    *..*)
        $ECHO "Domain name has two or more dots in a row"
        exit 1
        ;;
    *.*)
        # This is ok because it contains at least one dot in the middle.
        ;;
    *)
        $ECHO "Missing dot in the domain name"
        exit 1
        ;;
esac

if [ -n "$DO_LOG" ]; then
    rm -f $OUTFILE_PATH
    sh $0 --no_log $PASS_OPTIONS "$ADdom" 2>&1 | tee $OUTFILE_PATH
    pline
    $ECHO "The output of this program has been captured in $OUTFILE_PATH"
    pline
    exit
fi

pline
$ECHO "// Date: `date`"
$ECHO "// Script Name: $0"
$ECHO "// Script Version: $script_version"
$ECHO "// Input received: $ADdom"
pblank

pline
$ECHO "// Options:"
$ECHO "DO_DF=[$DO_DF]"
$ECHO "DO_LUG=[$DO_LUG]"
$ECHO "DO_FIND=[$DO_FIND]"
$ECHO "DO_SUDOERS=[$DO_SUDOERS]"
$ECHO "DO_PS=[$DO_PS]"
$ECHO "DO_NIS=[$DO_NIS]"
$ECHO "DO_NTP=[$DO_NTP]"
$ECHO "DO_AD=[$DO_AD]"
$ECHO "DO_AD_FIREWALL=[$DO_AD_FIREWALL]"
$ECHO "DO_DNS_ROOT=[$DO_DNS_ROOT]"
$ECHO "DO_INTERNET=[$DO_INTERNET]"
$ECHO "DO_SOFTWARE=[$DO_SOFTWARE]"
$ECHO "DO_ENV=[$DO_ENV]"
$ECHO "DO_SERVICES=[$DO_SERVICES]"
$ECHO "DO_CONFIG=[$DO_CONFIG]"
$ECHO "DO_CACHE=[$DO_CACHE]"
$ECHO "DO_ALTFILES=[$DO_ALTFILES]"
$ECHO "DO_PBUL=[$DO_PBUL]"
$ECHO "DO_CRON=[$DO_CRON]"
pblank

pline
$ECHO "OStype: $OStype"
pblank


##########################################
# Define some default flags
###########################################
if [ $OStype = "linux-rpm" ]; then
    ECHO="echo -e"
fi

###########################################
# Get some system parameters
if [ $OStype = "hpux" ]; then
    processor=`uname -m`
else
    processor=`uname -p`
fi

if [ "$OStype" = "solaris" ]; then
    awk="nawk"
else
    awk="awk"
fi

if [ $OStype = "aix" ]; then
    platform=`uname -M`
    df_cmd="df -k"
elif [ $OStype = "hpux" ]; then
    platform=`getconf _SC_CPU_VERSION`
    # From /usr/include/unistd.h
    case "$platform" in
        524)
            platform=mc68020
            ;;
        525)
            platform=mc68030
            ;;
        525)
            platform=mc68040
            ;;
        523)
            platform=hppa10
            ;;
        528)
            platform=hppa11
            ;;
        529)
            platform=hppa12
            ;;
        532)
            platform=hppa20
            ;;
        768)
            platform=ia64
            ;;
    esac
    df_cmd="df -kl"
elif [ $OStype = "darwin" ]; then
    platform=`uname -m`
    df_cmd="df -kl"
elif [ $OStype = "freebsd" ]; then
    platform=`uname -m`
    df_cmd="df -kl"
else
    platform=`uname -i`
    df_cmd="df -kl"
fi

host=`hostname`

pline
$ECHO "// hostname:\t $host"
$ECHO "// kernel:\t $kernel"
$ECHO "// processor:\t $processor"
$ECHO "// platform:\t $platform"
if [ $OStype = "solaris" ]; then
    isa=`isainfo -b 2>&1`
    $ECHO "// ISA bit level:\t $isa"
fi
pblank

###########################################
# Get OS info
pline
$ECHO "// Full uname output: "
uname -a 2>&1
pblank

case "$OStype" in
    aix)
        pline
        $ECHO "// OS level: "
        oslevel -r
        pblank
        ;;
    darwin)
        pline
        $ECHO "// OS sw_vers report: "
        sw_vers
        pblank
        ;;
    solaris)
        pline
        $ECHO "// Zone Type: "
        if [ -x /usr/sbin/zoneadm ]; then
            if [ `pkgcond is_sparse_root_nonglobal_zone;echo $?` -eq 0 ]; then
                $ECHO "sparse root"
            elif [ `pkgcond is_whole_root_nonglobal_zone;echo $?` -eq 0 ]; then
                $ECHO "whole root"
            elif [ `pkgcond is_global_zone;echo $?` -eq 0 ]; then
                $ECHO "global"
            fi
        else
            $ECHO "Not supported"
        fi
        pblank

        for file in /etc/*release ; do
            if [ -f "$file" ]; then
                pfile "$file"
            fi
        done
        ;;
    *)
        for file in /etc/*release /etc/*version ; do
            if [ -f "$file" ]; then
                pfile "$file"
            fi
        done
        ;;
esac

if [ -n "$DO_DF" ]; then
    pline
    $ECHO "// disk utilization:"
    pblank
    $df_cmd
    pblank
fi

pline
$ECHO "// mounted filesystems"
$ECHO "// make sure /, /usr, and /opt are not mounted read-only (ro)"
pblank
mount 2>&1
pblank

###########################################
# Get DHCP status
pline
$ECHO "// Checking DHCP status"

if [ $OStype = "solaris" ]; then
    ifconfig -a dhcp status 2>&1
elif [ $OStype = "freebsd" ]; then
    dhcp=`ps auxww | grep dhclient | grep -v grep`
    if [ "$dhcp" ]; then
        $ECHO "// The DHCP client appears to be running"
        $ECHO $dhcp
    else
        $ECHO "// The DHCP client does not appear to be running"
    fi
else
    dhcp1=`ps -ef | grep dhcpcd | grep -v grep`
    dhcp2=`ps -ef | grep dhclient | grep -v grep`
    if [ "$dhcp1" -o "$dhcp2" ]; then
        $ECHO "// The DHCP client appears to be running"
        $ECHO $dhcp1
        $ECHO $dhcp2
    else
        $ECHO "// The DHCP client does not appear to be running"
    fi
fi
pblank

#########################################
# Get Network info
pline

case "$OStype" in
    solaris|aix|hpux|darwin|freebsd)
        $ECHO "// Network Interfaces via netstat:"
        netstat -in | egrep -v 'Name|\*|\:' | awk '{ print $1,$4 }'
        ;;
    *)
        $ECHO "// Network Interfaces via ifconfig:"
        ifconfig | egrep 'inet addr|Link' | grep -v inet6
        ;;
esac
pblank

pline
$ECHO "// Route Table:"
netstat -nr 2>&1
pblank

pline
$ECHO "// Attempting to ping default router: "
GW=`netstat -nr | egrep 'default|UG ' | awk '{ print $2 }'`
if [ -n "$GW" ]; then
    xping $GW
else
    $ECHO "no default gateway configured!"
fi
pblank

###########################################
# nsswitch and resolv info
if [ $OStype = "aix" ]; then
    nsfile="/etc/netsvc.conf"
else
    nsfile="/etc/nsswitch.conf"
fi

pfile_nc $nsfile
pfile_nc /etc/resolv.conf
pfile_cond /etc/security/login.cfg
pfile_cond /etc/security/methods.cfg
pfile_cond /usr/lib/security/methods.cfg
pfile_cond /etc/security/aixpert
pfile_cond /etc/security/user
pfile_cond /etc/security/group

###########################################
# FQDN/IP info
pline
$ECHO "// FQDN and IP from /etc/hosts:"
grep -i "$host" /etc/hosts
pblank

pline
$ECHO "// FQDN and IP from DNS:"
fqdn=`nslookup $host | grep Name: | awk '{ print $2 }'`
ip=`nslookup $host | $AWK 'BEGIN{ getline; getline }; /Address:/ { print $2; }'`
$ECHO "FQDN:\t\t $fqdn"
$ECHO "IP address:\t $ip"
pblank

if [ -x `which perl` ]; then
    pline
    $ECHO "// FQDN from gethostbyname:"
    `which perl` -e '($name)=gethostbyname($ARGV[0]);print "$name\n";' "$host"
    pblank
elif [ -x /usr/bin/perl ]; then
    pline
    $ECHO "// FQDN from gethostbyname:"
    /usr/bin/perl -e '($name)=gethostbyname($ARGV[0]);print "$name\n";' "$host"
    pblank
fi

###########################################
# Get versions of important system utils
pline
$ECHO "// Here are the installed versions of some important system utilities"

case "$OStype" in
    linux-deb)
        apt-cache showpkg sudo openssl bash rpm ssh perl | egrep -A2 "Package:"
        ;;
    solaris)
        pkginfo | awk ' { print $2 } ' | egrep 'sudo|ssh|^SUNWbash$|^SUNWopensslr$|SUNWperl5' | xargs -n1 -iQ sh -c "echo Q ; pkginfo -l Q | egrep 'NAME|VERSION|PKGINST'"
        ssh -V 2>&1
        ;;
    aix)
        rpm -q sudo openssl bash perl
        rpm --version
        ssh -V 2>&1
        pblank
        $ECHO "This is AIX, so here is some lslpp output for ssh"
        lslpp -L | grep ssh 2>&1
        pblank
        lslpp -Lc openssh.base.client openssh.base.server
        pblank
        ;;
    linux-rpm)
        rpm -q sudo openssl bash rpm perl
        ssh -V 2>&1
        rpm -qa | egrep 'centeris|likewise|pbis|centrify|quest'
        ;;
    hpux)
        # swlist -l subproduct -l fileset
        swlist -a revision -a title -a location "*[Ss]ecure*[Ss]hell*" "*[Ss][Ss][Hh]*" "*[Ss][Uu][Dd][Oo]*" "*[Ss][Ss][Ll]*"
        ;;
    darwin)
        ssh -V 2>&1
        sudo -V 2>&1
        perl -V 2>&1
        ;;
    freebsd)
        ssh -V 2>&1
        sudo -V 2>&1
        perl -V 2>&1
        ;;
    *)
        echo "Unsupported OS/Platform"
esac

pblank

###########################################
# Get locations of important system utils
pline
$ECHO "// Here are the locations of some important system utilities"
which sudo openssl bash rpm ssh apt-get

###########################################
# Get locations of important files
pline
$ECHO "// Locations of important files"
#_SUDO_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/csw/sbin:/opt/csw/bin
#_SUDO_CONF_PATH=/usr/local/etc:/usr/etc:/etc:/opt/csw/etc
_SUDO_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/sudo/sbin:/opt/sudo/bin:/opt/csw/sbin:/opt/csw/bin
_SUDO_CONF_PATH=/usr/local/etc:/usr/etc:/etc:/opt/sudo/etc:/opt/csw/etc
show_in_path ssh:sshd /usr/sbin:/opt/ssh/sbin:/usr/local/sbin:/usr/bin:/opt/ssh/bin:/usr/local/bin:/usr/lib/ssh:/usr/openssh/sbin:/usr/openssh/bin:/opt/csw/sbin:/opt/csw/bin
show_in_path ssh_config:sshd_config /etc/ssh:/opt/ssh/etc:/usr/local/etc:/etc:/etc/openssh:/usr/openssh/etc:/opt/csw/etc
show_in_path visudo ${_SUDO_PATH}
show_in_path sudo ${_SUDO_PATH}
sudo="${_show_in_path}"
show_in_path sudoers ${_SUDO_CONF_PATH}
sudoers="${_show_in_path}"
show_in_path smb.conf /etc/samba:/opt/samba/etc:/usr/local/etc:/etc:/usr/local/samba/etc:/usr/local/smb/etc:/opt/csw/etc
smbconf="${_show_in_path}"
show_in_path nscd.conf /etc:/etc/nscd:/usr/local/etc:/opt/csw/etc:/opt/etc:/etc/opt/
nscdconf="${_show_in_path}"
pblank

###########################################
# Get patch information
pline
$ECHO "// OS patch information"
case "$OStype" in
    solaris)
        showrev -p | egrep '115831|115832'
        ;;
    hpux)
        swlist -l product '*,c=patch' | egrep 'PHCO_31923|PHCO_35743|PHKL_34805|PHSS_36004'
        ;;
    darwin)
        if [ `uname -v | awk '{ print $4 }' | cut -d'.' -f1` = '8' ]
        then
            ls -d /Library/Receipts/Sec*
            ls -d /Library/Receipts/MacOS*
        elif [ `uname -v | awk '{ print $4 }' | cut -d'.' -f1` = '9' ]
        then
            ls /Library/Receipts/boms/com.apple.pkg.update.*
        fi
        ;;
    *)
        echo "Unsupported OS/Platform"
        ;;
esac
pblank

###########################################
# Get sudo information
for _file in ${sudo} ; do
    lsfile $_file
    pline
    $ECHO "// Output of $_file -V:"
    # Note: sudo -V only outputs a lot when run as root.
    if [ -x $_file ]; then
        $_file -V
    else
        $ECHO "ERROR: $_file is not executable"
    fi
    pblank
done

###########################################
# Get smb.conf information
for _file in ${smbconf} ; do
    lsfile $_file
    pline
    pfile $_file
    pblank
done

###########################################
###########################################
# Kerberos stuff
pfile /etc/krb5.conf
pfile_cond /etc/krb5/krb5.conf

###########################################
# PAM stuff
case "$OStype" in
    solaris|aix|hpux)
        pfile /etc/pam.conf
        ;;
    freebsd)
        $ECHO "// Contents of /etc/pam.d:"
        ls -dp /etc/pam.d/* 2>&1
        pblank

        pfile /etc/pam.d/system
        ;;
    *)
        pline
        $ECHO "// Contents of /etc/pam.d:"
        ls -dp /etc/pam.d/* 2>&1
        pblank

        pfile /etc/pam.d/common-auth
        pfile /etc/pam.d/system-auth
        pfile /etc/pam.d/password-auth
        ;;
esac

###########################################
# Check for local users and groups
if [ -n "$DO_LUG" ]; then
    if [ $OStype = "darwin" ];
    then
        check_darwin_localplugin_usage
    elif [ "$OStype" = "aix" ];
    then
        pfile_pass /etc/security/passwd
        pfile /etc/security/group
        pfile /etc/passwd
        pfile /etc/group
    else
        pfile_pass /etc/passwd
        pfile /etc/group
    fi
fi

###########################################
# Check for files used for security access

if [ -n "$DO_SECURITY" ]; then
    pfile_cond /etc/netgroup
    pfile_cond /etc/security/access.conf
    pfile_cond /etc/sssd/sssd.conf
    pfile_cond /etc/ldap.conf
    pfile_cond /etc/nslcd.conf
    pfile_cond /etc/pam_ldap.conf
    pfile_cond /etc/openldap/ldap.conf
    pfile_cond /etc/ldap/ldap.conf
    pfile_cond /etc/ssh/sshd_config
    pfile_cond /etc/opt/boks/ssh/sshd_config
    pfile_cond /etc/opt/boksm/ssh/sshd_config
    pfile_cond /usr/local/etc/ssh/sshd_config
    pfile_cond /usr/local/etc/sshd_config
    for i in /etc/opt/quest/vas/*; do
        pfile_cond $i
    done
fi

###########################################
# sudoers file(s)
if [ -n "$DO_SUDOERS" ]; then
    for _file in ${sudoers} ; do
        lsfile $_file
        pfile $_file
    done

    _sudodirs=`echo "${_SUDO_CONF_PATH}" | sed -e 's/:/ /g'`
    for _file in ${_sudodirs} ; do
        if [ -d ${_file}/sudoers.d ]; then
            for _sudofile in ${_file}/sudoers.d/* ; do
                pfile ${_sudofile}
            done
        fi
    done
fi


###########################################
# Check for previously installed binaries
if [ -n "$DO_FIND" ]; then
    pline
    $ECHO "// Checking for previously installed binaries"
    pblank

    find_files_cond /usr/centeris
    find_files_cond /opt/centeris
    find_files_cond /opt/likewise
    find_files_cond /opt/pbis
fi

###########################################
#Check PBIS / Likewise Config
if [ -n "$DO_CONFIG" ]; then
    pline
    $ECHO "// Checking PBIS Config"
    pblank

    if [ -x /opt/pbis/bin/config ]; then
        LW_CONFIG="/opt/pbis/bin/config --dump"
    elif [ -x /opt/likewise/bin/lwconfig ]; then
        LW_CONFIG="/opt/likewise/bin/lwconfig --dump"
    elif [ -f /etc/likewise/lsassd.conf ]; then
        LW_CONFIG="cat /etc/likewise/lsassd.conf"
    elif [ -f /etc/likewise/lwiauthd.conf ]; then
        LW_CONFIG="cat /etc/likewise/lwiauthd.conf"
    elif [ -f /etc/centeris/lwiauthd.conf ]; then
        LW_CONFIG="cat /etc/centeris/lwiauthd.conf"
    else
        LW_CONFIG="$ECHO ''"
    fi
    $LW_CONFIG

    pline
    $ECHO "// Checking PBIS get-status"
    pblank
    if [ -x /opt/pbis/bin/get-status ]; then
        LW_GETSTATUS="/opt/pbis/bin/get-status"
    elif [ -x /opt/likewise/bin/lw-get-status ]; then
        LW_GETSTATUS="/opt/likewise/bin/lw-get-status"
    else
        LW_GETSTATUS="$ECHO ''"
    fi
    $LW_GETSTATUS
fi


###########################################
# Cache Config file(s)
if [ -n "$DO_CACHE" ]; then
    for _file in ${nscdconf} ; do
        lsfile $_file
        pfile $_file
    done
fi

###########################################
# Check for alternate files to gather, if customer requested
if [ -n "$DO_ALTFILES" ]; then
    for filename in $ALTFILES; do
        pfile_alt $filename
    done
    for filename in /home/*/.netrc; do
        pfile_cond $filename
    done

    for homedir in `perl -e 'while (1) { ($na,$pa,$ui,$gi,$qu,$co,$ge,$di,$sh,$ex) = getpwent(); exit if ($na=~/^$/); print $di."\n";}'`; do
        pfile_cond $homedir/.netrc
    done
fi

###########################################
# Check for PBUL files ot gather if requested by customer
if [ -n "$DO_PBUL" ]; then
    for filename in /etc/pb.conf /etc/pb.settings /etc/pb.cfg /etc/pbulsolrupdate /etc/pb/*; do pfile_cond $filename; done
fi

###########################################
# Check for crontabs owned by accounts if requested

if [ -n "$DO_CRON" ]; then
    for crondir in /var/spool/cron/crontabs /var/spool/cron/atjobs /var/spool/cron/crontab /var/spool/cron; do
        if [ -d "$crondir" ]; then
            lsfile "$crondir"
        fi
    done
fi
###########################################
# Check for Processes
if [ -n "$DO_PS" ]; then
    pline
    $ECHO "// ps output:"
    $ECHO "---------------------<START PS>-------------------"
    case "$OStype" in
        darwin|freebsd)
            ps auxww
            ;;
        *)
            ps -elf
            ;;
    esac
    $ECHO "---------------------<END PS>-------------------"
    pblank
fi

###########################################
# NIS server info
if [ -n "$DO_NIS" ]; then
    pline
    $ECHO "// NIS Domain:"
    domainname
    pblank

    pline
    $ECHO "// NIS Domain Server:"
    ypwhich
    pblank
fi

###########################################
# NTP info
if [ -n "$DO_NTP" ]; then
    pline
    $ECHO "// NTP Info:"
    ntpq -pn
    pblank
fi

###########################################
# Installed Software

if [ -n "$DO_SOFTWARE" ]; then
    pline
    $ECHO "//Installed Software:"
    case "$OStype" in
        solaris)
            showrev -p
            pkginfo -l
            ;;
        hpux)
            swlist -l product '*,c=patch'
            ;;
        darwin)
            if [ `uname -v | awk '{ print $4 }' | cut -d'.' -f1` = '8' ]
            then
                ls -d /Library/Receipts/Sec*
                ls -d /Library/Receipts/MacOS*
            elif [ `uname -v | awk '{ print $4 }' | cut -d'.' -f1` = '9' ]
            then
                ls /Library/Receipts/boms/com.apple.pkg.update.*
            fi
            find / -name "*.app" -print
            ;;
        aix)
            lslpp -L
            oslevel -r
            instfix -i|grep ML
            ;;
        linux-rpm)
            rpm -qva
            ;;
        linux-deb)
            dpkg -l
            ;;
        *)
            echo "Unsupported OS/Platform"
            ;;
    esac
fi

###########################################
# Environment Variables
if [ -n "$DO_ENV" ]; then
    pline
    $ECHO "//Environment variables:"
    env
    pblank
fi

###########################################
# Active Directory
if [ -n "$DO_AD" ]; then
    pline
    $ECHO "// Attempting to query DNS for SRV records"
    nslookup -q=srv _ldap._tcp.$ADdom. 2>&1
    pblank

    pline
    $ECHO "// Attempting to query DNS for PDC SRV records"
    nslookup -q=srv _ldap._tcp.pdc._msdcs.$ADdom. 2>&1
    pblank

    pline
    $ECHO "// Attempting to query DNS for DC SRV records"
    nslookup -q=srv _ldap._tcp.dc._msdcs.$ADdom. 2>&1
    pblank

    pline
    $ECHO "// Attempting to query DNS for GC SRV records"
    nslookup -q=srv _ldap._tcp.gc._msdcs.$ADdom. 2>&1
    pblank

    pline
    $ECHO "// Attempting to ping AD domain: $ADdom"
    xping $ADdom.
    pblank

    ###########################################
    # Active Directory contd: check for OS X ADplugin usage and pull information, perform only when DOAD=1 is set
    check_darwin_adplugin_usage

    ###########################################
    # Active Directory contd: Test firewall

    if [ -n "$DO_AD_FIREWALL" ]; then
        pline
        $ECHO "// AD firewall test for TCP ports:"
        pblank

        check_port 88 Kerberos $ADdom.
        check_port 389 LDAP $ADdom.
        check_port 445 SMB $ADdom.
        check_port 464 kpasswd $ADdom.
        check_port 3268 gcat $ADdom.
    fi
fi
# End Active Directory checks

###########################################
# Root DNS configured
if [ -n "$DO_DNS_ROOT" ]; then
    pline
    $ECHO "// Checking root DNS"
    date
    nslookup www.microsoft.com.
    date
    pblank
fi

###########################################
# Ping internet
if [ -n "$DO_INTERNET" ]; then
    pline
    $ECHO "// Attempting to query Internet"
    check_port_telnet www.microsoft.com. 80
    pblank
fi


###########################################
# Services output
if [ -n "$DO_SERVICES" ]; then
    pfile /etc/services
fi

###########################################
# The End
pline
$ECHO "// End Time: `date`"
pblank

if [ "$OStype" = "solaris" ]; then
    if [ -x /usr/bin/zonename ]; then
        if [ `/usr/bin/zonename` = "global" ]; then
            pline
            $ECHO "//Global Zone Detection."
            pblank
            #descend into child zones if able
            zoneadm list
            for zone in `zoneadm list`; do
                ZONEROOT=`zonecfg -z $zone info zonepath | awk '{ print $2 }'`
                if [ $? -eq 0 ]; then
                    cp $0 $ZONEROOT/root/tmp/
                    if [ $? -ne 0 ]; then
                        $ECHO "ERROR: Can't copy script to $zone - continuing to next!"
                    else
                        chmod +x $ZONEROOT/root/tmp/`basename $0`
                        #not sure why I have to use double quotes here instead of single quotes, but I do:
                        zlogin $zone "/tmp/`basename $0` $PASS_OPTIONS $ADdom"
                        if [ $? -ne 0 ]; then
                            $ECHO "ERROR: Can't run $0 on $zone! Zone may be off, or inaccessible to this account!"
                        fi
                    fi
                fi
            done
        fi
    fi
fi

exit 0

# 0.1 10/29/07 Anthony Ciarochi initial
# 0.2 11/01/07 Anthony Ciarochi
#   Added DHCP, ISA type, Readonly filespace, and AIX TL level tests,
#   and fixed minor syntax errors
# 0.3 11/06/07 Anthony Ciarochi
#   added lslpp version check commands for AIX
# 0.3.3 - 2008/02/21 - Danilo Almeida - add LUG, find, etc.
# 0.3.4 - 2008/03/13 - Anthony Ciarochi - remove 'cd to working directory'
#   statement, added a conditional around the ping to the router,
#   and commented out the Internet connectivity test
# 0.3.4.1 - 2008/04/10 - Danilo Almeida - merge in some fixes to -z/-n tests,
#       clean up Linux check for ping, add control variable for internet
#       connectivity check.
# 0.3.4.2 - 2008/04/15 - Steven Kaplan - add NIS domain server output
# 0.3.5 - 2008/04/17 - Danilo Almeida - Add HP-UX support
# 0.3.5.1 - 2008/04/22 - Steve Kaplan - add NIS domain and ps support
# 0.3.6 - 2008/04/23 - Danilo Almeida - enhance HP-UX platform reporting;
#       add patch reporting; enhance Solaris package reporting; remove
#       duplicate NIS information; use final dot in fully qualified names.
# 0.3.7 - 2008/04/30 - Danilo Almeida - Add command-line options
#       to control whether certain checks are done.
# 0.3.8 - 2008/05/01 - Danilo Almeida - Add NTP check; rename --no_tee
#       to --no_log; enhance usage msg wrt on/off default; add --no_df to
#       skip disk space check.
# 0.3.9 - 2008/05/02 - Danilo Almeida - Show relevant packages for HP-UX.
# 0.3.10 - 2008/05/02 - Danilo Almeida - Refactor script, more
#       command-line options
# 0.3.11 - 2008/05/07 - Danilo Almeida - Allow for Sudo in HP-UX swlist.
# 0.3.12 - 2008/05/07 - Danilo Almeida - Search for ssh (and config), visudo,
#       sudoers in various paths used by the product.  Also display sudoers,
#       /etc/krb5/krb5.conf (if present), and /etc/netgroup (if present).
# 0.3.13 - 2008/05/15 - Danilo Almeida - Change defaults for options to
#       enable everything by default.  Then the default is to grab as much
#       data as possible.  Options can be used to speed things up or
#       avoid issues.
# 0.3.14 - 2008/05/15 - Danilo Almeida - Check ports 445 and 464 too.
# 0.3.15 - 2008/05/20 - Danilo Almeida - Output sudo -V information.
# 0.3.16 - 2008/07/08 - Robert Auch - output file contains hostname
# 0.3.17 - 2008/09/12 - Robert Auch - add gathering /etc/services
# 0.3.18 - 2008/09/17 - Robert Auch - add Darwin/Mac support
# 0.3.19 - 2008/09/18 - Justin Pittman - powerpc fixes; had to further separate commands for Darwin from the Unices
# 0.3.20 - 2008/10/02 - Yvo van Doorn - Added Darwin AD plugin usage detection and attempted information gathering; also fixed ps for OS X 10.4 as it doesn't support '-ef'.
# 0.3.21 - 2008/10/02 - Yvo van Doorn - Added rudementary OS X listing and fixed inet info for darwin.
# 0.3.22 - 2008/10/10 - Yvo van Doorn - Added 'All Domains' lookup if ADdom failed, also collecting more info on adplugin setup if it seems to be detected.
# 0.3.23 - 2008/10/21 - Yvo van Doorn - Darwin only: Added query against Local DS node and parsed it in a familiar output like /etc/passwd & /etc/group
# 0.3.24 - 2008/10/30 - Yvo van Doorn - Changes $() to `` in for loops; Solaris 9 doesn't like $().
# 0.3.25 - 2008/12/11 - Robert Auch - pfile_pass() for sanitized passwd file output - includes new "$awk" value
# 0.3.26 - 2009/01/18 - Robert Auch - add checking for global catalog
# 0.3.27 - 2009/01/29 - Yvo van Doorn - added additional SRV record checking after running into issues at Advance Internet.
# 0.3.28 - 2009/02/04 - Robert Auch - fix up aix passwd dumps
# 0.3.29 - 2009/02/12 - Yvo van Doorn - change "ifconfig" to "netstat" for non-Linux OSes for safety
# 0.3.30 - 2010/03/17 - Robert Auch - additional test for patch levels, environmental values.
# 0.3.31 - 2010/05/17 - Yvo van Doorn - finalized FreeBSD support,changed TRUEPATH variable creation to a elif statement,removed extra kernel/unneeded kernel definition on line 683,
# 1.0.0 - 2011/08/18 - Robert Auch - Because we've been using it long enough, it's "final". Also, likewise 5.0+ check to software list
#                                   and fix from Jack C. of GE for "head" statement.
# 1.1.0 - 2012/01/06 - Robert Auch - If on Solaris Global zone, descend into child zones
# 1.2.0 - 2013/01/14 - Robert Auch - PBIS Configuration Dump addition
# 1.2.1 - 2013/12/08 - Robert Auch - add ldap configuration dump
# 1.2.3 - 2014/03/04 - Robert Auch - add '-x /usr/bin/zoneadm' to avoid Solaris 8/9 problems
# 1.2.4 - 2014/03/17 - Robert Auch - update /etc/*release checking for non-Linux
# 1.2.5 -              Robert Auch - checkpoint versioning - something got missed in the notes
# 1.2.6 - 2014/09/08 - Robert Auch - add sshd_config gathering
# 1.2.7 - 2014/10/31 - Robert Auch - add zone type checking
# 1.2.8 - 2015/01/15 - Robert Auch - add Ubuntu nlscd.conf as an ldap.conf file. Better ssh versions for Ubuntu
# 1.2.9 - 2015/04/06 - Robert Auch - add smb.conf dumping, pam additions for RHEL 7
# 1.2.10 - 2015/05/05 - Robert Auch - debian-version gathering for Squeeze
# 1.3.0 - 2016/02/21 - Robert Auch - custom file gathering
# 1.3.1 - 2016/04/15 - Ben Hendin - disabled ad_firewall by default.  Renamed output files to .srf (Server Readiness File)
# 1.4.0 - 2016/07/10 - Robert Auch - PBUL data gathering
# 1.5.0 - 2018/02/17 - Robert Auch - gather nscd.conf, disable AD Domain requirement (for PBUL/PBPS usage)
# 1.6.0 - 2018/03/20 - Robert Auch - add crontab output gathering for service account parsing

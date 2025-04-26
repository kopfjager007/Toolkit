#!/bin/bash
# Author: Aaron Lesmeister
# File: slober.sh
# Purpose: Nmap "slober" all the services.


########################################
#  Global Variables
VERSION='1.1.1'
gDate=$(date +"%Y%m%d-%H%M%S")
F="$(tput bold)$(tput setaf 7)[$(tput setaf 9)!$(tput setaf 7)]$(tput sgr0)"
P="$(tput bold)$(tput setaf 7)[$(tput setaf 10)+$(tput setaf 7)]$(tput sgr0)"
W="$(tput bold)$(tput setaf 7)[$(tput setaf 11)?$(tput setaf 7)]$(tput sgr0)"
BOLD="$(tput bold)"
RST="$(tput sgr0)"
REGEX_IP="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
REGEX_HOST="(([a-zA-Z]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
########################################

########################################
#  Functions

HELP()
{
    # Help/usage
    # Note: removed RDP for the time being
    #            RDP   : Default port T:3389;          NSE scripts \"rdp-enum-encryption,rdp-ntlm-info\".
    printf """
%sNmap Slober.sh (%s)%s
    %s-s%s  Service
          Supported Services (only specify one):
            MSSQL : Default port T:1433            NSE scripts \"ms-sql-info,ms-sql-empty-password\".
            MYSQL : Default port T:3306            NSE scripts \"mysql-info\".
            NTP   : Default port U:123             NSE scripts \"ntp-info,ntp-monlist\".
            SMB   : Default port U:137,T:139,445   NSE scripts from old 'smb_slober.sh' tool.
            SMTP  : Default port T:25              NSE scripts \"smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-open-relay\".
            SNMP  : Default port U:161             NSE scripts \"snmp-info\".
            SSH   : Default port T:22              NSE scripts \"ssh2-enum-algos,sshv1\"
    %s-p%s  Port(s)
          Specify a single port or comma-separated ports (e.g \"T:1433,T:1434\").
          *If port switch omitted the default port(s) in Supported Services will be used.
    %s-t%s  Target (Single)
          A single IPv4 Address or host (e.g. ftp.client.tld)
    %s-l%s  Target (List)
          A file containing targets, one IPv4 or host per line.
    %s-w%s  Output File Prepend
          Optional value to prepend to output file.
    %s-h%s  Show help

    Examples:
        1. Run an SMB Slober scan with a list of targets. Defaults to specified default ports.
            $ slober.sh -s smb -l services/hosts-smb

        2. Run an SSH Slober against a single target and prepend \"external\" to out file. 
           Omitted \"T:\" or \"U:\" in ports will default to TCP.
            $ slober.sh -s ssh -p \"T:22,2222\" -w external -t 12.34.56.78\
    \n\n""" "$BOLD" "$VERSION" "$RST" "$BOLD" "$RST" "$BOLD" "$RST" "$BOLD" "$RST" "$BOLD" "$RST" "$BOLD" "$RST" "$BOLD" "$RST"
} 

SUDO_CHECK()
{
    # Scans require root/sudo so we need to check for it.
    if [ "$(id -u)" -ne 0 ]; then
        printf "\n%s %sThis script must be ran with sudo/root privileges.%s\n\n" "$F" "$BOLD" "$RST"
        exit 1
    fi
}

PARSE()
{
    # Parse-nmap-xml.py function

    # Check for parser on the system
    has_parser="$(which parse-nmap-xml.py > /dev/null; echo $?)"

    if [ "$has_parser" -eq 1 ]; then
        printf "\nHAS_PARSER = %s\n" "$has_parser"
        printf "\n%s %sParse-nmap-xml.py was not found. Download it from the Team Tools repo to parse issues.%s\n" "$W" "$BOLD" "$RST"
    else
        parser=$(which parse-nmap-xml.py)
        "$parser" --"$service" -i "$outfile.xml" -w "$out_pre"
    fi
}

SCAN()
{
    # Scan Function

    # Check for Nmap on the system
    has_nmap="$(which nmap > /dev/null; echo $?)"
    if [ "$has_nmap" -eq 1 ]; then
        printf "\n%s %sNmap was not found. Ensure it is installed and in PATH before re-running.%s\n" "$F" "$BOLD" "$RST"
        exit 1
    else
        # Nmap Bin
        nmap_bin="$(which nmap)"
    fi

    # Make sure a target has been supplied and is either "-t" or "-l"
    if [ -z "$tgt_single" ] && [ -z "$tgt_file" ]; then
        printf "\n%s You must specify either a single target \"-t\" or target file \"-l\"\n" "$F"
        exit 1
    elif [ -n "$tgt_single" ] && [ -n "$tgt_file" ]; then
        printf "\n%s You cannot specify both \"-t\" and \"-l\" at the same time.\n\n" "$F"
        exit 1
    else
        # Do not double quote $target when using with nmap command. We want word splitting if target file is provided. (https://www.shellcheck.net/wiki/SC2086)
        if [ -n "$tgt_single" ]; then 
            if [[ "$tgt_single" =~ $REGEX_IP ]] || [[ "$tgt_single" =~ $REGEX_HOST ]]; then
                target="$tgt_single"
            else
                printf "\n%s Supplied target is not valid.\n" "$F"
                exit 1
            fi
        elif [ -n "$tgt_file" ]; then
            if [ -f "$tgt_file" ]; then
                target="-iL $tgt_file"
            else
                printf "%s Supplied file does not exist.\n" "$F"
                exit 1
            fi
        else
            printf "%s You supplied straight garbage.\n" "$F"
            exit 1
        fi
    fi

    # Check if TCP/UDP specified in ports. Determines Nmap scan type (e.g. -sU|-sS)
    if [ -n "$port" ]; then
        ports="$port" 
        if [[ "$ports" =~ 'U:' ]] && [[ "$ports" =~ 'T:' ]]; then
            scan="-sU -sS"
        elif [[ "$ports" =~ 'U:' ]]; then
            scan="-sU"
        elif [[ "$ports" =~ 'T:' ]]; then
            scan="-sS"
        else
            # Default to TCP if no U: or T: given in -p
            scan="-sS"
        fi
    else
        # If -p not given
        ports=""
    fi 

    # SERVICE SCANS
    if [ -n "$service" ]; then
        case $service in

            # SMB
            smb)
                printf "\n%s SMB Slober started.\n\n" "$P"
                if [ "$ports" == "" ]; then
                    # If no ports were specified, use default
                    ports="U:137,T:139,T:445"
                    scan="-sU -sS"
                fi

                 # Check for Outfile Prepend
                if [ -n "$out_pre" ]; then
                    outfile="$out_pre-smb-slober"
                else
                    outfile="smb-slober_$gDate"
                fi

                # Run Nmap (Don't double quote $target)
                sudo "$nmap_bin" -Pn -T4 -v -sU -sS -p "$ports" --script=smb-enum-domains,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-server-stats,smb-system-info,smb-security-mode,smb-protocols,smb2-security-mode,smb2-capabilities -oA "$outfile" $target
                ;;

            # SSH
            ssh)
                printf "\n%s SSH Slober started.\n\n" "$P"
                if [ "$port" == "" ]; then
                    # If no ports were specified, use default
                    ports="T:22"
                    scan="-sS"
                fi

                 # Check for Outfile Prepend
                if [ -n "$out_pre" ]; then
                    outfile="$out_pre-ssh-slober"
                else
                    outfile="ssh-slober_$gDate"
                fi

                # Run Nmap (Don't double quote $target)
                sudo "$nmap_bin" -Pn -T4 --open -v "$scan" -p "$ports" --script=ssh2-enum-algos,sshv1 -oA "$outfile" $target
                ;;
            
            # MSSQL
            mssql)
                printf "\n%s MSSQL Slober started.\n\n" "$P"
                if [ "$port" == "" ]; then
                    # If no ports were specified, use default
                    ports="T:1433"
                    scan="-sS"
                fi

                 # Check for Outfile Prepend
                if [ -n "$out_pre" ]; then
                    outfile="$out_pre-mssql-slober"
                else
                    outfile="mssql-slober_$gDate"
                fi

                # Run Nmap (Don't double quote $target)
                sudo "$nmap_bin" -Pn -T4 --open -v "$scan" -p "$ports" --script=ms-sql-info,ssl-cert,ms-sql-empty-password -oA "$outfile" $target
                ;;
            
            # MySQL
            mysql)
                printf "\n%s MySQL Slober started.\n\n" "$P"
                if [ "$port" == "" ]; then
                    # If no ports were specified, use default
                    ports="T:3306"
                    scan="-sS"
                fi

                 # Check for Outfile Prepend
                if [ -n "$out_pre" ]; then
                    outfile="$out_pre-mysql-slober"
                else
                    outfile="mysql-slober_$gDate"
                fi

                # Run Nmap (Don't double quote $target)
                sudo "$nmap_bin" -Pn -T4 --open -v "$scan" -p "$ports" --script=mysql-info -oA "$outfile" $target
                ;;
            
            # RDP
            # NOTE: RDP not yet implemented because Nmap's rdp-enum-encryption output is gross.
            # rdp)
            #     printf "\n%s RDP Slober started.\n\n" "$P"
            #     if [ "$port" == "" ]; then
            #         # If no ports were specified, use default
            #         ports="T:3389"
            #         scan="-sS"
            #     fi

            #      # Check for Outfile Prepend
            #     if [ -n "$out_pre" ]; then
            #         outfile="$out_pre-rdp-slober"
            #     else
            #         outfile="rdp-slober_$gDate"
            #     fi

            #     # Run Nmap (Don't double quote $target)
            #     sudo "$nmap_bin" -Pn -T4 --open -v "$scan" -p "$ports" --script=rdp-enum-encryption,rdp-ntlm-info -oA "$outfile" $target
            #     ;;

            # SMTP
            smtp)
                printf "\n%s SMTP Slober started.\n\n" "$P"
                if [ "$port" == "" ]; then
                    # If no ports were specified, use default
                    ports="T:25"
                    scan="-sS"
                fi

                # Check for Outfile Prepend
                if [ -n "$out_pre" ]; then
                    outfile="$out_pre-smtp-slober"
                else
                    outfile="smtp-slober_$gDate"
                fi

                # Run Nmap (Don't double quote $target)
                sudo "$nmap_bin" -Pn -T4 --open -v "$scan" -p "$ports" --script=smtp-enum-users,smtp-commands,smtp-open-relay,smtp-ntlm-info --script-args smtp-enum-users.methods={EXPN,VRFY,RCPT} -oA "$outfile" $target
                ;;

            # SNMP
            # Note; Not sure if i'll parse SNMP with parse-nmap-xml.py; msf's snmp_enum gives better evidence. We'll see...
            snmp)
                printf "\n%s SNMP Slober started.\n\n" "$P"
                if [ "$port" == "" ]; then
                    # If no ports were specified, use default
                    ports="U:161"
                    scan="-sU"
                fi

                 # Check for Outfile Prepend
                if [ -n "$out_pre" ]; then
                    outfile="$out_pre-snmp-slober"
                else
                    outfile="snmp-slober_$gDate"
                fi

                # Run Nmap (Don't double quote $target)
                sudo "$nmap_bin" -Pn -T4 --open -v "$scan" -p "$ports" --script=snmp-info -oA "$outfile" $target
                ;;
            
            # NTP
            ntp)
                printf "\n%s NTP Slober started.\n\n" "$P"
                if [ "$port" == "" ]; then
                    # If no ports were specified, use default
                    ports="U:123"
                    scan="-sU"
                fi

                 # Check for Outfile Prepend
                if [ -n "$out_pre" ]; then
                    outfile="$out_pre-ntp-slober"
                else
                    outfile="ntp-slober_$gDate"
                fi

                # Run Nmap (Don't double quote $target)
                sudo "$nmap_bin" -Pn -T4 --open -v "$scan" -p "$ports" --script=ntp-info,ntp-monlist -oA "$outfile" $target
                ;;
            
            # PROTO
            #proto|PROTO)
            #   printf "\n%s Add moar services as we expand.\n" "$P"
            #   # Run Nmap (Don't double quote $target)
            #   ;;

            # Unrecognized or currently unsupported service specified.
            *)
                printf "\n%s Unrecognized or currently unsupported service specified.\n\n" "$F"
                exit 1
                ;;
        esac
        PARSE "$scan" "$out_pre" "$outfile"
    else
        printf "\n% Unknown service specified.\n" "$F"
        exit 1
    fi
}
########################################

########################################
#  Main

if [ $# -eq 0 ]; then
    HELP
    exit 0
fi

# Command Line Options
# -s service -p port <-t ip_addr|-l target_file> -w out_pre -h help
while getopts :s:p:t:l:w:vh flag
do
    case "${flag}" in
        s)
            service="$(echo "${OPTARG}" | tr '[:upper:]' '[:lower:]')"
            ;;
        p)
            port=${OPTARG}
            ;;
        t)
            tgt_single=${OPTARG}
            ;;
        l)
            tgt_file=${OPTARG}
            ;;
        w)
            out_pre=${OPTARG}
            ;;
        h)
            HELP
            exit 0
            ;;
        v)
            printf "Version: %s\n\n" "$VERSION"
            exit 0
            ;;
        :)
            printf "\n%s %sMissing argument for %s.%s\n" "$F" "$BOLD" "$OPTARG" "$RST"
            exit 1
            ;;
        *)
            printf "\n%s %sUnrecognized flag provided: %s %s\n" "$W" "$BOLD" "$OPTARG" "$RST"
            HELP
            exit 1
            ;;
    esac
done

SCAN "$service" "$port" "$tgt_single" "$tgt_file" "$out_pre"
########################################

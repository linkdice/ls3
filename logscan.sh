#!/bin/bash
##the log must be ipsec.log or ipsec.log.x
##you must copy and past the entire endpoint name from the list priovided

if [[ "$EUID" -ne 0 ]]; then
    echo "Sorry, you need to run this as root, please tpye: 'sudo su' in order to run this as the root user"
    exit
fi
bold=$(tput bold)
normal=$(tput sgr0)
NC="\033[0m"                  # No color
Black="\033[0;30m"        # Black
Green="\033[0;32m"        # Green
yellow="\033[0;33m"       # yellow
Blue="\033[0;34m"         # Blue
Purple="\033[0;35m"       # Purple
Cyan="\033[0;36m"         # Cyan
White="\033[0;37m"        # White
red="\033[0;31m"	  # red
BlueHL="\e[104m"	  #Blue Highlighted
Default="\e[49m"	  #default background color

function list_peers () {
echo "List of endpoints: "
sudo cat /etc/ipsec.secrets | grep "#" | sed 's/#//'
exit
}

function log_status () {
echo "endpoint name?: "
read endpoint
sudo ipsec auto status | grep $endpoint | grep newest | grep "#"
exit
}

function peer_pro () {
echo "endpoint name?: "
read endpoint
cat /var/www/logs/ipsec.log | grep $endpoint | grep -i "peer pro" | awk '{print $9,$10,$11}' | sort -u
exit
}

if [[ -z "$1" ]]; then
    echo "running interactive script"
elif [[ $1 == "list" ]]; then
    list_peers
elif [[ $1 == "list_peers" ]]; then
    list_peers
elif [[ $1 == "log_status" ]]; then
    log_status
elif [[ $1 == "status" ]]; then
    list_peers
    log_status
elif [[ $1 == "peer_pro" ]]; then
    peer_pro
else
    echo -e "${red}CML not supported, OPTIONS= list_peer log_status  peer_pro     OR dont specific a variable${NC}"
    exit
fi

echo -n "What file would you like to look at?: "
read file

if [ "$file" = "ipsec.log" ] ; then
    echo " "
else
    if [ "$file" = "ipsec.log.1" ] ; then
        echo -e "${Cyan}${bold}DISREGARD THE 'last p1 and p2 rekey times' below!!${normal}${NC}"
    else
        echo -e "${red}${bold}log not found OR you typed something in wrong${normal}${NC}"
        exit 3
    fi
fi

echo "List of endpoints: "
sudo cat /etc/ipsec.secrets | grep "#" | sed 's/#//'

#specificy what endpoint the EF will look at
echo -n "What endpoint are you looking for?: "
read endpoint

#sudo ls /etc/ipsec.d/*$endpoint1* | cut -d / -f 4-8 | cut -d "_" -f 2-10 | cut -d . -f 1
#echo "would you like to look at a specific tunnel? enter=no: "
#read endpoint
#if [ $endpoint="" ] ; then
#    endpoint=$endpoint1
#fi

echo " "
#display endpoint configruation, display the 'peer proposed subnets " use your eyes and see the discrepancies.
subnet_propose () {
    declare -a leftsubnets
    declare -a rightsubnets
    for tunfile in /etc/ipsec.d/cftconn_$endpoint*.cft;
    do
        leftsubnets+=("$(sudo cat $tunfile | grep leftsubnet | cut -d = -f 2)")
        rightsubnets+=("$(sudo cat $tunfile | grep rightsubnet | cut -d = -f 2)")
    done
    echo -e "${yellow}${bold}These are the tunnels defined on VNS3 (past and present):${normal}${NC}"
    for ((tun=0;tun<${#leftsubnets[@]};tun++));
    do
        printf "%s <--> %s\n" "${leftsubnets[tun]}" "${rightsubnets[tun]}"
    done
    remotetunnels=$(cat /var/www/logs/$file | grep $endpoint | grep "peer proposed" | cut -d ":" -f 6,7 | sed 's/:0\/0 -> / <--> /g' | sort -u)
    echo -e "the remote side has proposed the following: "
    for element in "$remotetunnels";
    do
        echo -e "\e[33m$element${NC}"
    done
#    echo $tunefile1
#    echo $leftsubnets1
    echo " "
}

if cat $file | grep $endpoint | grep -q -i "doesn’t match my proposal" ; then
    other_tunnels=$(cat $file | grep $endpoint | grep -i "doesn't match my proposal" | cut -d - -f 2 | sort -u)
    echo "there could be other tunnels(subnet pairs) that the peer is proposing"
    echo -e "the peer is proposing: ${yellow}$other_tunnels${NC}"
fi

#is this connection ikev2??
ikev2_test () {
if sudo cat /etc/ipsec.d/*$endpoint* | grep -q -e "ikev2=insist" -e "ikev2=permit" ; then
    echo -e "${yellow}${bold}THIS VNS3 ENDPOINT IS SET UP FOR IKEV2${normal}${NC}"
    if cat $file | grep $endpoint | tail -50 | grep -q -i "v2N_NO_PROPOSAL_CHOSEN" ; then
        lastv2nopro=$(tac $file | grep $endpoint | grep -m 1 -i "v2n_no_pro" | cut -d "." -f 1 )
        echo -e "${red}v2N_NO_PROPOSAL_CHOSEN messages are present ${NC},last msg at ${red}$lastv2nopro${NC}"
        echo -e "${bold}${yellow}peer is configured for IKEv1 -OR-"
        echo -e "PSK mismatch -OR-"
        echo -e "Peer ID/IKE ID mismatch/not set -OR-"
        echo -e "parameters aren't matching -OR-"
        echo -e "NAT-T mismatch${NC}${normal}"
        date1=$(date -u | cut -d " " -f 2-5)
        echo -e  "                      CURRENT UTC TIME: ${BlueHL}$date1${NC} "
    else
        echo -e "${Green} v2n_no_proposal_chosen messages = NONE${NC}"
    fi
else
   echo -e "${yellow}this endpoint is not ikev2${NC}, keep going---->"
fi
}

ikev2_no_pro () {
    if sudo tail -70 $file | grep $endpoint | grep -q -i "no local proposal matches remote proposals" ; then
        echo -e "${red}IPSec parameters dont match peers. check encryption/lifetimes/etc.${NC}"
    else
        echo " "
    fi
}

is_v2_up () {
    if cat $file | grep $endpoint | grep -q -i -e "PARENT SA est" -e "IPsec SA established" ; then
        v2lastp1=$(tac $file | grep $endpoint | grep -a -h -m 1 "PARENT SA est" | cut -d "." -f 1 )
        v2p1=$(sudo cat /etc/ipsec.d/*$endpoint*.cft | grep ikelifetime | cut -d "=" -f 2 | sort -u )
        echo -e "${Green}PHASE 1 = YES${NC}, last successful P1 @ $v2lastp1     P1 lifetime = ${bold}$v2p1${normal}"
        string1=$(echo $v2lastp1 | cut -d " " -f 3)
        string2=$(date -u | cut -d " " -f 4)
        StartDate=$(date -u -d "$string1" +"%s")
        FinalDate=$(date -u -d "$string2" +"%s")
        v2p1diff=$( date -u -d "0 $FinalDate sec - $StartDate sec" +"%H:%M:%S")
        v2p1diffsec=$(echo $v2p1diff | awk -F: '{ print ($1 * 3600) + ($2 * 60) + $3 }')
        echo -e "                                           the last phase 1 rekey was $v2p1diffsec seconds ago OR $v2p1diff hrs/mins"
        if cat $file | grep $endpoint | grep -q "IPsec SA established" ; then
            v2lastp2=$(tac $file | grep $endpoint | grep -a -h -m 1 "IPsec SA established" | cut -d "." -f 1 )
            v2p2=$(cat /etc/ipsec.d/*$endpoint*.cft | grep salife | cut -d = -f 2 | sort -u )
            echo -e "${Green}PHASE 2 = YES${NC}, last successful P2 @ ${bold}$v2lastp2${normal}     P2 lifetime = ${bold}$v2p2${normal}"
            string3=$(echo $v2lastp2 | cut -d " " -f 3)
            string4=$(date -u | cut -d " " -f 4)
            StartDate1=$(date -u -d "$string3" +"%s")
            FinalDate1=$(date -u -d "$string4" +"%s")
            v2p2diff=$( date -u -d "0 $FinalDate1 sec - $StartDate1 sec" +"%H:%M:%S")
            v2p2diffsec=$(echo $v2p2diff | awk -F: '{ print ($1 * 3600) + ($2 * 60) + $3 }')
            echo -e "                                           the last phase 2 rekey was $v2p2diffsec seconds ago OR $v2p2diff hrs/mins"
            date2=$(date -u | cut -d " " -f 2-5)
            echo -e  "                  CURRENT UTC TIME: ${BlueHL}$date2${NC}"
        else
            echo "there has never been a phase 2 established"
        fi
    else
        if cat $file | grep $endpoint | grep -q -i "no acceptable response) to our first IKEv2 message"; then
            echo -e "${red}${bold}IKEv1/IKEv2 mismatch, try flipping to IKEv1${normal}${NC}"
            exit 4
        else
            echo -e "${red}The tunnels have never been connected with IKEv2${NC}, please review configuration and security groups"
            echo "the information below mayb be inaccurate since the tunnels have never been connected"
        fi
    fi
}

    #grep for phase 1 and phase 2 established  establied
ikev1_test () {
    if cat $file | grep $endpoint | grep -q -i "ISAKMP SA est" ; then
        lastp1=$(tac $file | grep $endpoint | grep -a -h -m 1 "ISAKMP SA est" | cut -d "." -f 1 )
        v1p1=$(cat /etc/ipsec.d/*$endpoint*.cft | grep ikelifetime | cut -d = -f 2 | sort -u )
        echo -e "${Green}PHASE 1 = YES${NC}, last successful P1 at $lastp1    P1 lifetime = $v1p1"
        string5=$(echo $lastp1 | cut -d " " -f 3)
        string6=$(date -u | cut -d " " -f 4)
        StartDate3=$(date -u -d "$string5" +"%s")
        FinalDate3=$(date -u -d "$string6" +"%s")
        v1p1diff=$( date -u -d "0 $FinalDate3 sec - $StartDate3 sec" +"%H:%M:%S")
        v1p1diffsec=$(echo $v1p1diff | awk -F: '{ print ($1 * 3600) + ($2 * 60) + $3 }')
        echo -e "                                           the last phase 1 rekey was ${bold}$v1p1diffsec${normal} seconds ago OR $v1p1diff hrs/mins"
        if cat $file | grep $endpoint | grep -q "IPsec SA established" ; then
            lastp2=$(tac $file | grep $endpoint | grep -a -h -m 1 "IPsec SA established" | cut -d "." -f 1 )
                v1p2=$(cat /etc/ipsec.d/*$endpoint*.cft | grep salife | cut -d = -f 2 | sort -u )
            echo -e "${Green}PHASE 2 = YES${NC}, last successful P2 at ${bold}$lastp2${normal}    P2 lifetime = $v1p2 "
            string7=$(echo $lastp2 | cut -d " " -f 3)
            string8=$(date -u | cut -d " " -f 4)
            StartDate4=$(date -u -d "$string7" +"%s")
            FinalDate4=$(date -u -d "$string8" +"%s")
            v1p2diff=$( date -u -d "0 $FinalDate4 sec - $StartDate4 sec" +"%H:%M:%S")
            v1p2diffsec=$(echo $v1p2diff | awk -F: '{ print ($1 * 3600) + ($2 * 60) + $3 }')
            echo -e "                                           the last phase 2 rekey was ${bold}$v1p2diffsec${normal} seconds ago OR $v1p2diff hrs/mins"
            date6=$(date -u | cut -d " " -f 2-5)
            echo -e  "                   CURRENT UTC TIME: ${BlueHL}$date6${NC}"
        else
            echo "there has never been a phase 2 established"
        fi
    else
        if cat $file | grep $endpoint | grep -q -i -e i2 -e r2 ; then
#            echo -e "${red}the tunnels have never been connected with the current settings. There are responses from our phase 1 negotiation attempts${NC}"
            echo -e "${red}${bold}REVIEW THE LOGS, DISREGARD THE BOTTOM OUTPUT${normal}${NC}"
            echo "the following is that last 20 lines of the log: "
            cat $file | grep $endpoint | tail -20
        else
        echo -e "${red}weird stuff happening in the logs${NC}, please review configuration and security groups, OR- you typed some shit in wrong"
        echo "the information below mayb be inaccurate since the tunnels have never been stable with the current settings"
        fi
fi
}

# if the peer is negoatiating using IKEv2, this message will come up.
is_peer_ikev2 () {
if cat $file | grep $endpoint | grep -q -i "no suitable connection found with IKEv2" ; then
    echo -e "${yellow}the peer is using IKEv2. try to flip to IKEv2${NC}"
else
    echo " "
fi
}

lastsuccessfulP2=$(tac $file | grep $endpoint |  grep -m 1 -i "ipsec sa est" | cut -d "." -f 1)
lastP2=$(date -d "$lastsuccessfulP2" +%s)

#grep for error messages, print out last error time if relevant
error_message () {
if cat $file | grep $endpoint | grep -q -i "error" ; then
    error_msg=$(tac $file | grep $endpoint | grep -m 1 -i "error")
    lasterror=$(echo $error_msg | cut -d "." -f 1)
    Slasterror=$(date -d "$lasterror" +%s)
    if [[ "$Slasterror" > "$lastP2" ]] ; then
        echo -e "${Green}ERROR messages are present ${NC}, last seen @ ${red}${bold}$lasterror${normal}${NC}"
    else
        echo -e "${Green}error message present ${bold}BEFORE${normal} the last successful phase 2${NC}"
    fi
else
    echo -e "${Green}no error messages in the logs"
fi
}

#shows when the last retransmission was. if its recent, connection is not setup/mismtach/or SG
retran_message () {
if cat $file | grep $endpoint | grep -q -i "retransmission" ; then
    retrans_msg=$(tac $file | grep $endpoint | grep -m 1 -i "retransmission")
    lastRT=$(echo $retrans_msg | cut -d "." -f 1)
    SlastRT=$(date -d "$lastRT" +%s)
    if [[ "$SlastRT" > "$lastP2" ]] ; then
        echo -e "${red}Retransmission messages are present ${NC}, last seen @ ${red}${bold}$lastRT${normal}${NC}"
        echo -e "${yellow} if tunnels are up, you may have to whack a zombie state. try ipsec whack --deletestate <state number>${NC}"
    else
        echo -e "${Green}Retransmission message present ${bold}BEFORE${normal} the last successful phase 2${NC}"
    fi
else
    echo -e "${Green}no Retransmission messages in the logs"
fi
}

#psk mismtach
psk_mismatch () {
if cat $file | grep $endpoint | grep -q -e "mismatch of preshared secrets" -e "Possible authentication failure" ; then
    lastpsk=$(tac $file | grep $endpoint | grep -m 1 -e "mismatch of preshared secrets" -e "Possible authentication failure" | cut -d "." -f 1 )
    Slastpsk=$(date -d "$lastpsk" +%s)
    if [[ "$Slastpsk" > "$lastP2" ]] ; then
        echo -e "${red} PSK mismatch ${NC} "
    exit 5
    else
        echo -e "${Green}PSK mismatch or authentication failure BEFORE the last successful phase 2${NC}, last seen @ ${yellow}${bold}$lastpsk${normal}${NC}"
    fi
else
    echo -e "${Green}there is no a PSK mismatch${NC}"
fi
}

#invalid_cookie  .... this could mean a lot of different thing.
invalid_cookie () {
if cat $file | grep $endpoint | grep -q -i "INVALID_COOKIE" ; then
    cookie=$(tac $file | grep $endpoint | grep -m 1 -i "INVALID_COOKIE" )
    lastcookie=$(echo $cookie | cut -d "." -f 1 )
    Slastcookie=$( date -d "$lastcookie" +%s)
    if [[ "$Slastcookie" > "$lastP2" ]] ; then
        echo -e "${red}INVALID_COOKIE in the logs.${NC} ${yellow}${bold} PSK mismatch, Peer ID, tunnels or CIDR mismatch${normal}${NC}"
        echo -e "${yellow}$cookie ${NC}"
    else
        echo -e "${Green}invalid_cookie messages are present, but BEFORE the last successful phase 2${NC}, last seen @ ${yellow}${bold}$lastcookie${normal}${NC}"
    fi
else
    echo -e "${Green}INVALID_COOKIE messages = NONE${NC}"
fi
}

#grep for invalid_id_infromation
invalid_id_info () {
if cat $file | grep $endpoint | grep -q -i "INVALID_ID_INFORMATION" ; then
    invalid_msg=$(tac $file | grep $endpoint | grep -m 1 -i "INVALID_ID_INFO")
    last_inv_id=$(echo $invalid_msg | cut -d "." -f 1 )
    Slast_invalid=$( date -d "$last_inv_id" +%s)
    if [[ "$Slast_invalid" > "$lastP2" ]] ; then
        echo -e "${red}INVALID_ID messages are currently in the logs${NC} the last message @ ${red}${bold}$last_inv_id${normal}${NC}"
        echo -e "${yellow} if invalid_id is part of p1, chekc peer ID's. If P2 ,  tunnel mismatch and/or NAT-T native mismatch."
        echo -e "$invalid_msg"
    else
        echo -e "${Green}invalid_id_info messages are present ${bold}BEFORE${normal} the last successful phase 2${NC}"
    fi
else
    echo -e "${Green}invalid_id_information messages = NONE${NC}"
fi
}

no_acceptable_response () {
if cat $file | grep $endpoint | grep -i -q "no acceptable response" ; then
    NARmsg=$(tac $file | grep $endpoint | grep -m 1 -i "no acceptable response")
    lastNARtime=$(echo $NARmsg | cut -d "." -f 1 )
    SlastNAR=$(date -d "$lastNARtime" +%s)
    if [[ "$SlastNAR" > "$lastP2" ]] ; then
        echo -e "${red}'no_acceptable_reponse' messages are currently in the logs${NC} the last message @ ${red}${bold}$lastNARtime${normal}${NC}"
        echo " "
    else
        echo -e "${Green}no_acceptable_response messages are present ${bold}BEFORE${normal} the last successful phase 2${NC}"
    fi
else
    echo -e "${Green}no acceptable response messages = NONE${NC}"
fi
}

#invalid SPI
invalid_spi () {
    if cat $file | grep $endpoint | grep -q -i "INVALID_SPI" ; then
    lastinvspi=$(tac $file | grep $endpoint | grep -m 1 -i "INVALID_SPI" | cut -d "." -f 1 )
        echo -e "${red}there are INVALID_SPI messages${NC} in the logs, last message at ${red}$lastinvspi${NC}"
    else
        echo -e "${Green}invalid_spi messages in logs = NONE${NC}"
fi
}

#grep for perhaps
perhaps_message () {
    if cat $file | grep $endpoint | grep -q -i "perhaps" ; then
    perhaps_msg=$(tac $file | grep $endpoint | grep -m 1 "perhaps")
    perhapstime=$(echo $perhaps_msg | cut -d "." -f 1)
    Sperhaps=$( date -d "$perhapstime" +%s)
        if [[ "$Sperhaps" > "$lastP2" ]] ; then
            echo -e "${red}configuration mismatch${bold} check tunnel definitons, CIDRS, PSK, Peer ID, etc.${normal}${NC}"
            echo -e "${yellow} $perhaps_msg ${NC}"
            echo -e "${yellow}${bold} if part of P1:mismatch alg/hash/dh, peer ID. if part of P2: could also be PFS, NAT-T/native mismatch${normal}${NC}"
            exit 7
        else
            echo -e "${Green}'perhaps' messages are present  BEFORE the last successful P2. ${NC} last 'perhaps' message @ ${yellow}$perhapstime ${NC}"
        fi
    else
    echo -e "${Green}'perhaps peer likes no proposal' =  NONE ${NC}"
    fi
}

#grep for no_proposal_chosen
no_proposal_chosen () {
if cat $file | grep $endpoint | grep -q -i "no_proposal_chosen" ; then
    noproposal=$(tac $file | grep $endpoint | grep -m 1 -i "no_proposal_chosen" )
    lastnopro=$(echo $noproposal | cut -d "." -f 1 )
    Slastnopro=$( date -d "$lastnoopro" +%s)
    if [[ "$Slastnopro" > "$lastP2" ]] ; then
        echo -e "${red} NO_PROPOSAL_CHOSEN messages in the logs. ${NC}${yellow}${bold}mismatch algorithm/hash/dh group, CIDR's, PFS, etc. ${normal}${NC}"
        echo -e "${yellow} if part of Phase2, could also be NAT-T/native mismatch${NC}"
    else
        echo -e "${Green} NO_PROPOSAL messages are in the logs BEFORE the last successful phase 2${NC} last seen @ ${yellow}${bold}$lastnopro ${normal}${NC}"
    fi
else
    echo -e "${Green}'NO_PROPOSAL_CHOSEN' messages = NONE${NC}"
fi
}

##run this to see if there is an extranious SA or if there are multiple phase 2 SA's. 
ipsec_auto_status () {
sudo ipsec auto status | grep $endpoint | grep newest | grep "#"
}

#run mtr against the remote endpoint IP, the output will only show lines that dont include "0.0%".  so any packet loss lines from mtr output.
mtr_command () {
remote_ip=$(cat /etc/ipsec.d/cftconn_$endpoint*.cft | grep right= | cut -d "=" -f 2)
echo -e "${yellow} MTR is currently running against the remote endpoint: $remote_ip ${NC}"
mtr $remote_ip  --timeout=10  --report-wide | grep -v 0.0% | grep -v "Start"
}

### this is the actual script now
subnet_propose

if sudo cat /etc/ipsec.d/*$endpoint* | grep -q -i "ikev2=insist" ; then
    ikev2_test
    ikev2_no_pro
    is_v2_up
else
    ikev1_test
fi

is_peer_ikev2
error_message
no_proposal_chosen

psk_mismatch
invalid_cookie
invalid_id_info
echo " "
perhaps_message
retran_message
no_acceptable_response
invalid_spi



echo " "
date6=$(date -u | cut -d " " -f 2-5)
echo -e  "       CURRENT UTC TIME: ${yellow}${bold}$date6${normal}${NC}"

if [[ "$Slasterror" > "$lastP2" ]] ; then
    echo -e "${yellow} last error message at : $error_msg ${NC}"
fi
if [[ "$SlastRT" > "$lastP2" ]] ; then
    echo -e "${yellow}last retransmission msg: $retrans_msg${NC}"
fi
if [[ "$lastNARtime" > "$lastsuccessfulP2" ]] ; then
    echo -e "${yellow} no_acceptable_reponse : $NARmsg${NC}"
fi

echo " "
echo "RAN: ipsec auto status | grep newest | grep "#" for the endpoint you specified"
ipsec_auto_status
echo " "
echo "mtr ran against the remote endpoint, this is the output minus any lines with zero packet loss"
echo " "
mtr_command

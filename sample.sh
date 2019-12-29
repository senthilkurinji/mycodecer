#!/bin/bash

################### Parsing Input In command line And Error Handling ####################

usage() { echo "$0 [-u <Jenkins username>] [-p <Jenkins Password>] [-t <disable or enable>]"; }
while getopts ":u:p:t:h:" o; do
    case "${o}" in
    u) USERNAME=${OPTARG}
        ;;
    p) PASSWORD=${OPTARG}
        ;;
    t) TYPE=${OPTARG} 
        if [[ ! ${OPTARG} = enable ]] && [[ ! ${OPTARG} = disable ]]
        then
            echo "${OPTARG} Is Not valid, Choose < enable or disable >"
            exit 1
            fi
         ;;
    h) usage
        exit
        ;;
    \?) echo "Invalid Option: -${OPTARG}" >&2
        exit 1
        ;;
    :)  echo "Option -${OPTARG} Requires An Argument." >&2
        exit 1
        ;;        
    esac
done

echo "********************* This Script Will $TYPE Synthetic Jobs **********************"
read -p "Are You Sure You Want To Continue? (y/n)" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Terminating The Script"
fi
RESPONSE=()

################### Bindling Input From Command Line And Call Jenkins API To Retrive All The Synthetic Jobs With Status (Enable / Disable)

RESPONSE=$(curl -s --basic --user $USERNAME:$PASSWORD --data tree=jobs[url,color] '')
echo $RESPONSE
if [ ! "$?" = "0" ];
then
    echo "Error In API Response, Due To Wrong Username And Password Or Target Is Unreachable "
    exit 1
else

#################### Iterate The Response From API, Alter Each Line Of Response As Suits For Post Operation And Bind The Type Along

arr=$(echo $RESPONSE | tr "," "\n")
for i in $RESPONSE 
do
line=$(echo "$i" | sed "s/^.\(.*\)/\1/")
# echo ${line%*/*}/$TYPE

# if [ "$TYPE" == "disable" ] && [[ "$line" != *"disabled"* ]];
# then

# ################## Post Request For Disable The Jobs ######################

#     curl -s -X POST --basic --user $USERNAME:$PASSWORD ${line%*/*}/$TYPE
# elif [ "$TYPE" == "enable" ] && [[ "$line" == *"disabled"* ]];
# then 

# ################# Post Request For Enable The Jobs ######################

#     curl -s -X POST --basic --user $USERNAME:$PASSWORD ${line%*/*}/$TYPE
    
# else

# ################# Skip Post Request Since The Jobs Are Already Disabled ####################

#     continue
# fi
done
fi


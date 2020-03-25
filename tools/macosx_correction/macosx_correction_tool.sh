#!/bin/sh
################################################################
# CODEVIEW CONSULTORIA
# MacOSX Correction Tool
#################################################################
# Last update: January, 2015
#################################################################
###########
# VARIABLES
########
# System
#################################################################
PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/X11/bin"
##########
# Baseline
#################################################################
# Please provide all items will be ignored
BASE_IGNORED="17506 27506 37506 47506 7506 17511 27510 27511 37510 37511 47510 47511 7510 7511"
# Please provide default console timeout (Seconds)
BASE_TMOUT="300"
# Please provide machine banner
BASE_BANNER="System access is restricted to authorized users only"
# Please provide the password expiration time (Minutes) -> 43200 == 1month
BASE_MAXAGE="43200"
# Please provide the password minimal lenght
BASE_MIN_LENGHT="8"
# Please provide the password minimal alpha characters
BASE_MIN_ALPHA="6"
# Please provide the password minimal special characters
BASE_MIN_SPECIAL="1"
# Please provide the maximum login attempts
BASE_MAX_LOGIN_ATTEMPTS="10"
# Please provide the password history
BASE_HISTORY="12"
################################################################
# AUX and CONTROL
################################################################
timestamp=`date +%s`

BKP_DIR="/var/security/ProteusBackup/$timestamp"
BKP_FILE="$BKP_DIR/geral.bkp"
mkdir -p $BKP_DIR
rm -f $BKP_FILE
VAR_BKP=""

# Creating aux files
mkdir -p /tmp/$timestamp 2>/dev/null 
dsexport /tmp/$timestamp/users.txt /Local/Default dsRecTypeStandard:Users 2>>/dev/null
USERs=`cat /tmp/$timestamp/users.txt | awk -F: '{ print $3":"$6 }' | egrep "\/(ba|(t)?c|z|k)?sh$" | cut -d: -f1 | egrep -v root 2>/dev/null`

if [ -z "$USERs" ]; then

	USERs=`cat /tmp/$timestamp/users.txt | awk -F: '{ print $3":"$8 }' | egrep "\/(ba|(t)?c|z|k)?sh$" | cut -d: -f1 | egrep -v root 2>/dev/null`

	[ -z "$USERs" ] && {

		echo "[!] FATAL ERROR: Impossible to create a temporary directory!"
		echo "[!] Aborting..."
		exit 1
	}
fi

# detecting the version for validation
darwin_version=`sw_vers | awk ' match($0,/^[ \t]*ProductVersion/) { print $2 } ' | cut -d. -f1`
darwin_subversion=`sw_vers | awk ' match($0,/^[ \t]*ProductVersion/) { print $2 } ' | cut -d. -f2`

if [ "$darwin_version" = 10 ]; then
	if [ "$darwin_subversion" -lt 5 ]; then
		echo "[!] FATAL ERROR: This version is not supported!"
		echo "[!] Aborting..."
		exit 1
	fi
else
	echo "[!] FATAL ERROR: This version is not supported!"
	echo "[!] Aborting..."
	exit 1
fi

# detecting the codename
case "$darwin_subversion" in

	"10") #yosemite
		codename='yosemite'
	;;

	"9") #mavericks
		codename='mavericks'
	;;

	"8") #mountain lion
		codename='mountain_lion'
	;;

	"7") #lion
		codename='lion'
	;;

	"6") #snow leopard
		codename='snow_leopard'
	;;

	"5") #leopard
		codename='leopard'
	;;
esac

# Enhanced echo/echo -n
if [ "X`echo -n`" = "X-n" ]; then
        echo_n() {
                echo ${1+"$@"}"\c"
                return
        }
else
        echo_n() {
                echo -n ${1+"$@"}
                return
        }
fi

#################################################################

###########
# Firewall is not enabled
#########################################################
fw_status() {

	echo_n "[+] Firewall is not enabled  					"
	
	# Backup
	VAR_BKP="$id=`defaults read /Library/Preferences/com.apple.alf globalstate     2>/dev/null`"
	echo $VAR_BKP >> $BKP_FILE

	# Applying
	defaults write /Library/Preferences/com.apple.alf globalstate -int 1 2>/dev/null
	
	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Bluetooth enabled unnecessarely
#########################################################
bluetooth_status() {

	echo_n "[+] Bluetooth enabled unnecessarely				"
	
	# Backup
	VAR_BKP="$id=`defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState      2>/dev/null`"
	echo $VAR_BKP >> $BKP_FILE

	# Applying
	defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0 2>/dev/null
	
	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Bluetooth doesnt have any access restrictions
#########################################################
bluetooth_restrictions() {

        status="x"
        substatus="x"
	cont=0
	user_error=""

        echo_n "[+] Bluetooth doesnt have any access restrictions               "

        for user in ${USERs}; do

		# Backup
                VAR_BKP="$id\_$user=`su - $user -c "defaults -currentHost read com.apple.bluetooth PrefKeyServicesEnabled"      2>/dev/null`"
		echo $VAR_BKP >> $BKP_FILE

		# Applying
                su - $user -c "defaults -currentHost write com.apple.bluetooth PrefKeyServicesEnabled 0" 2>/dev/null

                ########
                # Status
                ##################################
                substatus="$?"

                if [ "$status" != "erro" ]; then
                        if [ "$substatus" != 0 ]; then
                                status="erro"
			else
				cont=1
				user_error="$user_error $user"
                        fi
                fi
                ##################################
        done

        ########
        # Status
        ####################################################
        if [ "$status" != "erro" ]; then
                echo "[      SUCCESS       ]"
        else
		if [ $cont != 0 ]; then
			echo "[      WARNING       ] - Please manually apply to the user(s): $user_error"
		else
                	echo "[       FAILED       ]"
        	fi
	fi
        ####################################################
}
#########################################################

###########
# Wireless (Airport) enabled unnecessarely
#########################################################
wifi_status() {

	echo_n "[+] Wireless (Airport) enabled unnecessarely			"

	# Backup
	VAR_BKP="$id=`networksetup -getairportpower Airport    2>/dev/null`"
	echo $VAR_BKP >> $BKP_FILE

	# Applying
	networksetup -setairportpower Airport off 2>/dev/null >/dev/null
	
	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# IR (Infrared) enabled unnecessarely
#########################################################
infrared_status() {

	echo_n "[+] IR (Infrared) enabled unnecessarely				"

	# Backup
	VAR_BKP="$id=`defaults read /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled      2>/dev/null`"
	echo $VAR_BKP >> $BKP_FILE

	# Applying
	defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool No 2>/dev/null
	
	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# System doesn't request the adminstrator authorization 
# to modify any system configurations
#########################################################
admin_system_prefs() {

	echo_n "[+] System doesn't request the adminstrator authorization [...]	"

	# Backup
	touch /tmp/$timestamp/system.preferences.plist
	security authorizationdb read system.preferences 2>/dev/null > /tmp/$timestamp/system.preferences.plist
	VAR_BKP="$id=`/usr/libexec/PlistBuddy -c "Print :shared" /tmp/$timestamp/system.preferences.plist 2>/dev/null`"
	echo $VAR_BKP >> $BKP_FILE

	# Applying
	/usr/libexec/PlistBuddy -c "Set :shared false" /tmp/$timestamp/system.preferences.plist 2>/dev/null
	security authorizationdb write system.preferences < /tmp/$timestamp/system.preferences.plist 2>/dev/null
	rm -f /tmp/$timestamp/system.preferences.plist 2>/dev/null

	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Secure Virtual Memory is not enabled
#########################################################
swap_restriction() {

	echo_n "[+] Secure Virtual Memory is not enabled			"

	# Backup
	VAR_BKP="$id=`defaults read /Library/Preferences/com.apple.virtualMemory UseEncryptedSwap      2>/dev/null`"
	echo $VAR_BKP >> $BKP_FILE

	# Applying
	defaults write /Library/Preferences/com.apple.virtualMemory UseEncryptedSwap -bool yes 2>/dev/null
	
	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# External disks (flash disks, HD) enabled unnecessarely
#########################################################
external_disks_restriction() {

	echo_n "[+] External disks (flash disks, HD) enabled unnecessarely	"

       # Backup
        if [ -e /System/Library/Extensions/IOUSBMassStorageClass.kext]; then
                FILE="/System/Library/Extensions/IOUSBMassStorageClass.kext"
        else
                if [ -e /System/Library/Extensions/IOUSBMassStorageClass.kext_CODEVIEW_BASELINE]; then
                        FILE="/System/Library/Extensions/IOUSBMassStorageClass.kext_CODEVIEW_BASELINE"
                fi
        fi
        cp $FILE $BKP_DIR/$timestamp_$FILE\_$id

	# Applying
	mv /System/Library/Extensions/IOUSBMassStorageClass.kext /System/Library/Extensions/IOUSBMassStorageClass.kext_CODEVIEW_BASELINE 2>/dev/null
	
	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then

		# Refreshing kernel modules
		touch /System/Library/Extensions 2>/dev/null
		
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Users are being listed on Login window
#########################################################
list_users_loginwindow_status() {

	echo_n "[+] Users are being listed on Login window 			"

        # Backup
        VAR_BKP="$id=`defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME    2>/dev/null`"
        echo $VAR_BKP >> $BKP_FILE

	# Applying
	defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 1 2>/dev/null
	
	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Restriction message is not present in the system
#########################################################
login_message_restriction() {

	echo_n "[+] Restriction message is not present in the system		"

	if [ -z "$BASE_BANNER" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

        # Backup
        VAR_BKP="$id=`defaults read /Library/Preferences/com.apple.loginwindow LoginwindowText 2>/dev/null`"
        echo $VAR_BKP >> $BKP_FILE

	# Applying
	defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "$BASE_BANNER" 2>/dev/null

	########
	# Status
	####################################################
	status="$?"

	if [ "$status" -eq 0 ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Safari is opening downloaded files from the web automatically
#########################################################
auto_open_files_safari() {

	status="x"
	substatus="x"

	echo_n "[+] Safari is opening downloaded files from the web [...]	"

	for user in ${USERs}; do

                # Backup
                VAR_BKP="$id\_$user=`defaults read /Users/$user/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads      2>/dev/null`"
                echo $VAR_BKP >> $BKP_FILE

		# Applying
		su - $user -c "defaults write /Users/$user/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads 0 2>/dev/null"
	
		########
		# Status
		##################################
		substatus="$?"

		if [ "$status" != "erro" ]; then
			if [ "$substatus" != 0 ]; then
				status="erro"
			fi
		fi
		##################################
	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Password minimum size is not set
#########################################################
password_policy_minimum_size_restriction() {

	status="x"
	substatus="x"

	echo_n "[+] Password minimum size is not set				"

	# Checking if variable is set
	if [ -z "$BASE_MIN_LENGHT" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

        # Backup
        VAR_BKP="$id\_global=`pwpolicy -n /Local/Default -getglobalpolicy | egrep -o "minChars=[0-9]+"  2>/dev/null`"
        echo $VAR_BKP >> $BKP_FILE

	# Applying global configuration
	pwpolicy -n /Local/Default -setglobalpolicy "minChars=$BASE_MIN_LENGHT" 1>/dev/null	2>/dev/null
	########
	# Status 
	##################################
	substatus="$?"

	if [ "$substatus" != 0 ]; then
		status="erro"
	fi
	##################################
	
	# Applying for users
	for user in ${USERs}; do

		check_user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "minChars=[0-9]+"  2>/dev/null`

		if [ -n "$check_user" ]; then

			# Backup
                        VAR_BKP="$id\_$user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "minChars=[0-9]+"        2>/dev/null`"
                        echo $VAR_BKP >> $BKP_FILE
 
			# Applying global configuration
			pwpolicy -n /Local/Default -setpolicy -u $user "minChars=$BASE_MIN_LENGHT" 1>/dev/null 2>/dev/null
			########
			# Status
			##################################
			substatus="$?"
	
			if [ "$status" != "erro" ]; then
				if [ "$substatus" != 0 ]; then
					status="erro"
				fi
			fi
			##################################
		fi

	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Maximum time between password changes is not set (age)
#########################################################
password_policy_maximum_time_restriction() {

	status="x"
	substatus="x"

	echo_n "[+] Maximum time between password changes is not set (age)	"

	# Checking if variable is set
	if [ -z "$BASE_MAXAGE" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

        # Backup
        VAR_BKP="$id=`pwpolicy -n /Local/Default -getglobalpolicy | egrep -o "maxMinutesUntilChangePassword=[0-9]+"    2>/dev/null`"
        echo $VAR_BKP >> $BKP_FILE

	# Applying global configuration and protecting root from expiration
	pwpolicy -n /Local/Default -setglobalpolicy "maxMinutesUntilChangePassword=$BASE_MAXAGE" 1>/dev/null 2>/dev/null
	pwpolicy -n /Local/Default -u root -setpolicy "maxMinutesUntilChangePassword=0" 1>/dev/null 2>/dev/null

	########
	# Status
	##################################
	substatus="$?"

	if [ "$substatus" != 0 ]; then
		status="erro"
	fi
	##################################
	
	# Applying for users
	for user in ${USERs}; do

		check_user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "maxMinutesUntilChangePassword=[0-9]+"  2>/dev/null`

		if [ -n "$check_user" ]; then

			# Backup
                        VAR_BKP="$id=`pwpolicy -n /Local/Default -getpolicy -n $user | egrep -o "maxMinutesUntilChangePassword=[0-9]+" 2>/dev/null`"
                        echo $VAR_BKP >> $BKP_FILE

			# Applying global configuration
			pwpolicy -n /Local/Default -setpolicy -u $user "maxMinutesUntilChangePassword=$BASE_MAXAGE" 1>/dev/null 2>/dev/null
			########
			# Status
			##################################
			substatus="$?"
	
			if [ "$status" != "erro" ]; then
				if [ "$substatus" != 0 ]; then
					status="erro"
				fi
			fi
			##################################
		fi

	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Password minimum size for alpha characters is not set
#########################################################
password_policy_alpha_char_restriction() {

	status="x"
	substatus="x"

	echo_n "[+] Password minimum size for alpha characters is not set	"

	# Checking if variable is set
	if [ -z "$BASE_MIN_ALPHA" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

        # Backup
        VAR_BKP="$id=`pwpolicy -n /Local/Default -getglobalpolicy | egrep -o "requiresAlpha=[0-9]+"    2>/dev/null`"
        echo $VAR_BKP >> $BKP_FILE

	# Applying global configuration
	pwpolicy -n /Local/Default -setglobalpolicy "requiresAlpha=$BASE_MIN_ALPHA" 1>/dev/null 2>/dev/null
	########
	# Status
	##################################
	substatus="$?"

	if [ "$substatus" != 0 ]; then
		status="erro"
	fi
	##################################
	
	# Applying for users
	for user in ${USERs}; do

		check_user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "requiresAlpha=[0-9]+"  2>/dev/null`

		if [ -n "$check_user" ]; then

                        # Backup
                        VAR_BKP="$id\_$user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "requiresAlpha=[0-9]+"  2>/dev/null`"
                        echo $VAR_BKP >> $BKP_FILE

			# Applying global configuration
			pwpolicy -n /Local/Default -setpolicy -u $user "requiresAlpha=$BASE_MIN_ALPHA"  1>/dev/null 2>/dev/null
			########
			# Status
			##################################
			substatus="$?"
	
			if [ "$status" != "erro" ]; then
				if [ "$substatus" != 0 ]; then
					status="erro"
				fi
			fi
			##################################
		fi

	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Password minimum size for symbol characters is not set
#########################################################
password_policy_symbol_char_restriction() {

	status="x"
	substatus="x"

	echo_n "[+] Password minimum size for symbol characters is not set	"

	# Checking if variable is set
	if [ -z "$BASE_MIN_SPECIAL" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

        # Backup
        VAR_BKP="$id=`pwpolicy -n /Local/Default -getglobalpolicy | egrep -o "requiresSymbol=[0-9]+"  2>/dev/null`"
        echo $VAR_BKP >> $BKP_FILE

	# Applying global configuration
	pwpolicy -n /Local/Default -setglobalpolicy "requiresSymbol=$BASE_MIN_SPECIAL" 1>/dev/null 2>/dev/null
	########
	# Status
	##################################
	substatus="$?"

	if [ "$substatus" != 0 ]; then
		status="erro"
	fi
	##################################
	
	# Applying for users
	for user in ${USERs}; do

		check_user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "requiresSymbol=[0-9]+"  2>/dev/null`

		if [ -n "$check_user" ]; then

                        # Backup
                        VAR_BKP="$id\_$user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "requiresSymbol=[0-9]+"  2>/dev/null`"
                        echo $VAR_BKP >> $BKP_FILE

			# Applying global configuration
			pwpolicy -n /Local/Default -setpolicy -u $user "requiresSymbol=$BASE_MIN_SPECIAL" 1>/dev/null 2>/dev/null
			########
			# Status
			##################################
			substatus="$?"
	
			if [ "$status" != "erro" ]; then
				if [ "$substatus" != 0 ]; then
					status="erro"
				fi
			fi
			##################################
		fi

	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Account lockout after failed attempts is not set
#########################################################
password_policy_max_login_attempts_restriction() {

	status="x"
	substatus="x"

	echo_n "[+] Account lockout after failed attempts is not set		"

	# Checking if variable is set
	if [ -z "$BASE_MAX_LOGIN_ATTEMPTS" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

        # Backup
        VAR_BKP="$id=`pwpolicy -n /Local/Default -getglobalpolicy | egrep -o "maxFailedLoginAttempts=[0-9]+"  2>/dev/null`"
        echo $VAR_BKP >> $BKP_FILE

	# Applying global configuration
	pwpolicy -n /Local/Default -setglobalpolicy "maxFailedLoginAttempts=$BASE_MAX_LOGIN_ATTEMPTS" 1>/dev/null 2>/dev/null
	########
	# Status
	##################################
	substatus="$?"

	if [ "$substatus" != 0 ]; then
		status="erro"
	fi
	##################################
	
	# Applying for users
	for user in ${USERs}; do

		check_user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "maxFailedLoginAttempts=[0-9]+"  2>/dev/null`

		if [ -n "$check_user" ]; then

                        # Backup
                        VAR_BKP="$id\_$user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "maxFailedLoginAttempts=[0-9]+"  2>/dev/null`"
                        echo $VAR_BKP >> $BKP_FILE

			# Applying global configuration
			pwpolicy -n /Local/Default -setpolicy -u $user "maxFailedLoginAttempts=$BASE_MAX_LOGIN_ATTEMPTS" 1>/dev/null 2>/dev/null
			########
			# Status
			##################################
			substatus="$?"
	
			if [ "$status" != "erro" ]; then
				if [ "$substatus" != 0 ]; then
					status="erro"
				fi
			fi
			##################################
		fi

	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Password history is not set
#########################################################
password_policy_history_size_restriction() {

	status="x"
	substatus="x"

	echo_n "[+] Password history is not set					"

	# Checking if variable is set
	if [ -z "$BASE_HISTORY" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

        # Backup
        VAR_BKP="$id=`pwpolicy -n /Local/Default -getglobalpolicy | egrep -o "usingHistory=[0-9]+"  2>/dev/null`"
        echo $VAR_BKP >> $BKP_FILE

	# Applying global configuration
	pwpolicy -n /Local/Default -setglobalpolicy "usingHistory=$BASE_HISTORY" 1>/dev/null 2>/dev/null
	########
	# Status
	##################################
	substatus="$?"

	if [ "$substatus" != 0 ]; then
		status="erro"
	fi
	##################################
	
	# Applying for users
	for user in ${USERs}; do

		check_user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "usingHistory=[0-9]+" 1>/dev/null 2>/dev/null`

		if [ -n "$check_user" ]; then

                        # Backup
                        VAR_BKP="$id\_$user=`pwpolicy -n /Local/Default -getpolicy -u $user | egrep -o "usingHistory=[0-9]+"  2>/dev/null`"
                        echo $VAR_BKP >> $BKP_FILE

			# Applying global configuration
			pwpolicy -n /Local/Default -setpolicy -u $user "usingHistory=$BASE_HISTORY" 1>/dev/null 2>/dev/null
			########
			# Status
			##################################
			substatus="$?"
	
			if [ "$status" != "erro" ]; then
				if [ "$substatus" != 0 ]; then
					status="erro"
				fi
			fi
			##################################
		fi

	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Motd and Issue files are not set
#########################################################
motd_restriction() {

	file="x"
	files="/etc/motd /etc/issue /etc/issue.net"
	status="x"
	substatus="x"

	echo_n "[+] Motd and Issue files are not set				"

	# Checking if variable is set
	if [ -z "$BASE_BANNER" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

        # Backup
        VAR_BKP="$id="
        echo $VAR_BKP >> $BKP_FILE
        cp /etc/motd $BKP_DIR/motd.bkp  2>/dev/null
        cp /etc/issue $BKP_DIR/issue.bkp        2>/dev/null
        cp /etc/issue.net $BKP_DIR/issue.net.bkp        2>/dev/null

	# Applying
	for file in ${files}; do

		echo "$BASE_BANNER" > $file 2>/dev/null
		echo "" >> $file 2>/dev/null
	
		########
		# Status
		##################################
		substatus="$?"

		if [ "$status" != "erro" ]; then
			if [ "$substatus" != 0 ]; then
				status="erro"
			fi
		fi
		##################################
	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		echo "[       FAILED       ]"
	fi
	####################################################
}
#########################################################

###########
# Timeout for idle sessions is not enabled (graphical/screensaver)
#########################################################
idle_sessions_timeout_restriction() {

	status="x"
	substatus="x"
	cont=0
	user_error=""

	echo_n "[+] Timeout for idle sessions is not enabled (ScreenSaver)	"

	# Checking if variable is set
	if [ -z "$BASE_TMOUT" ]; then
		echo "[ VARIABLE IS MISSED ]"
		return
	fi

	for user in ${USERs}; do

                # Backup
                VAR_BKP="$id\_iddleTime_$user=`su - $user -c "defaults -currentHost read com.apple.screensaver idleTime  2>/dev/null"`"
                echo $VAR_BKP >> $BKP_FILE
                VAR_BKP="$id\_askForPassword\_$user=`su - $user -c "defaults -currentHost read com.apple.screensaver askForPassword  2>/dev/null"`"
                echo $VAR_BKP >> $BKP_FILE

		# Applying
		su - $user -c "defaults -currentHost write com.apple.screensaver idleTime -int $BASE_TMOUT 2>/dev/null"
		########
		# Status
		##################################
		substatus="$?"

		if [ "$status" != "erro" ]; then
			if [ "$substatus" != 0 ]; then
				status="erro"
			else
				cont=1
				user_error="$user_error $user"
			fi
		fi
		##################################

		su - $user -c "defaults -currentHost write com.apple.screensaver askForPassword -int 1 2>/dev/null"
		########
		# Status
		##################################
		substatus="$?"

		if [ "$status" != "erro" ]; then
			if [ "$substatus" != 0 ]; then
				status="erro"
			else
				cont=1
			fi
		fi
		##################################
	done

	########
	# Status
	####################################################
	if [ "$status" != "erro" ]; then
		echo "[      SUCCESS       ]"
	else
		if [ $cont != 0 ]; then
			echo "[      WARNING       ] - Please manually apply to the user(s): $user_error"
		else
			echo "[       FAILED       ]"
		fi
	fi
	####################################################
}
#########################################################

#######################
# Running all functions
#########################################################

#leopard / snow_leopard
apply_7501() { fw_status; };
apply_7503() { bluetooth_status; };
apply_7504() { bluetooth_restrictions; };
apply_7505() { admin_system_prefs; };
apply_7506() { wifi_status; };
apply_7507() { infrared_status; };
apply_7508() { swap_restriction; };
apply_7509() { auto_open_files_safari; };
apply_7510() { external_disks_restriction; };
apply_7511() { password_policy_maximum_time_restriction; };
apply_7512() { password_policy_minimum_size_restriction; };
apply_7513() { password_policy_alpha_char_restriction; };
apply_7514() { password_policy_symbol_char_restriction; };
apply_7515() { password_policy_max_login_attempts_restriction; };
apply_7516() { password_policy_history_size_restriction; };
apply_7518() { list_users_loginwindow_status; };
apply_7519() { login_message_restriction; };
apply_7520() { motd_restriction; };
apply_7521() { idle_sessions_timeout_restriction; };

#lion
apply_27501() { fw_status; };
apply_27503() { bluetooth_status; };
apply_27504() { bluetooth_restrictions; };
apply_27505() { admin_system_prefs; };
apply_27506() { wifi_status; };
apply_27507() { infrared_status; };
apply_27508() { swap_restriction; };
apply_27509() { auto_open_files_safari; };
apply_27510() { external_disks_restriction; };
apply_27511() { password_policy_maximum_time_restriction; };
apply_27512() { password_policy_minimum_size_restriction; };
apply_27513() { password_policy_alpha_char_restriction; };
apply_27514() { password_policy_symbol_char_restriction; };
apply_27515() { password_policy_max_login_attempts_restriction; };
apply_27516() { password_policy_history_size_restriction; };
apply_27518() { list_users_loginwindow_status; };
apply_27519() { login_message_restriction; };
apply_27520() { motd_restriction; };
apply_27521() { idle_sessions_timeout_restriction; };

#mountain_lion
apply_17501() { fw_status; };
apply_17503() { bluetooth_status; };
apply_17504() { bluetooth_restrictions; };
apply_17505() { admin_system_prefs; };
apply_17506() { wifi_status; };
apply_17507() { infrared_status; };
apply_17508() { swap_restriction; };
apply_17509() { auto_open_files_safari; };
apply_17510() { external_disks_restriction; };
apply_17511() { password_policy_maximum_time_restriction; };
apply_17512() { password_policy_minimum_size_restriction; };
apply_17513() { password_policy_alpha_char_restriction; };
apply_17514() { password_policy_symbol_char_restriction; };
apply_17515() { password_policy_max_login_attempts_restriction; };
apply_17516() { password_policy_history_size_restriction; };
apply_17518() { list_users_loginwindow_status; };
apply_17519() { login_message_restriction; };
apply_17520() { motd_restriction; };
apply_17521() { idle_sessions_timeout_restriction; };

#mavericks
apply_37501() { fw_status; };
apply_37503() { bluetooth_status; };
apply_37504() { bluetooth_restrictions; };
apply_37505() { admin_system_prefs; };
apply_37506() { wifi_status; };
apply_37507() { infrared_status; };
apply_37508() { swap_restriction; };
apply_37509() { auto_open_files_safari; };
apply_37510() { external_disks_restriction; };
apply_37511() { password_policy_maximum_time_restriction; };
apply_37512() { password_policy_minimum_size_restriction; };
apply_37513() { password_policy_alpha_char_restriction; };
apply_37514() { password_policy_symbol_char_restriction; };
apply_37515() { password_policy_max_login_attempts_restriction; };
apply_37516() { password_policy_history_size_restriction; };
apply_37518() { list_users_loginwindow_status; };
apply_37519() { login_message_restriction; };
apply_37520() { motd_restriction; };
apply_37521() { idle_sessions_timeout_restriction; };

#yosemite
apply_47501() { fw_status; };
apply_47503() { bluetooth_status; };
apply_47505() { admin_system_prefs; };
apply_47506() { wifi_status; };
apply_47507() { infrared_status; };
apply_47508() { swap_restriction; };
apply_47509() { auto_open_files_safari; };
apply_47510() { external_disks_restriction; };
apply_47511() { password_policy_maximum_time_restriction; };
apply_47512() { password_policy_minimum_size_restriction; };
apply_47513() { password_policy_alpha_char_restriction; };
apply_47514() { password_policy_symbol_char_restriction; };
apply_47515() { password_policy_max_login_attempts_restriction; };
apply_47516() { password_policy_history_size_restriction; };
apply_47518() { list_users_loginwindow_status; };
apply_47519() { login_message_restriction; };
apply_47520() { motd_restriction; };
apply_47521() { idle_sessions_timeout_restriction; };


[ "$codename" == 'leopard' ] && FUNCTION_IDS="7501 7503 7504 7505 7506 7507 7508 7509 7510 7511 7512 7513 7514 7515 7516 7518 7519 7520 7521"
[ "$codename" == 'snow_leopard' ] && FUNCTION_IDS="7501 7503 7504 7505 7506 7507 7508 7509 7510 7511 7512 7513 7514 7515 7516 7518 7519 7520 7521"
[ "$codename" == 'lion' ] && FUNCTION_IDS="27501 27503 27504 27505 27506 27507 27508 27509 27510 27511 27512 27513 27514 27515 27516 27518 27519 27520 27521"
[ "$codename" == 'mountain_lion' ] && FUNCTION_IDS="17501 17503 17504 17505 17506 17507 17508 17509 17510 17511 17512 17513 17514 17515 17516 17518 17519 17520 17521"
[ "$codename" == 'mavericks' ] && FUNCTION_IDS="37501 37503 37504 37505 37506 37507 37508 37509 37510 37511 37512 37513 37514 37515 37516 37518 37519 37520 37521"
[ "$codename" == 'yosemite' ] && FUNCTION_IDS="47501 47503 47505 47506 47507 47508 47509 47510 47511 47512 47513 47514 47515 47516 47518 47519 47520 47521"

#########################################################
for id in $FUNCTION_IDS; do
	for ign in ${BASE_IGNORED}; do
		[ "$id" = "$ign" ] && continue 2;
	done
	CHECK_IDS="$CHECK_IDS $id"
done

for id in ${CHECK_IDS}; do

	eval "apply_$id" 2>/dev/null
done
#########################################################

########################################
# Deleting temporary files and directory
#########################################################
rm -rf /tmp/$timestamp 2>/dev/null 
#########################################################

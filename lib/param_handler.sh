#Parameters Handler

verbosity="0"
interactive="yes"
interactiveRestore="yes"
default_backup_dir="/var/security/backup/"
rollback_mode="off"
allowed_domains_os="AIX FreeBSD HP-UX Linux SunOS"
allowed_domains_services="Apache Lighttpd Postfix Resin Samba Sendmail SSH"
allowed_domains=`echo "$allowed_domains_os" "$allowed_domains_services" | tr " " "\n" | sort -u | tr "\n" " "`
started_with_options="0"

while [ "$#" -gt "0" ]; do

	started_with_options="1"	
	case "$1" in

    		#shows all correction items
		# --list_items <tech_name>
    		--list-items)

      			shift
      			value=`echo "$1" | grep "^[^-]"`

      			if [ -n "$value" ]; then
        
				tech_name="$value"
        			shift
      			else
        		
				echo "[*] ERROR: Name of technology (--list-items option) can't be blank. "
				echo
        			echo "exiting..."
				echo
        			exit 1
      			fi

      			desc_file=$APP_PATH/desc/$tech_name

      			if [ -s $desc_file ]; then

				echo
        			echo "[*] Vulnerability items for $tech_name:" 
				echo
        			echo "$item" | sed -n 's/^NAME_\([0-9]\{1,\}\)=\"\(.\{1,\}\)\"$/  \1 - \2/p' $desc_file 
				echo
      			else

				echo
        			echo "[*] ERROR: This Operating System or Service is not valid! "
				echo " List of valid technologies: $allowed_domains"
				echo
				echo "[*]  USAGE: "
				echo " sh unix_corrections.sh --list-items <tech_name> "
        			echo "exiting..."
				echo
        			exit 1
      			fi  

      			exit 0
      		;;


    		#shows all available backups
		# --list-backups
    		--list-backups)
      
			shift

      			backup_sessions=`ls $default_backup_dir 2>/dev/null`

      			if [ -d "$default_backup_dir" -a -n "$backup_sessions" ]; then

				echo
        			echo "[*] List of available backups:"
				echo
				echo "$backup_sessions"
				echo

      			else

				echo
        			echo "[*] ERROR: No backup available on this System"
				echo
        			exit 1
      			fi  

      			exit 0
      		;;


    		#session to restore (rollback)
		# --backup-to-restore <backup_session>
   	 	--backup-to-restore)
      
			shift
      			value=`echo "$1" | grep "^[^-]"`

      			if [ -n "$value" ]; then
        			
				SESSION="$default_backup_dir/$value"
				START="$value"
	
				[ ! -d "$SESSION" ] && {

					echo
	        			echo "[*] ERROR: Backup session to be restored does'nt exist or is not valid."
					echo
	        			echo "exiting..."
					echo
	        			exit 1
				}

				rollback_mode="on"
        			shift
      			else
				echo
        			echo "[*] ERROR: Backup session to be restored can't be blank."
				echo
        			echo "exiting..."
				echo
        			exit 1
      			fi
      		;;

    
		#ignore list
		# -I "8888,9999,7777"
    		-I)
      	
			shift
      			value=`echo "$1" | grep "^[^-]"`

      			if [ -n "$value" ]; then
        		
				BASELINE_IGNORE_ID_LIST="$value"
        			shift
      			else
        	
				echo "[*] ERROR: List of IDs to be ignored (-I option) can't be blank."
				echo
        			echo "exiting..."
        			exit 1
      			fi
      		;;


    		#list of available baselines
		# -l
    		-l)

			shift
			value="$1"

			if [ -n "$value" ]; then

				echo
        			echo "[*] ERROR: This option does not need of any parameter!"
				echo
				echo "[*]  USAGE: "
				echo " sh unix_corrections.sh -l "
        			echo "exiting..."
				echo
        			exit 1
			else

				last_domain=""
				baselines=`find $APP_PATH/baselines/ -type f | sed -n "s:.\{1,\}baselines/\(.\{1,\}\):\1:p" | sort`
				echo "[*] Available Technologies and Baselines:"
				echo "  [*] Operating Systems "

		
				#for os'
				allowed_domains_os=`uname -s`
				for b in ${baselines}; do

					domain=`dirname $b`

					found=1
					for d in ${allowed_domains_os}; do

						[ "$d" = "$domain" ] && found=0
					done

					[ $found -eq 1 ] && continue

					baseline_name=`sed -n "s/BASE_NAME=\"\(.*\)\"/\1/p" $APP_PATH/baselines/${b}`
					if [ "$domain" != "$last_domain" ]; then

						echo "      * $domain"
						last_domain=$domain
					fi

					echo "          * \"$baseline_name\""
				done

				echo
				echo "  [*] Services "
	
				#for services
				for b in ${baselines}; do

					domain=`dirname $b`

					found=1
					for d in ${allowed_domains_services}; do

						[ "$d" = "$domain" ] && found=0
					done

					[ $found -eq 1 ] && continue

					baseline_name=`sed -n "s/BASE_NAME=\"\(.*\)\"/\1/p" $APP_PATH/baselines/${b}`
					if [ "$domain" != "$last_domain" ]; then

						echo "      * $domain"
						last_domain=$domain
					fi

					echo "          * \"$baseline_name\""
				done

			fi
			unset value domain baselines last_domain baseline_name baseline_file

			echo
			exit 0
		;;


		# specify which technology is going to be corrected
		# --tech <tech_name>
		--tech)

			shift
			allowed_domain_os=`uname -s`
			allowed_domains=`echo "$allowed_domain_os" "$allowed_domains_services"`

			value=`echo "$1" | grep "^[-]"`
			[ -n "$value" ] && {

				echo "[*] ERROR: This option must be used with the correct technology!"
				echo 
				echo "[*] USAGE: "
				echo " sh unix_corrections.sh --tech <tech_name> -b \"Baseline of this Technology\" --target-path /etc/path/of/conf.txt "
				echo "exiting..."
				echo
				exit 1

			}

			value="$1"
			if [ -n "$value" ]; then

				temp_checking=`echo "$allowed_domains" | tr " " "\n" | egrep "^$value$"`
				if [ -n "$temp_checking" ]; then

					shift
					NO_INTERACTIVE_TECH_NAME="$value"

				else

					echo "[*] ERROR: Technology not available!"
					echo 
					echo " List of available technologies: $allowed_domains"
					echo "exiting..."
					echo 
					exit 1
				fi

			else
			
				echo "[*] ERROR: This option must be used with the correct technology!"
				echo 
				echo "[*] USAGE: "
				echo " sh unix_corrections.sh --tech <tech_name> -b \"Baseline of this Technology\" --target-path /etc/path/of/file.conf "
				echo "exiting..."
				echo
				exit 1

			fi
			unset value temp_checking
		;;


		# specify which configuration file is going to be corrected
		# --target-path <configuration_file>
		--target-path)

			shift
			value=`echo "$1" | grep "^[-]"`
			[ -n "$value" ] && {

				echo "[*] ERROR: This option must be used with a configuration file! "
				echo 
				echo "[*] USAGE: "
				echo " sh unix_corrections.sh --tech <tech_name> -b \"Baseline of this Technology\" --target-path /etc/path/of/file.conf "
				echo "exiting..."
				echo
				exit 1

			}

			value="$1"
			if [ -n "$value" ]; then

				shift
				NO_INTERACTIVE_TARGET_PATH="$value"
			else
			
				echo "[*] ERROR: This option must be used with a valid configuration file!"
				echo 
				echo "[*] USAGE: "
				echo " sh unix_corrections.sh --tech <tech_name> -b \"Baseline of this Technology\" --target-path /etc/path/of/file.conf "
				echo "exiting..."
				echo
				exit 1

			fi
			unset value 
		;;


    		#baseline
		# -b "Whatever baseline here"
    		-b)
      
			shift
      			value=`echo "$1" | grep "^[^-]"`

      			if [ -n "$value" ]; then
        
				shift
				NO_INTERACTIVE_BASELINE_NAME="$value"

            		else
        	
				echo "[*] ERROR: Baseline parameter value can't be blank."
				echo
        			echo "exiting..."
				echo
        			exit 1
      			fi

      			unset value base_file
      		;;


    		#checklist item risk
		# --risk <risk>
		# --risk "low"
    		--risk|-c)
      
			shift
      			value=`echo "$1" | grep "^[^-]" | tr "[[:upper:]]" "[[:lower:]]"`

      			if [ -n "$value" ]; then
        
				for risk in ${value}; do
          			
					[ "$risk" != "low" ] && [ "$risk" != "medium" ] && \
          				[ "$risk" != "high" ] && [ "$risk" != "critical" ] && {
            
						echo "[*] ERROR: Checklist item risk parameter must have its value as \"low\", \"medium\", \"high\" or \"critical\"."
						echo
            					echo "exiting..."
            					exit 1
          				}
        			done

        			RISK_LEVEL_FILTER="$value"
        			shift
      			else
        
				echo "[*] ERROR: Checklist item risk parameter (--risk) cannot be used with its value as blank."
				echo
        			echo "exiting..."
        			exit 1
      			fi
      
			unset value
      		;;

    
		#checklists id
		# -i "8888,9999,7777"
    		-i)
      
			shift
      			value=`echo "$1" | grep "^[^-]"`

      			if [ -n "$value" ]; then
        		
				#FIXME - need to check if the given list is comma or \n separated
        			BASELINE_ID_LIST_FILTER="$value"
        			shift
      			else
        
				echo "[*] ERROR: Checklist ids parameter (-i) cannot be used with its value as blank."
				echo
        			echo "exiting..."
        			exit 1
      			fi

      			unset value
      		;;  

    
		#interactivity
		# -y no
    		-y) 
      
			shift
      			value=`echo "$1" | grep "^[^-]"`

      			if [ -n "$value" ]; then
        			
				[ "$value" != "yes" ] && [ "$value" != "no" ] && {
          
					echo "[*] ERROR: Interactive parameter (-y) must have its value as \"yes\", \"no\" or blank."
					echo
          				echo "exiting..."
          				exit 1
        			}
        
				interactive="$value"
        			shift
      			else
        
				interactive="no"
      			fi

      			unset value
      		;;  

		# -h
    		-h|--help)
      
			shift
      			value="$1"

      			[ -n "$value" ] && {
       
				echo "[*] Help option (-h) does not need to have any parameters! " 
				echo "[*] Ignoring them..."
				echo
      			}

			echo
      			echo "[*] OPTIONS: "
			echo "   -l 				 	: List all available baselines;"
			echo "   --list-items <tech> 		 	: List all available items for such technology;"
			echo "   --list-backups 		 	: List all available backup sessions to be restored;"
			echo "   --backup-to-restore \"session\" 	: Load the session you are going to restore on the system;" 
			echo "   -b \"Baseline Description\" 	 	: Load the baseline you are going to use for deployment;"
			echo "   -i \"id1,id2,idN\" 		 	: Load only items you are going to apply on the system;"
			echo "   -I \"id1,id2,idN\" 		  	: Load all available items, except items you are NOT going to apply on the system;"
			echo "   --risk <low|medium|high|critical>   	: Load only items you are going to apply on the system, according to the risk;"
			echo "   -y <yes|no>	 		 	: Apply items with interactivity or without;"
			echo

			echo "[*] EXAMPLES: "
			echo " sh unix_corrections.sh -l"
			echo
			echo " sh unix_corrections.sh --list-backups"
			echo
			echo " sh unix_corrections.sh --backup-to-restore \"15042013-13:10:42\""
			echo
			echo " sh unix_corrections.sh --tech Linux -b \"RedHat - Default\" -y yes"
			echo
			echo " sh unix_corrections.sh --tech Apache -b \"Apache WebServer - Default\" --target-path /etc/httpd/conf/httpd.conf -y no"
			echo
			echo " sh unix_corrections.sh --tech SSH -b \"OpenSSH  - Testing\" --target-path /etc/ssh/sshd_config -i \"6102,6105\" -y no"
			echo
			echo " sh unix_corrections.sh --tech Sendmail -b \"Sendmail - Production\" --target-path /etc/mail/sendmail.cf --risk \"medium\" -y no"
			echo

			echo
			exit 0
      		;;

    		*|-*)  
      
			echo "[*] ERROR: This option ($1) is not valid!"
			echo "[*] For more information on correct use of this tool, try the following: "
			echo " sh unix_corrections.sh --help "
			echo
			exit 1
      		;;  
  	esac

done

baseline_option_validation() {

	value="$1"
	temp_tech="$2"

	#check_baseline_files
       	[ "$?" -eq "1" ] && exit 1


	[ -z "$temp_tech" ] && {


		echo "[*] ERROR: This option must be used with the correct technology!"
		echo 
		echo "[*] USAGE: "
		echo " sh unix_corrections.sh --tech <tech_name> -b \"Baseline of this Technology\" --target-path /etc/path/of/file.conf "
		echo "exiting..."
		echo
		exit 1
	}

       	grep_path=`which grep`
       	grep_params="-x"

       	case $OS in
       
		"SunOS")
       			grep_path="/usr/xpg4/bin/grep"
			grep_params="${grep_params} -l"
       		;;

     		"Linux" | "FreeBSD")
         	
			grep_params="${grep_params} -H"
       		;;

       		"HP-UX")
       
			grep_params="${grep_params} -l"
       		;;

      		"AIX")

			grep_params="${grep_params} -l"
       		;;
       	esac

  	printf "%s" "[*] Looking for baseline..."
       	query="BASE_NAME=\\\"$value\\\""

       	base_file=`find baselines/${temp_tech} -type f | xargs ${grep_path} ${grep_params} "$query" | awk -F: '{print $1}' | head -n1`
      	[ ! -f "$base_file" ] && {
       
		echo
       		echo "  [*] ERROR: Baseline does not exists."
       		echo "exiting..."
		echo
       		exit 1
       	}

     	echo " found."

       	baseline="$APP_PATH/${base_file}"
       	baseline_file="$baseline"
       	baseline_name="$value"

      	unset value base_file
}

target_path_option_validation () {

	temp_tech="$1"
	case "$temp_tech" in

		"Apache" | "Lighttpd" | "Postfix" | "Resin" | "Samba" | "Sendmail" | "SSH" )

			TECH_TYPE="SERVICE"
			if [ -z "$NO_INTERACTIVE_TARGET_PATH" ]; then

				echo "[*] ERROR: For this technology ($temp_tech) you must specify a valid configuration file!"
				echo 
				echo "[*] USAGE: "
				echo " sh unix_corrections.sh --tech $temp_tech -b \"Baseline of this Technology\" --target-path /etc/path/of/file.conf "
				echo "exiting..."
				echo
				exit 1

			else

				case "$temp_tech" in

					"Lighttpd" | "Postfix" | "Resin" )

						[ ! -d "$NO_INTERACTIVE_TARGET_PATH" ] && {

							echo "[*] ERROR: Configuration dir not found!"
							echo 
							echo "exiting..."
							echo 
							exit 1
						}
					;;

					*)
						[ ! -f "$NO_INTERACTIVE_TARGET_PATH" ] && {

							echo "[*] ERROR: Configuration file not found!"
							echo 
							echo "exiting..."
							echo 
							exit 1
						}
					;;

				esac
			fi
		;;

		*)
			[ -n "$NO_INTERACTIVE_TARGET_PATH" ] && {
			
				echo "[*] WARNING: --target-path option is not necessary for this technology!"
				echo "ignoring..."
				unset NO_INTERACTIVE_TARGET_PATH
			}
		;;
	esac
}

#run these functions only with options via command line
[ "$started_with_options" -eq "1" ] && [ "$rollback_mode" = "off" ] && {

	baseline_option_validation "$NO_INTERACTIVE_BASELINE_NAME" "$NO_INTERACTIVE_TECH_NAME"
	target_path_option_validation "$NO_INTERACTIVE_TECH_NAME"
}

[ -z "$TECH_TYPE" ] && TECH_TYPE="OS"

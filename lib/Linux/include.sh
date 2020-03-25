#===============================================================================
#===============================================================================

SNMP_DEFAULT_SEC_NAME="notConfigUser"

#===  FUNCTION  ================================================================
#          NAME:  fix_irrestrict_su
#   DESCRIPTION:  
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure
#===============================================================================

fix_irrestrict_su () {


  [ -z "$LINUX_DISTRO_TOKEN" ] && {
    echo "    Can not recognize Linux distro." 2>> "$LOGF"
    [ $verbosity ] && echo "    Can not recognize Linux distro."
    return $CODE_ERROR
  }

  #Specific distro functions are found on specific distro scripts on CD/lib/Linux/$SO
  #and it is sourced by CD/lib/Linux/Linux
  case $LINUX_DISTRO_TOKEN in

    'debian')

      fix_irrestrict_su_debian

      return $?

      ;;

    'suse')

      fix_irrestrict_su_suse

      return $?

      ;;

    'fedora')

      fix_irrestrict_su_fedora

      return $?

      ;;

    'redhat')

      fix_irrestrict_su_redhat

      return $?

      ;;

    'slackware')


      fix_irrestrict_su_slackware

      return $? #FIXME

      ;;


    *)
      #OS not supported
      echo "Can not recognize Linux distro, skipping..." >> "$LOGF"
      [ $verbosity ] && echo "Can not recognize Linux distro, skipping..."
      return $CODE_ERROR
      ;;

  esac    # --- end of case ---

  return $CODE_OK 

}


#===  FUNCTION  ================================================================
#          NAME:  fix_irrestrict_su_common
#   DESCRIPTION:  Fix the irrestric use of 'su' command on Debian, Fedora, Suse
#                 and Redhat.
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure ; 33 = Missed BASE_PRIVGROUP var ;
#                 34 = Missed BASE_SU_USERS var
#===============================================================================

fix_irrestrict_su_common () {

  [ -z "$BASE_PRIVGROUP" ] && {
    MISSED_VAR="BASE_PRIVGROUP"
    return $CODE_MISSED_VAR 
  }

  [ -z "$BASE_SU_USERS" ] && {
    MISSED_VAR="BASE_SU_USERS"
    return $CODE_MISSED_VAR
  }

  privgroup_exists=`cat /etc/group | grep -w $BASE_PRIVGROUP 2>> "$LOGF"`
  su_users=""

  usermod_path=`which usermod 2>> "$LOGF"`
  
  #fedora and redhat workaround
  [ -z "$usermod_path" ] && [ -x "/usr/sbin/usermod" ] && usermod_path="/usr/sbin/usermod"

  [ -z "$usermod_path" ] && return $CODE_ERROR 

  #For each user allowed to run su, check if:
  #It has a valid password.
  #It has a valid shell.
  #It isn't a service user.

  for user in $BASE_SU_USERS; do

    user_su_validation "$user"

    status=$?

    case $status in
      0)
      echo "Valid User: $user allowed to use su" >> "$LOGF"
      [ $verbosity ] && echo "  [*] Valid User: $user allowed to use su"
      su_users="${su_users} $user"
      ;;

      64)
      echo "Invalid User: User $user does not exists." >> "$LOGF"
      [ $verbosity ] && echo "  [*] Invalid User: User $user does not exists."
      ;;

      65)
      echo "Invalid User: User $user hasn't a shell or it's a service user (baseline specification)." >> "$LOGF"
      [ $verbosity ] && echo "  [*] Invalid User: User $user hasn't a shell or it's a service user (baseline specification)."
      ;;

      66)
      echo "Invalid User: Invalid shell associated to this user (${user})." >> "$LOGF"
      [ $verbosity ] && echo "  [*] Invalid User: Invalid shell associated to this user (${user})."
      ;;

      67)
      echo "Invalid User: User $user has an empty password" >> "$LOGF"
      [ $verbosity ] && echo "  [*] Invalid User: User $user has an empty password"
      ;;

    esac    # --- end of case ---

  done

  [ -z "$su_users" ] && {
    echo "No valid users were found. Skipping..." >> "$LOGF"
    [ $verbosity ] && echo "  [*] No valid users were found. Skipping..."
    return 100
  }

  #adding a valid user to BASE_PRIVGROUP
  [ -z "$privgroup_exists" ] && {
    groupadd $BASE_PRIVGROUP 2>> "$LOGF"
    #restore procedure will delete BASE_PRIVGROUP 
    has_privgroup="groupdel $BASE_PRIVGROUP;"
  }


  #adding user to BASE_PRIVGROUP
  for user in $su_users; do
    user_groups=`id -Gn $user | tr " " , 2>> "$LOGF"`

    # if user isn't in group, add it and and create the restore procedure.
    if [ "`echo $user_groups|grep -E "(^|[,])$BASE_PRIVGROUP([,]|\$)"`" = "" ]; then
      usermod -G $user_groups,$BASE_PRIVGROUP $user 2>> "$LOGF"
      #restore procedure (removing user from BASE_PRIVGROUP)
      remove_user_from_group="${remove_user_from_group} tmpfile=\`mktemp /tmp/etc.group.XXXXXX\`; cat /etc/group | sed \"s/^\\(${BASE_PRIVGROUP}:.*:.*:.*\\)\\(,\\)*${user}\\(,\\)*\\(.*\\)/\\1\\4/\" > \$tmpfile; cat \$tmpfile > /etc/group; rm \$tmpfile;"
    fi
  done

  case $LINUX_DISTRO_TOKEN in
    'slackware')

      target_file="/etc/login.defs"

      #updating or adding 'SU_WHEEL_ONLY' to 'SU_WHEEL_ONLY yes' in $target_file

      grep -q "SU_WHEEL_ONLY" $target_file 2>> "$LOGF"
      has_conf=$?

      if [ $has_conf -eq 0 ]; then
        corr=`sed "s/#\{0,\}[ \t]\{0,\}SU_WHEEL_ONLY.\{1,\}/SU_WHEEL_ONLY yes/" $target_file 2>> "$LOGF"`
        printf "%s" "$corr" > $target_file 2>> "$LOGF"
      else
        echo "SU_WHEEL_ONLY yes" >> $target_file 2>> "$LOGF"
      fi

      remove_pam="corr=\`sed \"s/\(SU_WHEEL_ONLY\)[ \t]\{1,\}yes/\1 no/\" $target_file\` ; printf \"%s\" \"\$corr\" > $target_file; unset corr;"

      ;;

    *)

      #FIXME - If there isn't 'auth sufficient pam_rootok.so' configuration inside the file, it cannot be applied.

      target_file="/etc/pam.d/su"
      grep -E "^[[:blank:]]*auth[[:space:]]+required[[:space:]]+(/lib/security/(\\\$ISA/)?)?pam_wheel.so" $target_file > /dev/null 2>> "$LOGF"
      has_conf=$?

      if [ $has_conf -eq 1 ]; then

        #adding 'auth required pam_wheel.so group=$BASE_PRIVGROUP' to $target_file
        tmp_file=`mktemp /tmp/tmp.XXXXXX 2>> "$LOGF"`
        sed "/auth[ \t]\{1,\}sufficient[ \t]\{1,\}pam_rootok.so/a\auth\trequired pam_wheel.so\tgroup=$BASE_PRIVGROUP" $target_file > $tmp_file
        cat $tmp_file > $target_file 2>> "$LOGF"
        rm $tmp_file 2>> "$LOGF"

        #restore procedure for pam configuration
        remove_pam="corr=\`sed \"/auth[ \t]\{1,\}required[ \t]\{1,\}pam_wheel.so[ \t]\{1,\}group=${BASE_PRIVGROUP}/d\" $target_file\`; printf \"%s\" \"\$corr\" > $target_file; unset corr;"

      fi
      ;;

  esac

  [ -z "${has_privgroup}" ] && [ -z "${remove_user_from_group}" ] && [ -z "${remove_pam}" ] && return 22

  backupFile "$target_file" "data" "${has_privgroup} ${remove_user_from_group} ${remove_pam}" 

  return 0

}

#===  FUNCTION  ================================================================
#          NAME:  user_su_validation
#   DESCRIPTION:  Validate if an user can use the 'su' command.
#    PARAMETERS:  $1 = username
#       RETURNS:  0 = valid ; 64 = user not exists ; 65 = invalid users (baseline)
#                 66 = invalid shell (baseline) ; 67 = empty password
#===============================================================================

user_su_validation () {

  [ -z "$1" ] && return $CODE_ERROR 

  username=$1

  user_passwd=`cat /etc/passwd | grep "^${username}:" 2>> "$LOGF"`
  user_shell=`echo $user_passwd | cut -d: -f7` 2>> "$LOGF"

  # user_shell=`cat /etc/passwd | grep "$username" | awk -F: '$7 ~ /[^ ]/ && $7 !~ /false|nologin/ { print $7 }'`

    #Checking if the user exists
  [ -z "$user_passwd" ] && return 64 

  #Looking for username in 'no shell associated' baseline user list
  for noshell in $BASE_NOSHELL; do
    [ "$noshell" = "$username" ] && return 65 
  done

  #Checking if the user shell is a valid shell

  is_valid_shell=1
  for valid_shell in $BASE_SHELLS; do
    [ "$valid_shell" = "$user_shell" ] && {
      is_valid_shell=0
      break
    }
  done

  [ $is_valid_shell -ne 0 ] && return 66 

  #Checking if the user has a non empty password
  has_password=`cat /etc/shadow | grep "^${username}:" | cut -d: -f2 | sed -n "/[^\*\!]/p" 2>> "$LOGF"`

  [ -z "$has_password" ] && [ "$username" != "root" ] && return 67 

  return $CODE_OK 

}

#===  FUNCTION  ================================================================
#          NAME:  fix_login_attempts_check
#   DESCRIPTION:  Check if the system auth file has the right policy for logins
#                 attempts.
#    PARAMETERS:  $1 = system auth filename (i.e.: /etc/pam.d/system-auth)
#                 $2 = deny value
#                 $3 = unlock_time value
#       RETURNS:  71 = policy ok ; 72 = policy not ok ; 1 = failure
#===============================================================================

fix_login_attempts_check () {

  [ $# -lt 3 ] && return $CODE_ERROR

  system_auth=$1
  deny_value=$2
  unlock_time_default=$3
  
  parameters=`sed -n "s/auth[ \t]\{1,\}required[ \t]\{1,\}pam_tally.so[ \t]\{1,\}\(deny=[0-9]\{1,\}\)[ \t]\{1,\}\(unlock_time=[0-9]\{1,\}\)\([ \t]\{1,\}magic_root\)*/\1 \2/p" $system_auth 2>> "$LOGF"`

  deny=`echo ${parameters} | sed -n "s/.*deny=\([0-9]\{1,\}\).*/\1/p" 2>> "$LOGF"`
  unlock_time=`echo ${parameters} | sed -n "s/.*unlock_time=\([0-9]\{1,\}\).*/\1/p" 2>> "$LOGF"`

  [ "$deny" != "$deny_value" ] || [ "$unlock_time" != "$unlock_time_default" ] && return 72

  return 71

}

#===  FUNCTION  ================================================================
#          NAME:  fix_login_attempts 
#   DESCRIPTION:  Restricit the user login attempts and lock login for sixty 
#          seconds after three wrongs attempts.
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure ; 22 = login attempts policy 
#          ok already
#===============================================================================

fix_login_attempts () {

  [ -z "$BASE_PASS_DENY" ] && {
		MISSED_VAR="BASE_PASS_DENY"
		return 33
	}
	
  [ -z "$LINUX_DISTRO_TOKEN" ] && {
    echo "    Can not recognize Linux distro." 2>> "$LOGF"
    [ $verbosity ] && echo "    Can not recognize Linux distro."
    return $CODE_ERROR
  }

  
  deny_default=$BASE_PASS_DENY
  unlock_time_default=$BASE_PASS_UNLOCK

  [ -n "$unlock_time_default" ] && unlock_def="unlock_time=${unlock_time_default}"

  case $LINUX_DISTRO_TOKEN in

		'debian')
  		system_auth="/etc/pam.d/common-auth"
	  	previous_def=`sed -n "/auth[ \t]\{1,\}required[ \t]\{1,\}pam_tally.so[ \t]\{1,\}deny=[0-9]\{1,\}[ \t]\{1,\}\(unlock_time=[0-9]\{1,\}\)\{0,\}/p" $system_auth`
	    before=`sed -n "/auth[ \t]\{1,\}required[ \t]\{1,\}pam_unix.so[ \t]\{1,\}nullok\(_secure\)\{0,1\}/p" $system_auth`
	    #FIXME - Adicionar unlock_time soh se existir o valor no baseline
	    add_rule="auth  required  pam_unix.so  nullok\nauth  required  pam_tally.so  deny=${deny_default}  ${unlock_def}"

      #Command to add the new definition before 'auth required pam_unix.so nullok[_secure]'
      cmd1="sed \"/auth[ \\t]\\{1,\\}required[ \\t]\\{1,\\}pam_unix.so[ \\t]\\{1,\\}nullok\\(_secure\\)\\{0,1\\}/iauth\\trequired\\tpam_tally.so\\tdeny=${deny_default}\\t${unlock_def}\" $system_auth"

      #changing 'auth required pam_unix.so nullok_secure' to 'auth required pam_unix.so nullok' if it exists
      cmd1_extra="tmp_file1=\`mktemp /tmp/temp.XXXXXX\`; cat \$tmp_file | sed \"s/auth[ \\t]\\{1,\\}required[ \\t]\\{1,\\}pam_unix.so[ \\t]\\{1,\\}nullok_secure/auth\\trequired\\tpam_unix.so\\tnullok/\" > \$tmp_file1; cat \$tmp_file1 > \$tmp_file; rm \$tmp_file1"

      #Command to replace old deny= and unlock_time definitions  
      cmd2="sed \"s/auth[ \\t]\\{1,\\}required[ \\t]\\{1,\\}pam_tally.so[ \\t]\\{1,\\}deny=[0-9]\\{1,\\}[ \\t]\\{1,\\}\\(unlock_time=[0-9]\\{1,\\}\\)\\{0,\\}/auth\\trequired\\tpam_tally.so\\tdeny=${deny_default}\\t${unlock_def}/\" $system_auth"

      #changing 'auth required pam_unix.so nullok_secure' to 'auth required pam_unix.so nullok' if it exists
      cmd2_extra=$cmd1_extra

    	;;

    'suse')
  		system_auth="/etc/pam.d/common-auth"
			previous_def=`sed -n "/auth[ \t]\{1,\}required[ \t]\{1,\}pam_tally.so[ \t]\{1,\}deny=[0-9]\{1,\}[ \t]\{1,\}\(unlock_time=[0-9]\{1,\}\)\{0,\}/p" $system_auth`
			before=`sed -n "/auth[ \t]\{1,\}required[ \t]\{1,\}pam_env.so/p" $system_auth`
      #FIXME - Adicionar unlock_time soh se existir o valor no baseline
			add_rule="auth	required	pam_env.so\nauth	required	pam_tally.so	deny=${deny_default}	unlock_time=${unlock_time_default}"

      #Command to add the new definition before 'auth required pam_env.so'
			cmd1="sed \"/auth[ \\t]\\{1,\\}required[ \\t]\\{1,\\}pam_env.so/iauth\\trequired\\tpam_tally.so\\tdeny=${deny_default}\\t${unlock_def}\" $system_auth"

      #Command to replace old deny= and unlock_time definitions  
 		  cmd2="sed \"s/auth[ \\t]\\{1,\\}required[ \\t]\\{1,\\}pam_tally.so[ \\t]\\{1,\\}deny=[0-9]\\{1,\\}[ \\t]\\{1,\\}\\(unlock_time=[0-9]\\{1,\\}\\)\\{0,\\}/auth\\trequired\\tpam_tally.so\\tdeny=${deny_default}\\t${unlock_def}/\" $system_auth"
  
      ;;

    'fedora'|'redhat')
	  	system_auth="/etc/pam.d/system-auth"
	   	previous_def=`sed -n "/auth[ \t]\{1,\}required[ \t]\{1,\}pam_tally.so[ \t]\{1,\}deny=[0-9]\{1,\}[ \t]\{1,\}\(unlock_time=[0-9]\{1,\}\)\{0,\}[ \t]\{1,\}magic_root/p" $system_auth`
	    before=`sed -n "/auth[ \t]\{1,\}required[ \t]\{1,\}pam_env.so/p" $system_auth`
      #FIXME - Adicionar unlock_time soh se existir o valor no baseline
      add_rule="auth  required  pam_env.so\nauth  required  pam_tally.so  deny=${deny_default}  ${unlock_def}  magic_root"

      #Command to add the new definition before 'auth required pam_env.so'
      cmd1="sed \"/auth[ \\t]\\{1,\\}required[ \\t]\\{1,\\}pam_env.so/iauth\\trequired\\tpam_tally.so\\tdeny=${deny_default}\\t${unlock_def}\\tmagic_root\" $system_auth"

      #Command to replace old deny= and unlock_time definitions  
      cmd2="sed \"s/auth[ \\t]\\{1,\\}required[ \\t]\\{1,\\}pam_tally.so[ \\t]\\{1,\\}deny=[0-9]\\{1,\\}[ \\t]\\{1,\\}\(unlock_time=[0-9]\\{1,\\}\)\{0,\\}[ \\t]\\{1,\\}magic_root/auth\\trequired\\tpam_tally.so\\tdeny=${deny_default}\\t${unlock_def}\\tmagic_root/\" $system_auth"

      ;;

    *)
      #OS not supported
      echo "Can not recognize Linux distro, skipping..." >> "$LOGF"
      [ $verbosity ] && echo "Can not recognize Linux distro, skipping..."
      return $CODE_ERROR

      ;;

  esac

  [ ! -f $system_auth ] && return 1

  backupFile "$system_auth" "data"

  if [ -z "$previous_def" ]; then

    # No auth session in the file
    if [ -z "$before" ]; then

      printf "$add_rule" >> $system_auth
  
    else

      tmp_file=`mktemp /tmp/XXXXXX`
      #Command to add the new definition
      eval "$cmd1 > $tmp_file"
 
			[	-n "$cmd1_extra" ] && eval "$cmd1_extra"

      cat $tmp_file > $system_auth

      rm $tmp_file

    fi

  else

    #Considering the existence of 'auth required pam_env.so' inside system-auth

    fix_login_attempts_check "$system_auth" "$deny_default" "$unlock_time_default"

    if [ $? -eq 72 ]; then

      tmp_file=`mktemp /tmp/XXXXXX`

      eval "$cmd2 > $tmp_file"
 
			[	-n "$cmd2_extra" ] && eval "$cmd2_extra"

      cat $tmp_file > $system_auth
      rm $tmp_file

    else

      return $CODE_CONFORMITY 

    fi

  fi

  return $CODE_OK 

}


#===  FUNCTION  ================================================================
#          NAME:  fix_suid_remote_directories
#   DESCRIPTION:  Disable SUID in remote directories defined on /etc/fstab
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure
#===============================================================================

fix_suid_remote_directories () {

        fstab_conf="/etc/fstab"
        [ -f "$fstab_conf" ] || return ${CODE_MISSED_FILE}

        vulnerable=`awk '{ if ( $1 !~ /^[ \t]*#/ && $3 == /nfs/ && $4 !~ /nosuid/ ) { print } }' $fstab_conf`
        [ -z "$vulnerable" ] && return ${CODE_CONFORMITY}

        backupFile "$fstab_conf" "data"
        tmp_file=`mktemp /tmp/tmp.XXXXXX 2>> "$LOGF"`

        [ -z "$tmp_file" -o ! -f "$tmp_file" ] || return ${CODE_FAILURE}

        awk -v tmp_file=$tmp_file '{ if ( $1 !~ /^[ \t]*#/ && $3 == /nfs/ && $4 !~ /nosuid/ ) { printf("%s\t%s\t%s\t%s,nosuid\t%s\t%s\n",$1,$2,$3,$4,$5,$6) >> tmp_file } else { print >> tmp_file } }' $fstab_conf 2>> "$LOGF"

        cat $tmp_file > $fstab_conf
        rm $tmp_file
        return ${CODE_OK}

}

#===  FUNCTION  ================================================================
#          NAME:  fix_perms_on_audit_files
#   DESCRIPTION:  Prevents audit files to be created with wrong permissions.
#    PARAMETERS:  $1 = permission 
#       RETURNS:  0 = success ; 1 = failure
#===============================================================================

fix_perms_on_audit_files () {

  audit_dir="/etc/logrotate.d"
  audit_conf_file="/etc/logrotate.conf"

  [ ! -d $audit_dir ] && [ ! -f "$audit_conf_file" ] && {
    echo "    Audit file dir $audit_dir and /etc/logrotate.conf not found." >> "$LOGF"
    [ $verbosit ] && echo "    Audit file dir $audit_dir and /etc/logrotate.conf not found."
    return $CODE_ERROR
  }

  audit_files=`grep create ${audit_dir}/* | grep -v 60 | cut -d: -f1 | sort -u 2>> /dev/null`

  has_wtmp=`sed -n "/wtmp.\{0,\}{/p" $audit_conf_file`
  wtmp_perm=`sed -n "/wtmp.\{0,\}{/,/}/ { /\(create[ \t]\{1,1\}\)0640\{1,\}\(.*\)/p }" $audit_conf_file`
  if [ -n "$has_wtmp" ] &&  [ -z "$wtmp_perm" ]; then
    audit_files="$audit_files $audit_conf_file"
  else
    wtmp_sec_perms=`sed -n "/wtmp.\{0,\}{/,/}/! { s/^.\{1,\}create[ \t]\{1,1\}\(0[0-6][0-7][0-7]\).*/\1/p }" /etc/logrotate.conf`
    for perm in $wtmp_sec_perms; do
      [ "$perm" != "0640" ] && {
        audit_files="$audit_files $audit_conf_file"
        break
      }
    done
  fi


  [ -z "$audit_files" ] && return $CODE_CONFORMITY

  backupFile "$audit_files" "data"

  for file in $audit_files; do

		tmp_file=`mktemp /tmp/XXXXXX 2>> "$LOGF"`

		if [ "$file" = "/etc/logrotate.conf" ]; then

			tmp_file1=`mktemp /tmp/XXXXXX 2>> "$LOGF"`

			sed "/wtmp.\{0,\}{/,/}/ { s/\(create[ \t]\{1,1\}\)[0-9]\{1,\}\(.*\)/\10640\2/ }" $file > $tmp_file 2>> $LOGF
			sed "/wtmp.\{0,\}{/,/}/! { s/\(create[ \t]\{1,1\}\)[0-9]\{1,\}\(.*\)/\10600\2/ }" $tmp_file > $tmp_file1 2>> $LOGF 

			cat $tmp_file1 > $file 2>> $LOGF
			rm $tmp_file $tmp_file1 2>> $LOGF

		else

			sed "s/\(create[ \t]\{1,1\}\)[0-9]\{1,\}\(.*\)/\10600\2/" $file > $tmp_file 2>> $LOGF

			cat $tmp_file > $file 2>> $LOGF
			rm $tmp_file 2>> $LOGF

		fi

  done

  return $CODE_OK 
}


#===  FUNCTION  ================================================================
#          NAME:  detect_grub
#   DESCRIPTION:  Detects grub binary and configuration file paths
#    PARAMETERS:  --
#===============================================================================
detect_grub () {

        grub_bin=`which grub`
        [ -z "$grub_bin" ] && {

                if [ -f "/sbin/grub" ]; then

                        grub_bin="/sbin/grub"
                else

                        return #no grub binary has been found
                fi
        }

        grub_conf_file=`"$grub_bin" --help | awk ' $1 ~ /--config-file/ { print $NF }' | sed 's/[][]//g ; s/default\=//g'`
        [ -z "$grub_conf_file" ] && {

                grub_paths=`echo "/boot/grub/menu.lst /boot/grub/grub.conf /etc/grub.conf" | tr " " "\n"`
                for grub_path in ${grub_paths}; do

                        [ -f "$grub_path" ] && {

                                grub_conf_file="$grub_path"
                                break
                        }
                done

                [ -z "$grub_conf_file" ] && return #no grub configuration file has been found
        }

        echo "$grub_conf_file"
}

#===  FUNCTION  ================================================================
#          NAME:  fix_grub_password
#   DESCRIPTION:  Force md5 crypt password on grub loader.
#    PARAMETERS:  --
#===============================================================================

fix_grub_password () {

	#how about /boot/grub/grub.conf?
  	file=`detect_grub`
  	grub_shell=`which grub`

  	[ -z "$file" ] && {
    
		MISSED_FILE="$file"
    		return ${CODE_MISSED_FILE}
  	}

  	[ -z "$grub_shell" ] && {
    
		echo "Grub not found." 2>> "$LOGF"
    		[ $verbosity ] && echo "    Grub not found."
    		return ${CODE_ERROR}
  	}

  	has_crypt_password=`sed -n "/^[ \t]*password[ \t]*--md5/p ; /^[ \t]*password[ \t]*--encrypted/p" ${file}`

  	if [ -z "$has_crypt_password" ]; then

    		[ -z "$BASE_GRUB_PASSWORD" ] && {
      
			MISSED_VAR="BASE_GRUB_PASSWORD"
      			return ${CODE_MISSED_VAR}
    		}

    		backupFile "$file" "data"

    		#Creating a md5 crypt password from grub shell 
    		hash_password=`$grub_shell --batch <<EOF \
			| grep "^Encrypted: " | sed 's/^Encrypted: //'
md5crypt
$BASE_GRUB_PASSWORD
quit
EOF 2>> "$LOGF"`

    		tmp_file=`mktemp /tmp/XXXXXX 2>> "$LOGF"`
    		sed "1ipassword --md5 $hash_password" $file > $tmp_file 2>> "$LOGF"

    		cat $tmp_file > $file 2>> "$LOGF"
    		rm -f $tmp_file 2>> "$LOGF"

    		return ${CODE_OK}

  	else

    		return ${CODE_CONFORMITY}
  	fi
}


#===  FUNCTION  ================================================================
#          NAME:  fix_password_expiration  
#   DESCRIPTION:  Set the baseline password expiration.
#    PARAMETERS:  --
#       RETURNS:  0 = succes ; 1 = failure
#===============================================================================

fix_password_expiration () {

  [ $# -lt 1 ] && return $CODE_ERROR 

  file="/etc/login.defs"

  [ -f "$file" ] || {
    MISSED_FILE="$file"
    return $CODE_MISSED_FILE
  }

  base_pass_days=$1

  in_accordance=`grep "^[ \t]*PASS_MAX_DAYS.*${base_pass_days}" $file`

  [ -n "$in_accordance" ] && return $CODE_CONFORMITY

  backupFile "$file" "data"

  tmp_file=`mktemp /tmp/XXXXXX`

  sed "s/^\([ \t]*PASS_MAX_DAYS\).*/\1\t${base_pass_days}/" $file > $tmp_file 2>> "$LOGF"

  cat $tmp_file > $file 2>> "$LOGF"

  rm $tmp_file 2>> "$LOGF"

  users=`cut -d: -f1 /etc/passwd 2>> "$LOGF"`

  for user in $users; do
    not_apply=`echo $BASE_USERS_PASSWORD_NOT_EXPIRE | grep $user 2>> "$LOGF"`
    [ -z "$not_apply" ] && chage -M ${base_pass_days} $user 2>> "$LOGF"
  done

  return $CODE_OK 

}



#===  FUNCTION  ================================================================
#          NAME:  fix_password_warning
#   DESCRIPTION:  Set the baseline password warning.
#    PARAMETERS:  --
#       RETURNS:  0 = succes ; 1 = failure
#===============================================================================

fix_password_warning () {

        [ $# -lt 1 ] && return $CODE_ERROR

	local IFS="
"
        local target_file="/etc/login.defs"
        local temp_file=`mktemp /tmp/XXXXXXXXXXXXXXX`
        local users=`cut -d: -f1 /etc/passwd 2>> "$LOGF"`
        local base_pass_warn_age=$1
	local users
        local has_pass_warn
        local pass_warn_value

	#applying the global policy
        if [ -f "$target_file" ]; then

                has_pass_warn=`cat $target_file | egrep -o "^[ \t]*PASS_WARN_AGE.*"`
                if [ -n "$has_pass_warn" ]; then 

                        pass_warn_value=`echo $has_pass_warn | egrep -o "[0-9]+"`
                        if [ -n "$pass_warn_value" ]; then 

                                if [ "$pass_warn_value" = "$base_pass_warn_age" ]; then

                                        return ${CODE_CONFORMITY}
                                else

                                        sed "s/^[ \t]\{0,\}PASS_WARN_AGE.*/PASS_WARN_AGE \t$base_pass_warn_age/" $target_file > $temp_file
                                        backupFile "$target_file" "data"
                                        cat $temp_file > $target_file
                                        rm -f $temp_file
                                fi
                        else

                                sed "s/^[ \t]\{0,\}PASS_WARN_AGE.*/PASS_WARN_AGE \t$base_pass_warn_age/" $target_file > $temp_file
                                backupFile "$target_file" "data"
                                cat $temp_file > $target_file
                                rm -f $temp_file
                        fi
                else

                        backupFile "$target_file" "data"
                        echo "PASS_WARN_AGE ${base_pass_warn_age}" >> $target_file
                fi
        else

                return ${CODE_MISSED_FILE}
        fi

	#applying user policy
	for user in ${users}; do

		if [ -n "$BASE_USERS_PASSWORD_NOT_EXPIRE" ]; then

			not_apply=`echo $BASE_USERS_PASSWORD_NOT_EXPIRE | grep $user 2>> "$LOGF"`
			[ -z "$not_apply" ] && chage -W ${base_pass_warn_age} $user 2>> "$LOGF"
		else

			chage -W ${base_pass_warn_age} $user 2>> "$LOGF"
		fi
	done

	return ${CODE_OK}
}



#===  FUNCTION  ================================================================
#          NAME:  fix_password_history
#   DESCRIPTION:  Force the system to make a history of user passwords.
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure ;
#===============================================================================

fix_password_history () {

  [ -z "$LINUX_DISTRO_TOKEN" ] && {
    echo "    Can not recognize Linux distro." 2>> "$LOGF"
    [ $verbosity ] && echo "    Can not recognize Linux distro."
    return $CODE_ERROR 
  }

  base_pass_hist=$1

  #Specific distro functions can be found on specific distro scripts on CD/lib/Linux/$SO
  #and it is sourced by CD/lib/Linux/Linux
  case $LINUX_DISTRO_TOKEN in

    'debian')

      fix_password_history_debian "$base_pass_hist"
      return $? 

      ;;

    'fedora'|'redhat')

      fix_password_history_fedora "$base_pass_hist"
      return $?

      ;;

    'suse')

      fix_password_history_suse "$base_pass_hist"
      return $?

      ;;

    'slackware')

      #Need specification
      echo "Can not be applied on Slackware." >> "$LOGF"
      [ $verbosity ] && echo "    Can not be applied on Slackware."
      return $CODE_ERROR 

      ;;


    *)
      #OS not supported
      echo "Can not recognize Linux distro, skipping..." >> "$LOGF"
      [ $verbosity ] && echo "Can not recognize Linux distro, skipping..."
      return $CODE_ERROR 
      ;;

  esac    # --- end of case ---

}

#===  FUNCTION  ================================================================
#          NAME:  fix_password_history_debian
#   DESCRIPTION:  Fix the password history on Debian and Ubuntu.
#    PARAMETERS:  $1 = password history number.
#       RETURNS:  0 = success ; 1 = failure  ; 77 = baseline definiton not found
#===============================================================================

fix_password_history_debian () {

  [ -z "$BASE_PASS_HIST" ] && {
    MISSED_VAR="BASE_PASS_HIST"
    return $CODE_MISSED_VAR
  }

  file="/etc/pam.d/common-password" 

  [ -f "$file" ] || {
    MISSED_FILE="$file"
    return $CODE_MISSED_FILE
  }

  regex="password[ \t]\{1,\}required[ \t]\{1,\}pam_unix.so[ \t]\{1,\}nullok[ \t]\{1,\}obscure[ \t]\{1,\}min=4[ \t]\{1,\}max=8[ \t]\{1,\}md5"
  regex1="$regex[ \t]*remember=${BASE_PASS_HIST}"
  line=`sed -n "/${regex1}/p" $file 2>> "$LOGF"`

  #In accordance with baseline 
  [ ! -z "$line" ] && return $CODE_CONFORMITY 

  line=`sed -n "/${regex}/p" $file 2>> "$LOGF"`

  [ -z "$line" ] && {
    echo "Pam configuration not found." >> "$LOGF"
    [ $verbosity ] && echo "Pam configuration not found."
    return $CODE_ERROR 
  } 

  backupFile "$file" "data"

  tmp_file=`mktemp /tmp/correction.XXXXXX 2>> "$LOGF"`
  sed "s/\(${regex}\)/\1\tremember=${BASE_PASS_HIST}/" $file > $tmp_file 2>> "$LOGF"

  cat $tmp_file > $file 2>> "$LOGF"

  rm $tmp_file 2>> "$LOGF"

  return $CODE_OK 

}

#===  FUNCTION  ================================================================
#          NAME:  fix_password_history_fedora
#   DESCRIPTION:  Fix the password history on Fedora and Redhat.
#    PARAMETERS:  $1 = password history number. 
#       RETURNS:  0 = success ; 1 = failure  ; 77 = baseline definition not found
#===============================================================================

fix_password_history_fedora () {

  [ -z "$BASE_PASS_HIST" ] && {
    MISSED_VAR="BASE_PASS_HIST"
    return $CODE_MISSED_VAR
  }

  file="/etc/pam.d/system-auth" 

  [ -f "$file" ] && {
    MISSED_FILE="$file"
    return $CODE_MISSED_FILE
  }

  regex="password[ \t]\{1,\}sufficient[ \t]\{1,\}pam_unix.so[ \t]\{1,\}md5[ \t]\{1,\}shadow[ \t]\{1,\}nullok[ \t]\{1,\}try_first_pass[ \t]\{1,\}use_authtok"
  regex1="$regex[ \t]*remember=${BASE_PASS_HIST}"
  line=`sed -n "/${regex1}/p" $file 2>> "$LOGF"`

  #In accordance with baseline 
  [ ! -z "$line" ] && return $CODE_CONFORMITY 

  line=`sed -n "/${regex}/p" $file 2>> "$LOGF"`

  [ -z "$line" ] && {
    echo "Pam configuration not found." >> "$LOGF"
    [ $verbosity ] && echo "Pam configuration not found."
    return $CODE_ERROR 
  } 

  backupFile "$file" "data"

  tmp_file=`mktemp /tmp/correction.XXXXXX 2>> "$LOGF"`
  sed "s/\(${regex}\)/\1\tremember=${BASE_PASS_HIST}/" $file > $tmp_file 2>> "$LOGF"

  cat $tmp_file > $file 2>> "$LOGF"

  rm $tmp_file 2>> "$LOGF"

  return $CODE_OK 

}


#===  FUNCTION  ================================================================
#          NAME:  fix_password_complexity
#   DESCRIPTION:  Set a bunch of directives to password update and creation.
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure ; 
#===============================================================================

fix_password_complexity () {

  [ -z "$LINUX_DISTRO_TOKEN" ] && {
    echo "Linux Distro not found, skipping..." >> "$LOGF"
    [ $verbosity ] && echo "    Linux Distro not found, skipping..."
    return $CODE_ERROR 
  }

  #Specific distro functions are found on specific distro scripts on CD/lib/Linux/$SO
  #and it is sourced by CD/lib/Linux/Linux
  case $LINUX_DISTRO_TOKEN in

    'debian')

      fix_password_complexity_common "/etc/pam.d/common-password" "password requisite pam_cracklib.so try_first_pass retry=3"
			status=$?
      return $status

      ;;

    'suse')

      fix_password_complexity_common "/etc/pam.d/common-password" "password required pam_cracklib.so try_first_pass retry=3"
      return $? 

      ;;

    'fedora'|'redhat')

      fix_password_complexity_common "/etc/pam.d/system-auth" "password requisite pam_cracklib.so try_first_pass retry=3"
      return $?

      ;;

    'slackware')

      #Need specification
      echo "Can not be applied on Slackware." >> "$LOGF"
      [ $verbosity ] && echo "    Can not be applied on Slackware."
      return $CODE_ERROR 

      ;;


    *)
      #OS not supported
      echo "Can not recognize Linux distro, skipping..." >> "$LOGF"
      [ $verbosity ] && echo "Can not recognize Linux distro, skipping..."
      return $CODE_ERROR 
      ;;

  esac    # --- end of case ---

}

#===  FUNCTION  ================================================================
#          NAME:  fix_password_complexity_common
#   DESCRIPTION:  Set a bunch of directives to password update and creation.
#    PARAMETERS:  $1 = pam configuration file
#          $2 = base configuration
#       RETURNS:  0 = success ; 1 = failure ;
#===============================================================================


fix_password_complexity_common () {

#BASE_PASS_DIFOK=4
#BASE_PASS_LEN=8
#BASE_PASS_LCREDIT=-1
#BASE_PASS_UCREDIT=-1
#BASE_PASS_DCREDIT=-1
#BASE_PASS_OCREDIT=0

  [ $# -lt 2 ] && {
    echo "Not enough parameters when calling fix_password_complexity_common" >> "$LOGF"
    return $CODE_ERROR 
  }


  #baseline specs
  if [ -z "$BASE_PASS_DIFOK" -o \
     -z "$BASE_PASS_LEN" -o \
     -z "$BASE_PASS_LCREDIT" -o \
     -z "$BASE_PASS_UCREDIT" -o \
     -z "$BASE_PASS_DCREDIT" -o \
     -z "$BASE_PASS_OCREDIT" ]; then

     MISSED_VAR="BASE_PASS_DIFOK BASE_PASS_LEN BASE_PASS_LCREDIT BASE_PASS_UCREDIT BASE_PASS_DCREDIT BASE_PASS_OCREDIT"
     return $CODE_MISSED_VAR 

  fi

  file=$1

  [ -f "$file" ] || {
    MISSED_FILE="$file"
    return $CODE_MISSED_FILE 
  }

  look_for=$2
  regex=`echo $look_for | sed -n 's/[[:blank:]]/[[:blank:]]\\\{1,\\\}/gp' 2>> "$LOGF"`

  params[1]="difok="
  params[2]="minlen="
  params[3]="lcredit="
  params[4]="ucredit="
  params[5]="dcredit="
  params[6]="ocredit="

  values[1]=$BASE_PASS_DIFOK
  values[2]=$BASE_PASS_LEN
  values[3]=$BASE_PASS_LCREDIT
  values[4]=$BASE_PASS_UCREDIT
  values[5]=$BASE_PASS_DCREDIT
  values[6]=$BASE_PASS_OCREDIT

  line=`sed -n "/^${regex}/p" $file 2>> "$LOGF"`

  #No previous policy in file. Configuring a new one.

  if [ -z "$line" ]; then

  	line="${look_for}"
  	for index in 1 2 3 4 5 6; do
    	line="${line} ${params[$index]}${values[$index]}"
  	done

    backupFile "$file" "data"


  	echo "echo \"$line\" >> $file"
  	echo "$line" >> $file

    return $CODE_OK 

  fi



  #In accordance
  [ -n "$line" ] && {
    in_accordance=0
    for index in 1 2 3 4 5 6; do
      prop=`sed -n "/^${regex}[ \t]\{1,\}.*${params[$index]}${values[$index]}/p" $file`
      [ -z "$prop" ] && in_accordance=1
    done

    [ $in_accordance -eq 0 ] && return $CODE_CONFORMITY
  }

  append=""
  delete=""



  #Checking if the parameters already exist. If not, append them. If it exists and has not the baseline value, replace it.
  for index in 1 2 3 4 5 6; do

    has_param=`echo $line | sed -n "/${params[$index]}/p" 2>> "$LOGF"`

  	if [ -z "$has_param" ]; then
    
    	append="$index $append"

    else

    	in_accordance=`echo $line | sed -n "/${param[$index]}${values[$index]}/" 2>> "$LOGF"`

    	[ -z "$in_accordance" ] && replace="$index $replace"

  	fi

  done

  for index in $replace; do

    line=`echo $line | sed "s/\(.*\)${params[$index]}[0-9]\{1,\}\(.*\)/\1\2/p" 2>> "$LOGF"`
    line="$line ${params[$index]}${values[$index]}"

  done

  for index in $append; do

    line="$line ${params[$index]}${values[$index]}"

  done



  backupFile "$file" "data"

  #Replacing the old configuration for the new one
  tmp_file=`mktemp /tmp/correction.XXXXXX`
  sed "s/${regex}.*/${line}/" $file > $tmp_file

  cat $tmp_file > $file

  rm $tmp_file

  return $CODE_OK 


}

#===  FUNCTION  ================================================================
#          NAME:  fix_password_complexity_debian
#   DESCRIPTION:  Set a bunch of directives to password update and creation on 
#                 Debian and Ubuntu.
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure ; 77 = baseline value not defined
#===============================================================================


fix_password_complexity_debian () {

#BASE_PASS_DIFOK=4
#BASE_PASS_LEN=8
#BASE_PASS_LCREDIT=-1
#BASE_PASS_UCREDIT=-1
#BASE_PASS_DCREDIT=-1
#BASE_PASS_OCREDIT=0

  #baseline specs
  if [ -z "$BASE_PASS_DIFOK" -o \
     -z "$BASE_PASS_LEN" -o \
     -z "$BASE_PASS_LCREDIT" -o \
     -z "$BASE_PASS_UCREDIT" -o \
     -z "$BASE_PASS_DCREDIT" -o \
     -z "$BASE_PASS_OCREDIT" ]; then

     return 77

  fi

  file="/etc/pam.d/common-password"
    # password required   pam_cracklib.so retry=3 minlen=6 difok=3
  regex="^[ \t]*password[ \t]\{1,\}required[ \t]\{1,\}pam_cracklib.so[ \t]\{1,\}retry=3[ \t]\{1,\}minlen=6[ \t]\{1,\}"

  regex1="$regex[ \t]\{1,\}difok=${BASE_PASS_DIFOK}[ \t]\{1,\}minlen=${BASE_PASS_LEN}[ \t]\{1,\}lcredit=${BASE_PASS_LCREDIT}[ \t]\{1,\}ucredit=${BASE_PASS_UCREDIT}[ \t]\{1,\}dcredit=${BASE_PASS_DCREDIT}[ \t]\{1,\}ocredit=${BASE_PASS_OCREDIT}"

  line=`sed -n "/${regex1}/p" $file`

  #In accordance with baseline 
  [ ! -z "$line" ] && return 0

  line=`sed -n "/${regex}/p" $file`
  if [ ! -f "$file" ]; then

    return 1

  fi

  backupFile "$file" "data"
  tmp_file=`mktemp /tmp/correction.XXXXXX`

  if [ ! -z "$line" ]; then

    #deleting previous definitions
    sed "/${regex}/d" $file > $tmp_file

  fi

  echo "password requisite pam_cracklib.so try_first_pass retry=3 difok=${BASE_PASS_DIFOK} minlen=${BASE_PASS_LEN} lcredit=${BASE_PASS_LCREDIT} ucredit=${BASE_PASS_UCREDIT} dcredit=${BASE_PASS_DCREDIT} ocredit=${BASE_PASS_OCREDIT}" >> $tmp_file

  cat $tmp_file > $file

  rm $tmp_file

  return 0

}

#===  FUNCTION  ================================================================
#          NAME:  fix_irrestrict_graphical_login
#   DESCRIPTION:  Deny irrestrict graphical login to XDM and GDM
#    PARAMETERS:  --
#       RETURNS:  --
#===============================================================================

fix_irrestrict_graphical_login () {

  gdm_confs="/etc/gdm/custom.conf /etc/opt/gnome/gdm.conf /etc/gdm/gdm.conf /etc/X11/gdm/gdm.conf"
  xdm_conf="/etc/X11/xdm/Xaccess"
  backup_files=""

  for file in $gdm_confs $xdm_conf; do
    [ -f "$file" ] && backup_files="$file $backup_files"
  done

  backupFile "$backup_files" "data"

  for gdm_conf in $gdm_confs; do

    if [ -f "$gdm_conf" ]; then
            #Checking if [xdmcp] session has Enable=False
      line=`sed -n '/\[xdmcp\]/,/\[.*\]/p' $gdm_conf | grep "Enable=False" 2>> "$LOGF"`

      if [ -z "$line" ]; then

        tmp_file=`mktemp /tmp/correction.XXXXXX`

        sed "/\[xdmcp\]/aEnable=False" $gdm_conf > $tmp_file
        cat $tmp_file > $gdm_conf

        rm $tmp_file

      fi

    fi

  done

  tmp_file=`mktemp /tmp/correction.XXXXXX 2>> "$LOGF"`
  if [ -f "$xdm_conf" ]; then

    #http://tldp.org/HOWTO/XDM-Xterm/config.html
    sed "s/^\(\*.*\)$/#\1/" $xdm_conf  > $tmp_file 2>> "$LOGF"
    cat $tmp_file > $xdm_conf 2>> "$LOGF"

  fi
  rm $tmp_file 2>> "$LOGF"

  return $CODE_OK 

}


#===  FUNCTION  ================================================================
#          NAME:  fix_min_len_password
#   DESCRIPTION:  Set the minimal user password lenght.
#    PARAMETERS:  --
#       RETURNS:  0 = succes ; 1 = failure
#===============================================================================

fix_min_len_password () {

	[ -z "$BASE_PASS_LEN" ] && {

		MISSED_VAR="BASE_PASS_LEN"
		return ${CODE_MISSED_VAR}
	}

	# is it debian/ubuntu-like?
	if [ -s "/etc/debian_version" ]; then

		local target_file="/etc/pam.d/common-password"
		local temp_file=`mktemp /tmp/XXXXXXXXXXXXXXX`
		local has_cracklib_in_pam
		local has_pam_unix
		local min_test
		local has_min_value
		local new_conf

		if [ -s "$target_file" ]; then

		        has_cracklib_in_pam=`cat $target_file | egrep -v "(^[ \t]*#|^[ \t]*$)" | egrep "^[ \t]*password.*cracklib"`
		        if [ -n "$has_cracklib_in_pam" ]; then

		                #correct cracklib.so
		                has_min_value=`echo $has_cracklib_in_pam | egrep -o "minlen=[0-9]+"`
		                if [ -n "$has_min_value" ]; then

		                        min_test=`echo $has_min_value | egrep -o "[0-9]+"`
		                        if [ "$min_test" = "$BASE_PASS_LEN" ]; then

						return ${CODE_CONFORMITY}
		                        else

		                                new_conf=`echo $has_cracklib_in_pam | sed "s/minlen=[0-9]\{1,\}/minlen=$BASE_PASS_LEN/g"`
		                                sed "s/^[ \t]\{0,\}password.*cracklib.*/$new_conf/" $target_file > $temp_file
						backupFile "$target_file" "data"
		                                cat $temp_file > $target_file
		                                rm -f $temp_file
						return ${CODE_OK}
		                        fi
		                else

		                        #add minlen parameter to password.*cracklib line
		                        new_conf=`echo $has_cracklib_in_pam" minlen=$BASE_PASS_LEN"`
		                        sed "s/^[ \t]\{0,\}password.*cracklib.*/$new_conf/" $target_file > $temp_file
		                       	backupFile "$target_file" "data" 
		                        cat $temp_file > $target_file
		                        rm -f $temp_file
					return ${CODE_OK}
		                fi
		        else

		                #correct pam_unix.so
		                has_pam_unix=`cat $target_file | egrep -v "(^[ \t]*#|^[ \t]*$)" | egrep "^[ \t]*password.*pam_unix(2)?\.so"`
		                if [ -n "$has_pam_unix" ]; then

		                        has_min_value=`echo $has_pam_unix | egrep -o "min=[0-9]+"`
		                        if [ -n "$has_min_value" ]; then

		                                min_test=`echo $has_min_value | egrep -o "[0-9]+"`
		                                if [ "$min_test" = "$BASE_PASS_LEN" ]; then

							return ${CODE_CONFORMITY}
		                                else

		                                        new_conf=`echo $has_pam_unix | sed "s/min=[0-9]\{1,\}/min=$BASE_PASS_LEN/g"`
		                                        sed "s/^[ \t]\{0,\}password.*pam_unix.*/$new_conf/" $target_file > $temp_file
		                                        backupFile "$target_file" "data"
		                                        cat $temp_file > $target_file
		                                        rm -f $temp_file
							return ${CODE_OK}
		                                fi
		                        else

		                                #add minlen parameter to password.*cracklib line
		                                new_conf=`echo $has_pam_unix" min=$BASE_PASS_LEN"`
		                                sed "s/^[ \t]\{0,\}password.*pam_unix.*/$new_conf/" $target_file > $temp_file
		                                backupFile "$target_file" "data"
		                                cat $temp_file > $target_file
		                                rm -f $temp_file
						return ${CODE_OK}
		                        fi
		                else

					return ${CODE_ERROR}
		                fi
		        fi
		else

			return ${CODE_MISSED_FILE}
		fi
	else

		local IFS="
"
		local target_file="/etc/login.defs"
		local temp_file=`mktemp /tmp/XXXXXXXXXXXXXXX`
		local has_pass_min_len
		local pass_min_len_value

		if [ -f "$target_file" ]; then 

			has_pass_min_len=`cat $target_file | egrep -o "^[ \t]*PASS_MIN_LEN.*"`
			if [ -n "$has_pass_min_len" ]; then

				pass_min_len_value=`echo $has_pass_min_len | egrep -o "[0-9]+"`
				if [ -n "$pass_min_len_value" ]; then

					if [ "$pass_min_len_value" = "$BASE_PASS_LEN" ]; then

						return ${CODE_CONFORMITY}
					else

						sed "s/^[ \t]\{0,\}PASS_MIN_LEN.*/PASS_MIN_LEN \t$BASE_PASS_LEN/" $target_file > $temp_file
						backupFile "$target_file" "data"
						cat $temp_file > $target_file
						rm -f $temp_file
						return ${CODE_OK}
					fi
				else

					sed "s/^[ \t]\{0,\}PASS_MIN_LEN.*/PASS_MIN_LEN \t$BASE_PASS_LEN/" $target_file > $temp_file
					backupFile "$target_file" "data"
					cat $temp_file > $target_file
					rm -f $temp_file
					return ${CODE_OK}
				fi
			else

				backupFile "$target_file" "data"
				echo "PASS_MIN_LEN ${BASE_PASS_LEN}" >> $target_file
				return ${CODE_OK}
			fi
		else

			return ${CODE_MISSED_FILE}
		fi
	fi
}

#===  FUNCTION  ================================================================
#          NAME:  snmp_fix_default_communities
#   DESCRIPTION:  Disable public and/or private default comminities.
#    PARAMETERS:  --
#===============================================================================
snmp_fix_default_communities () {

	local snmp_conf
	local all_communities
	local vuln_communities
	local name
	local cmd_suffixes
	local tmp_file

	snmp_conf="/etc/snmp/snmpd.conf"

	[  -f "$snmp_conf" ] || {

		MISSED_FILE="$snmp_conf"
		return $CODE_MISSED_FILE
	}

	# If BASE_SNMP_COMMUNITY is not setted, then comment only public or private community and
	#   do not add any community.
	# Otherwise, look in BASE_SNMP_COMMUNITY baseline variable for valid communities names and
	#   add the missing communities on snmp configuration file.
	base_exists=`set | egrep "^[ \t]*BASE_SNMP_COMMUNITY="`

	[ -z "${base_exists}" ] && {
    
		MISSED_VAR="BASE_SNMP_COMMUNITY"
    		return $CODE_MISSED_VAR
  	}

  	all_communities=`sed -n -e "/^[ \t]\{0,\}#/d" -e "/^[ \t]\{0,\}com2sec/p" $snmp_conf`
  	vuln_communities=""

  	# For each community found check if it is in accordance with specified baseline.
  	oldIFS=$IFS
  	IFS=$'\n'
  	for community in $all_communities; do
    
		name=`echo "$community" | awk '{ print $4 }'`
    		[ -z "$name" ] && continue

    		if [ -n "$BASE_SNMP_COMMUNITY" ]; then
      
			testing=`echo "$BASE_SNMP_COMMUNITY" | tr " " "\n" | sort -u | awk -v name="$name" ' ( $0 == name ) { print $0 } '`
			[ -z "$testing" ] && {
        		
				if [ -z "$vuln_communities" ]; then
          	
					vuln_communities="$community"
        			else
          
					vuln_communities="$vuln_communities
$community"
        			fi
      			}
    		else 
      
			[ "$name" = "public" ] || [ "$name" = "private" ] && {
        
				if [ -z "$vuln_communities" ]; then
          
					vuln_communities="$community"
        			else
          	
					vuln_communities="$vuln_communities
$community"
        			fi
      			} 
    		fi

  	done
  	IFS=$oldIFS


	[ -n "$vuln_communities" ] && {

          	 backupFile "$snmp_conf" "data"

                oldIFS=$IFS
                IFS=$'\n'

                tmp_file=`mktemp /tmp/tmp.XXXXXX`

                for community in $vuln_communities; do

                        name=`echo "$community" | awk '{ print $4 }'`
                        cat $snmp_conf | awk -v name="$name" ' (( $1 == "com2sec" ) && ( $4 != name )) || ( $1 != "com2sec" ) { print $0 } ' > $tmp_file
                        cat $tmp_file > $snmp_conf
                done

                rm -f $tmp_file
                IFS=$oldIFS

        }


  	[ -z "${base_exists}" ] && [ -z "$vuln_communities" ] && return $CODE_CONFORMITY
  	[ -z "${base_exists}" ] && [ -n "$vuln_communities" ] && return $CODE_OK

  	missing_communities=""

  	# Looking for communities specified on baseline and not present on snmpd file.
  	for community in $BASE_SNMP_COMMUNITY; do
    
		found=`awk -v name="$name" ' ( $1 == "com2sec" ) && ( $4 == name ) { print $0 } ' $snmp_conf`
		[ -z "$found" ] &&  {
      	
			if [ -z "$missing_communities" ]; then
        
				missing_communities="$community"
      			else
        
				missing_communities="$missing_communities
$community"
      			fi
    		}
  	done
 

  	[ -z "${missing_communities}" ] && [ -z "$vuln_communities" ] && return $CODE_CONFORMITY
  	[ -z "${missing_communities}" ] && [ -n "$vuln_communities" ] && return $CODE_OK

  	[ -z "$vuln_communities" ] && backupFile "$snmp_conf" "data"

  	# Adding missing communities do snmpd configuration file.
  	oldIFS=$IFS
  	IFS=$'\n'
  	for community in $missing_communities; do
    
		echo "com2sec ${SNMP_DEFAULT_SEC_NAME} default ${community}" >> $snmp_conf
  	done
  	IFS=$oldIFS

  	return $CODE_OK
}

#===  FUNCTION  ================================================================
#          NAME:  snmp_fix_managers
#   DESCRIPTION:  Enable managers on communities.
#    PARAMETERS:  --
#===============================================================================
snmp_fix_managers() {

snmp_conf="/etc/snmp/snmpd.conf"

	[  -f "$snmp_conf" ] || {

		MISSED_FILE="$snmp_conf"
		return $CODE_MISSED_FILE
	}

  	[ -z "${BASE_SNMP_ALLOWED_HOSTS}" ] && {
    
		MISSED_VAR="BASE_SNMP_ALLOWED_HOSTS"
    		return $CODE_MISSED_VAR
  	}

  	###all_communities=`sed -n -e "/^[ \t]\{0,\}#/d" -e "/^[ \t]\{0,\}com2sec/p" $snmp_conf`
  	all_communities=`sed -n -e "/^[ \t]\{0,\}com2sec/p" $snmp_conf`
  	vuln_communities=""

  	# Looking for communities with invalid managers
  	oldIFS=$IFS
  	IFS=$'\n'
  	
	for community in $all_communities; do

    		name=`printf "$community" | awk '{ print $4 }'`
    		address=`printf "$community" | awk '{ print $3 }' | awk -F"/" '{ print $1 }'`
    		netmask=`printf "$community" | awk '{ print $3 }' | awk -F"/" '{ print $2 }'`
		[ -z "$netmask" ] && netmask="32"
 
    		# Invalid source (default or network)
    		[ "$address" == "default" ] || [ "$netmask" != "32" -a "$netmask" != "255.255.255.255" ] && {
      
			if [ -z "$vuln_communities" ]; then
        
				vuln_communities="$community"
      			else
        
				vuln_communities="$vuln_communities
$community"
      			fi
      			continue
   	 	}

    		# Address not found on baseline.
    		printf "$BASE_SNMP_ALLOWED_HOSTS" | tr " " "\n" | sort -u | egrep -v "^[ \t]*$" | egrep -q "^$address$" || {
      
			if [ -z "$vuln_communities" ]; then
        		
				vuln_communities="$community"
      			else
        
				vuln_communities="$vuln_communities
$community"
      			fi
      			continue
    		}
  	done

	IFS=$oldIFS

  	[ -n "$vuln_communities" ] && {
    
		backupFile "$snmp_conf" "data"

    		# Building sed command to comment all vulnerable communities.
    		cmd_suffixes=""
    		oldIFS=$IFS
    		IFS=$'\n'
    
    		tmp_file=`mktemp /tmp/tmp.XXXXXX`

		for community in $vuln_communities; do

			address=`printf "$community" | awk '{ print $3 }' | awk -F"/" '{ print $1 }'`
			cat $snmp_conf | sed -e "/^[ \t]\{0,\}com2sec.*$address.*/d" > $tmp_file
			cat $tmp_file > $snmp_conf
    		done

    		rm $tmp_file
		IFS=$oldIFS
  	}

  	missing_comm_managers=""

  	# Looking for managers not configured on available communities.
  	# At this point we have communities with manager as hosts only.

  	# Retrieving community names
  	community_names=`printf "$all_communities" | awk '{ print $4 }' | sort -u`

  	for comm_name in $community_names; do
    
		sources=`awk -v name="$comm_name" ' ( $1 == "com2sec" && $4 == name ) { print $3 } ' $snmp_conf`

    		# Discarding subnet (MASK or BITS) from source.
    		# Remember, we have only hosts configured on comunities at this stage of the fix.
    		managers=`printf "$sources" | awk -F"/" '{ print $1 }'`
    
		for manager in $BASE_SNMP_ALLOWED_HOSTS; do
      
			printf "$managers" | tr " " "\n" | sort -u | egrep -v "^[ \t]*$" | egrep -q "^$manager$" || {
        
				if [ -z "$missing_comm_managers" ]; then
          	
					missing_comm_managers="$manager/32 $comm_name"
        			else
          		
					missing_comm_managers="$missing_comm_managers
$manager/32 $comm_name"
        			fi
     	 		}
    		done
  	done

  	[ -z "$vuln_communities" ] && [ -z "$missing_comm_managers" ] && return $CODE_CONFORMITY
  	[ -n "$vuln_communities" ] && [ -z "$missing_comm_managers" ] && return $CODE_OK

  	# Adding missing managers on available communities.
  	[ -z "$vuln_communities" ] && backupFile "$snmp_conf" "data"
 
  	oldIFS=$IFS
  	IFS=$'\n'
  	for missing in $missing_comm_managers; do
    
		echo "com2sec ${SNMP_DEFAULT_SEC_NAME} $missing" >> $snmp_conf
  	done
  
	IFS=$oldIFS
  	return $CODE_OK
}

#===  FUNCTION  ================================================================
#          NAME:  fix_unnecessary_services 
#   DESCRIPTION:  Disable unnecessary services.
#    PARAMETERS:  --
#       RETURNS:  0 = succes ; 1 = failure ; 72 = configuration file not found.
#             ; 77 = baseline definiton not found ; 
#===============================================================================

fix_unnecesary_services () {

  	unset MISSED_VAR

  	[ -z "$BASE_SERV_DENY" ] && [ -z "$BASE_SERV_ALLOW" ] && {

		MISSED_VAR="BASE_SERV_ALLOW BASE_SERV_DENY"
		return $CODE_MISSED_VAR
	}

  	services_backup=""                                 
  	[ -n "$BASE_SERV_ALLOW" ] && {

    		#all init scripts
    		for init_script in `ls /etc/rc[0-9S].d/S* 2>> "$LOGF"`; do

      			runlevel=`echo $init_script | sed -n 's/.*rc\([0-9]\)\.d.*/\1/p'`
      			script_name=`basename $init_script`
      			service_name=`echo $script_name | sed -n 's/^.[0-9]\{2\}\([a-z]\{1,\}\)/\1/p'`

      			#Do not enable the service in runlevel 0, 1 or 6
      			[[ "$runlevel" == [016] ]] && continue

      			allowed=1
      			for base_script in $BASE_SERV_ALLOW; do
				
				[ "$base_script" == "$service_name" ] && { 
					
					allowed=0
					break
        			}
      			done

      			id_number=`echo $script_name | sed -n 's/^.\([0-9]\{2\}\).*/\1/p'`
      			status=`echo $script_name | sed -n 's/^\(.\)[0-9]\{2\}.*/\1/p'`
      			script_dirname=`dirname $init_script`

			#enable the service if it's disabled
			if [ $allowed -eq 0 ]; then

				#service is already enabled 
				[ "$status" == "S" ] && continue

				tmp_id=`expr 100 - $id_number`
				enabled_id=`printf "%02d" $tmp_id`

				echo "Enabling $service_name" >> "$LOGF"
				[ $verbosity ] && echo "    Enabling $service_name"
				mv $init_script $script_dirname/S${enabled_id}${service_name} 2>> "$LOGF"

				services_backup="$services_backup mv $script_dirname/S${enabled_id}${service_name} $init_script;"

      			else

        			#the service is not allowed to run and it need to be disabled.
				#service is already disabled
				[ "$status" == "K" ] && continue

				tmp_id=`expr 100 - $id_number`
        			disabled_id=`printf "%02d" $tmp_id`

                                apply_service="0"
                                [ "$interactive" = "no" ] || {

                                        yn "            [*] Service to be stopped: \"${service}\". Apply?"
                                        apply_service="$?"
                                }

                                [ "$apply_service" -eq "1" ] && {

                                        continue
                                }

				echo "                Disabling $name" >> "$LOGF"
				echo "                Disabling $name"
				mv $init_script $script_dirname/K${disabled_id}${service_name} 2>> "$LOGF"
				services_backup="$services_backup mv $script_dirname/K${disabled_id}${service_name} $init_script;"
      			fi

    		done

    		backupFile "" "perm" "$services_backup"
    		unset init_script runlevel script_name service_name allowed base_script id_number status script_dirname enabled_id services_backup disabled_id
    		return $CODE_OK 
  	}

  	[ -n "$BASE_SERV_DENY" ] && {

    		for denied in $BASE_SERV_DENY; do

      			init_scripts=`ls /etc/rc[0-9S].d/*${denied}* 2>> "$LOGF"`

      			for script_path in $init_scripts; do
				
				runlevel=`echo $script_path | sed -n 's/.*rc\([0-9]\)\.d.*/\1/p' 2>> "$LOGF"`

				script_name=`basename $script_path 2>> "$LOGF"`
				script_dirname=`dirname $script_path 2>> "$LOGF"`

				status=`echo $script_name | sed -n 's/^\(.\)[0-9]\{2\}[a-z]\{1,\}/\1/p' 2>> "$LOGF"`

				#service is already disabled
				[ "$status" == "K" ] && continue

				id_number=`echo $script_name | sed -n 's/^.\([0-9]\{2\}\)[a-z]\{1,\}/\1/p' 2>> "$LOGF"`
				id_number=`expr 100 - $id_number`
				name=`echo $script_name | sed -n 's/^.[0-9]\{2\}\([a-z]\{1,\}\)/\1/p' 2>> "$LOGF"`

                                apply_service="0"
                                [ "$interactive" = "no" ] || {

                                	yn "            [*] Service to be stopped: \"${service}\". Apply?"
                                	apply_service="$?"
                                }

                                [ "$apply_service" -eq "1" ] && {

                                	continue
                                }

				echo "                Disabling $name" >> "$LOGF"
				echo "                Disabling $name"
				mv $script_path $script_dirname/K${id_number}${name} 2>> "$LOGF"
				services_backup="$services_backup mv $script_dirname/K${id_number}${name} $script_path;"

      			done

    		done

    		backupFile "" "perm" "$services_backup"
    		unset denied init_scripts script_path runlevel script_name script_dirname status id_number name services_backup 

    		return $CODE_OK 

  	}

  	return $CODE_ERROR 
}

#===  FUNCTION  ================================================================
#          NAME:  remove_dup
#   DESCRIPTION:  Receives a list of strings and strip the repetition.
#    PARAMETERS:  $1 = (string) list of strings, \n separated.
#                 $2 = (integer) Maximum size of string comparison.(optional)
#       RETURNS:  0 = success ; 1 = failure
#===============================================================================

remove_dup () {

  [ $# -lt 1 ] && return 1

  max="$2"

  if [ -n "$max" ]; then

    echo "$1" | awk -v max="$max" '!x[substr($0,1,max)]++'

  else

    echo "$1" | awk '!x[$0]++'

  fi

  return 0

}

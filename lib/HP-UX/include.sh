#===============================================================================

#===  FUNCTION  ================================================================
#          NAME:  snmp_disable_default_communities
#   DESCRIPTION:  Disable public and/or private default comminities.
#    PARAMETERS:  --
#===============================================================================
snmp_disable_default_communities () {

  local snmp_conf
  local all_communities
  local vuln_communities
  local name
  local perm
  local cmd_suffixes
  local tmp_file
  local do_not_backup
  local missing_communities
  local found
  local community

  snmp_conf="/etc/SnmpAgent.d/snmpd.conf"

  [  -f "$snmp_conf" ] || {
    MISSED_FILE="$snmp_conf"
    return $CODE_MISSED_FILE
  }

  # If BASE_SNMP_COMMUNITY is not setted, then comment only public or private community and
  #   do not add any community.
  # Otherwise, look in BASE_SNMP_COMMUNITY baseline variable for valid communities names and
  #   add the missing communities on snmp configuration file.
  base_exists=`set | grep "BASE_SNMP_COMMUNITY="`

  [ -z "${base_exists}" ] && {
    MISSED_VAR="BASE_SNMP_COMMUNITY"
    return $CODE_MISSED_VAR
  }

  all_communities=`sed -n -e "/^[ \t]\{0,\}#/d" -e "/[gs]et-community-name[ \t]\{0,\}:/p" $snmp_conf`
  vuln_communities=""

  # For each community found check if it is in accordance with specified baseline.
  oldIFS=$IFS
  IFS="
"
  for community in $all_communities; do
    name=`printf "$community" | awk '{ print $2 }'`
    perm=`printf "$community" | awk -F"-" '{ print $1 }'`

    [ -z "$name" ] || [ -z "$perm" ] && continue

    if [ -n "${BASE_SNMP_COMMUNITY}" ]; then
      echo "$BASE_SNMP_COMMUNITY" | grep -q "$name" || {
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

  do_not_backup=""
  [ -n "$vuln_communities" ] &&  {
    backupFile "$snmp_conf" "data"
    do_not_backup="true"

    # Building sed command to comment all vulnerable communities.
    cmd_suffixes=""
    oldIFS=$IFS
    IFS="
"
    for community in $vuln_communities; do
      cmd_suffixes="$cmd_suffixes -e 's/^\\($community\)/#\\1/'"
    done
    IFS=$oldIFS
  
    tmp_file=`mktemp /tmp/tmp.XXXXXX`
    eval "sed $cmd_suffixes $snmp_conf > $tmp_file"
    cat $tmp_file > $snmp_conf
    rm $tmp_file

  }

  [ -z "${base_exists}" ] && [ -z "$vuln_communities" ] && return $CODE_CONFORMITY
  [ -z "${base_exists}" ] && [ -n "$vuln_communities" ] && return $CODE_OK

  missing_communities=""

  for community in $BASE_SNMP_COMMUNITY; do
    found=`sed -n "/^[ \t]\{0,\}[gs]et-community-name.\{1,\}$community/p" $snmp_conf`
    [ -z "$found" ] &&  {
      if [ -z "$missing_communities" ]; then
        missing_communities="$community"
      else
        missing_communities="$missing_communities
$community"
      fi
    }
  done

  [ -z "$missing_communities" ] && [ -z "$vuln_communities" ] && return $CODE_CONFORMITY
  [ -z "$missing_communities" ] && [ -n "$vuln_communities" ] && return $CODE_OK

  [ -z "$do_not_backup" ] && backupFile "$snmp_conf" "data"

  oldIFS=$IFS
  IFS="
"
  for community in $missing_communities; do
    echo "get-community-name: $community" >> $snmp_conf
  done
  IFS=$oldIFS

  return $CODE_OK

}

#===  FUNCTION  ================================================================
#          NAME:  snmp_fix_managers 
#   DESCRIPTION:  Set the communities managers according the baseline. 
#    PARAMETERS:  --
#===============================================================================
snmp_fix_managers() {

  local snmp_conf
  local vuln_traps
  local all_traps
  local _trap
  local name
  local cmd_suffixes
  local tmp_file
  local missing_traps

  snmp_conf="/etc/SnmpAgent.d/snmpd.conf"

  [  -f "$snmp_conf" ] || {
    MISSED_FILE="$snmp_conf"
    return $CODE_MISSED_FILE
  }

  [ -z "${BASE_SNMP_ALLOWED_HOSTS}" ] && {
    MISSED_VAR="BASE_SNMP_ALLOWED_HOSTS"
    return $CODE_MISSED_VAR
  }

  # Removing newline from BASE_SNMP_ALLOWED_HOSTS variable
  basetmp=""
  oldIFS=$IFS
  IFS="
"
  for h in $BASE_SNMP_ALLOWED_HOSTS; do
    if [ -z "$basetmp" ]; then
      basetmp="$h"
    else
      basetmp="$basetmp $h"
    fi
  done
  IFS=$oldIFS

  BASE_SNMP_ALLOWED_HOSTS=$basetmp
  #

  vuln_communities=""
  all_communities=`sed -n -e "/^[ \t]\{0,\}#/d" -e "/[gs]et-community-name[ \t]\{0,\}:/p" $snmp_conf`

  # Looking for communities without managers or unknown managers (according with baseline).
  oldIFS=$IFS
  IFS="
"
  for community in $all_communities; do
    # get-community-name: name [IP: [addr [addr1] [addrn]]] [VIEW: mib-view]
   
    # If community does not have the IP field, it's vulnerable. 
    printf "$community" | grep -q "IP:" || {
      if [ -z "$vuln_communities" ]; then
        vuln_communities="$community"
      else
        vuln_communities="$vuln_communities
$community"
      fi
      continue
    }

    # If the community contains a manager that does not belongs to baseline, it's vulnerable
    managers=`printf "$community" | sed -n "s/.\{1,\}IP:[ \t]\{0,\}\([0-9\. ]\{1,\}\).\{0,\}/\1/p"` 
    oldIFS1=$IFS
    IFS=" "
    for manager in $managers; do
      printf "$BASE_SNMP_ALLOWED_HOSTS" | grep -q "$manager" || {
        if [ -z "$vuln_communities" ]; then
          vuln_communities="$community"
        else
          vuln_communities="$vuln_communities
$community"
        fi
        break
      }
    done
    IFS=$oldIFS1

  done
  IFS=$oldIFS
  #

  [ -z "$vuln_communities" ] && return $CODE_CONFORMITY 

  oldIFS=$IFS
  IFS="
"
  for community in $vuln_communities; do
    name=`printf "$community" | awk '{ print $2 }'`
    printf "$community" | grep -q "IP:"
    has_manager=$?

    tmp_file=`mktemp /tmp/tmp.XXXXXX`
    if [ $has_manager -eq 0 ]; then
      # Replacing IP field.
      sed "/^[ \t]\{0,\}[gs]et-community-name:[ \t]\{1,\}${name}/ { s/IP:[ \t]\{1,\}[0-9\. ]\{1,\}/IP: ${BASE_SNMP_ALLOWED_HOSTS} / }" $snmp_conf > $tmp_file 2>> "$LOGF"
    else
      # Adding IP field.
      sed "s/^[ \t]\{0,\}\([gs]et-community-name:[ \t]\{1,\}${name}\)\( .\{1,\}\)\{0,1\}$/\1\2 IP: ${BASE_SNMP_ALLOWED_HOSTS}/" $snmp_conf > $tmp_file 2>> "$LOGF"
    fi
    cat $tmp_file > $snmp_conf
    rm $tmp_file

  done
  IFS=$oldIFS

  return $CODE_OK

}

#===  FUNCTION  ================================================================
#          NAME:  fix_password_expiration_warning
#   DESCRIPTION:  Change the time of the warning to be shown before the user's 
#                 password expiration.
#    PARAMETERS:  --
#===============================================================================

fix_password_expiration_warning () {

        local file='/etc/default/security'

        [ -z "$BASE_WARNTIME" ] && {

                MISSED_VAR='BASE_WARNTIME'
                return ${CODE_MISSED_VAR}
        }

        local trusted_status=`check_trusted`
        if [ "$trusted_status" = "1" ]; then

                if [ ! -f "$file" ]; then

                        touch "$file"
                        bkp_cmd="rm -f $file"
                        backupFile "" "perm" "$bkp_cmd"

                        chmod 640 "$file"
                        echo "PASSWORD_WARNDAYS=${BASE_WARNTIME}" > "$file"
                else

                        local curr_value=`egrep -s "^[ \t]*PASSWORD_WARNDAYS[ \t]*=[ \t]*${BASE_WARNTIME}" "$file"`
                        if [ -n "$curr_value" ]; then

                                return ${CODE_CONFORMITY}
                        else

                                curr_value=`egrep -s "^[ \t]*PASSWORD_WARNDAYS[ \t]*=[ \t]*[0-9]+" "$file" | awk -F'=' '{ print $2 }' | tail -n1`
                                if [ -f '/usr/sbin/ch_rc' ]; then

                                        ch_rc_bin='/usr/sbin/ch_rc'
                                        if [ -z "$curr_value" ]; then

                                                bkp_cmd=`$ch_rc_bin -r -p "PASSWORD_WARNDAYS" "$file"`
                                        else

                                                bkp_cmd=`$ch_rc_bin -a -p "PASSWORD_WARNDAYS=$curr_value" "$file"`
                                        fi

                                        backupFile "" "perm" "$bkp_cmd"
                                        $ch_rc_bin -a -p "PASSWORD_WARNDAYS=$BASE_WARNTIME" "$file" 2>>$LOG >>$LOG
                                else

                                        backupFile "$file" "data"
                                        local temp_file=`mktemp /tmp/XXXXXXXXXXX`
                                        cat "$file" | sed "s/^[ \t]\{0,\}PASSWORD_WARNDAYS[ \t]\{1,\}.*/PASSWORD_WARNDAYS=$BASE_WARNTIME/g" > "$temp_file"
                                        cat "$temp_file" > "$file"
                                        rm -f "$temp_file"
                                fi
                        fi
                fi
        else

                curr_value=`/usr/lbin/getprdef -m expwarn | awk -F'=' '{ print $2 }'`
                if [ -n "$curr_value" -a "$curr_value" = "$BASE_WARNTIME" ]; then

                        return ${CODE_CONFORMITY}
                else

                        bkp_cmd=`/usr/lbin/modprdef -m expwarn=${curr_value}`
                        backupFile "" "perm" "$bkp_cmd"

                        /usr/lbin/modprdef -m expwarn=${BASE_WARNTIME} 2>>$LOG >>$LOG
                        /usr/lbin/modprpw -V 2>>$LOG >>$LOG
                fi
        fi

        return ${CODE_OK}
}

#===  FUNCTION  ================================================================
#          NAME:  fix_account_locking
#   DESCRIPTION:  Define the maximum number of login attempts before the
#                 password is locked.
#    PARAMETERS:  --
#===============================================================================

fix_account_locking () {

        local file='/etc/default/security'

        [ -z "$BASE_RETRIES" ] && {

                MISSED_VAR='BASE_RETRIES'
                return ${CODE_MISSED_VAR}
        }

        local trusted_status=`check_trusted`
        if [ "$trusted_status" = "1" ]; then

                if [ ! -f "$file" ]; then

                        touch "$file"
                        bkp_cmd="rm -f $file"
                        backupFile "" "perm" "$bkp_cmd"

                        chmod 640 "$file"
                        echo "AUTH_MAXTRIES=${BASE_RETRIES}" > "$file"
                else

                        local curr_value=`egrep -s "^[ \t]*AUTH_MAXTRIES[ \t]*=[ \t]*${BASE_RETRIES}" "$file"`
                        if [ -n "$curr_value" ]; then

                                return ${CODE_CONFORMITY}
                        else

                                curr_value=`egrep -s "^[ \t]*AUTH_MAXTRIES[ \t]*=[ \t]*[0-9]+" "$file" | awk -F'=' '{ print $2 }' | tail -n1`
                                if [ -f '/usr/sbin/ch_rc' ]; then

                                        ch_rc_bin='/usr/sbin/ch_rc'
                                        if [ -z "$curr_value" ]; then

                                                bkp_cmd=`$ch_rc_bin -r -p "AUTH_MAXTRIES" "$file"`
                                        else

                                                bkp_cmd=`$ch_rc_bin -a -p "AUTH_MAXTRIES=$curr_value" "$file"`
                                        fi

                                        backupFile "" "perm" "$bkp_cmd"
                                        $ch_rc_bin -a -p "AUTH_MAXTRIES=$BASE_RETRIES" "$file" 2>>$LOG >>$LOG
                                else

                                        backupFile "$file" "data"
                                        local temp_file=`mktemp /tmp/XXXXXXXXXXX`
                                        cat "$file" | sed "s/^[ \t]\{0,\}AUTH_MAXTRIES[ \t]\{1,\}.*/AUTH_MAXTRIES=$BASE_RETRIES/g" > "$temp_file"
                                        cat "$temp_file" > "$file"
                                        rm -f "$temp_file"
                                fi
                        fi
                fi
        else

                curr_value=`/usr/lbin/getprdef -m umaxlntr | awk -F'=' '{ print $2 }'`
                if [ -n "$curr_value" -a "$curr_value" = "$BASE_RETRIES" ]; then

                        return ${CODE_CONFORMITY}
                else

                        bkp_cmd=`/usr/lbin/modprdef -m umaxlntr=${curr_value}`
                        backupFile "" "perm" "$bkp_cmd"

                        /usr/lbin/modprdef -m umaxlntr=${BASE_RETRIES} 2>>$LOG >>$LOG
                        /usr/lbin/modprpw -V 2>>$LOG >>$LOG
                fi
        fi

        return ${CODE_OK}
}

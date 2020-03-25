#===  FUNCTION  ================================================================
#          NAME:  fix_mail_root
#   DESCRIPTION:  Set an email to handle all emails sent to root.
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure ; 77 = not defined on baseline
#===============================================================================

fix_mail_root () {

  [ -z "$BASE_MAILROOT" ] && {
    MISSED_VAR="BASE_MAILROOT"
    return $CODE_MISSED_VAR
  }

  file="/etc/mail/aliases"

  [ -f "$file" ] || {
    MISSED_FILE="$file"
    return $CODE_MISSED_FILE
  }

  conf=`sed -n "/^[ \t]\{0,\}root:.\{0,\}${BASE_MAILROOT}/p" $file 2>> "$LOGE"`
  [ -n "$conf" ] && return $CODE_CONFORMITY
#  grep "^root:[ \t]*${BASE_MAILROOT}" "$file" > /dev/null 2>> "$LOGE" && return $CODE_CONFORMITY

  backupFile "$file" "data"

  tmp_file=`mktemp /tmp/correction.XXXXXX 2>> "$LOGE"`

  sed "/root:/d" $file > $tmp_file 2>> "$LOGE"
  printf "root:\t\t${BASE_MAILROOT}\n\n" >> $tmp_file 2>> "$LOGE"

  cat $tmp_file > $file 2>> "$LOGE"

  rm $tmp_file 2>> "$LOGE"

}

#===  FUNCTION  ================================================================
#          NAME:  snmp_fix_managers
#   DESCRIPTION:  Set a host restriction to snmp communities.
#    PARAMETERS:  --
#       RETURNS: 0 = success ; 1 = failure ; 77 = not defined on baseline
#===============================================================================

snmp_fix_managers() {

   file=$1

  [ ! -f "$file" ] && {
    return $CODE_MISSED_FILE
  }

  [ -z "$BASE_SNMP_ALLOWED_HOSTS" ] && {
    echo "FAILURE: BASE_SNMP_ALLOWED_HOSTS variable is missed"
    return $CODE_MISSED_VAR
  }

    managers=`cat "$file" | grep "^[ \t]\{0,\}managers[ \t]\{1,\}" | sed 's/^[ \t]*managers[ \t]\{1,\}//g'`
    cat "$file" | grep "^[ \t]\{0,\}managers[ \t]\{1,\}" >> "$LOGF"

    vuln=0
    fiX_5=0


    #
    # We must first verify how many parts of snmp.conf are not according
    # to baseline. If there's at least one key with a wrong value, we'll 
    # backup the file and then we'll fix the file.
    #

    # Verify managers
    list1=`echo $managers | awk '{ for (i=1;i<=NF;i++) { print $i } }'|sort|uniq`
    list2=`echo $BASE_SNMP_ALLOWED_HOSTS | awk '{ for (i=1;i<=NF;i++) { print $i } }'|sort|uniq`
    if [ "$list1" != "$list2" ]; then 
        vuln=1
        fix_5=1
    fi


    if [ "$vuln" == "1" ]; then
        backupFile "$file" "data"
    else
        return $CODE_CONFORMITY
    fi

    # Fix managers
    [ "$fix_5" == "1" ] && {
        fix_file=`mktemp /tmp/.fix_snmp.XXXXXX 2>> "$LOGE"`
        cat "$file" | grep -v "^[ \t]*managers[ \t]\{1,\}" > "$fix_file" 2>> "$LOGE"
        echo "managers $BASE_SNMP_ALLOWED_HOSTS" >> "$fix_file" 2>> "$LOGE"
        [ -s "$fix_file" ] && cat "$fix_file" > "$file" 2>> "$LOGE"
        rm "$fix_file" 2>> "$LOGE"
    }

    return $CODE_OK 


}

#===  FUNCTION  ================================================================
#          NAME:  snmp_sma_fix_managers
#   DESCRIPTION:  Enable managers on communities.
#    PARAMETERS:  --
#===============================================================================
snmp_sma_fix_managers() {

  snmp_conf="/etc/sma/snmp/snmpd.conf"

  [  -f "$snmp_conf" ] || {
    return $CODE_MISSED_FILE
  }

  [ -z "${BASE_SNMP_ALLOWED_HOSTS}" ] && {
    echo "FAILURE: BASE_SNMP_ALLOWED_HOSTS variable is missed"
    return $CODE_MISSED_VAR
  }

  all_communities=`sed -n -e "/^[ \t]\{0,\}#/d" -e "/^[ \t]\{0,\}r[wo]community/p" $snmp_conf`
  vuln_communities=""

  # rocommunity: a SNMPv1/SNMPv2c read-only access community name
  #   arguments:  community [default|hostname|network/bits] [oid]

  # Looking for communities with invalid managers
  oldIFS=$IFS
  IFS="
"
  for community in $all_communities; do
    name=`printf "$community" | awk '{ print $2 }'`
    source=`printf "$community" | awk '{ print $3 }'`
    address=`printf "$source" | awk -F"/" '{ print $1 }'`
    netmask=`printf "$source" | awk -F"/" '{ print $2 }'`
 
    # Address not found on baseline.
    printf "$BASE_SNMP_ALLOWED_HOSTS" | grep -q "$address" || {
      if [ -z "$vuln_communities" ]; then
        vuln_communities="$community"
      else
        vuln_communities="$vuln_communities
$community"
      fi
      continue
    }

    # No manager configured
    [ -z "$address" ] || [ "$address" = "default" ] && {
      if [ -z "$vuln_communities" ]; then
        vuln_communities="$community"
      else
        vuln_communities="$vuln_communities
$community"
      fi
      continue
    }

    # Manager configured as network.
    [ -n "$netmask" ] && [ "$netmask" != "32" ] && {
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
    IFS="
"
    for community in $vuln_communities; do
      cmd_suffixes="$cmd_suffixes -e 's:^\\($community\):#\\1:'"
    done
    IFS=$oldIFS

    tmp_file=`mktemp /tmp/tmp.XXXXXX`
    eval "sed $cmd_suffixes $snmp_conf > $tmp_file"
    cat $tmp_file > $snmp_conf
    rm $tmp_file
  }

  missing_comm_managers=""

  # Looking for managers not configured on available communities.
  # At this point we have communities with manager as hosts only.

  # Retrieving community names
  community_names=`printf "$all_communities" | awk '{ print $2 }' | sort -u`

  for comm_name in $community_names; do
    managers=`awk -v name="$comm_name" '$1 ~ /r[w|o]community/ && $2 == name { print $3 }' $snmp_conf`

    for manager in $BASE_SNMP_ALLOWED_HOSTS; do
      printf "$managers" | grep -q "$manager" || {
        if [ -z "$missing_comm_managers" ]; then
          missing_comm_managers="$comm_name $manager"
        else
          missing_comm_managers="$missing_comm_managers
$comm_name $manager"
        fi
      }
    done
  done

  [ -z "$vuln_communities" ] && [ -z "$missing_comm_managers" ] && return $CODE_CONFORMITY
  [ -n "$vuln_communities" ] && [ -z "$missing_comm_managers" ] && return $CODE_OK

  # Adding missing managers on available communities.
  [ -z "$vuln_communities" ] && backupFile "$snmp_conf" "data"
 
  oldIFS=$IFS
  IFS="
"
  for missing in $missing_comm_managers; do
    echo "rocommunity $missing" >> $snmp_conf
  done
  IFS=$oldIFS

  return $CODE_OK
}

#===  FUNCTION  ================================================================
#          NAME:  snmp_fix_default_communities
#   DESCRIPTION:  Replace default public and private communities for communnity
#		  previously define on the baseline.
#    PARAMETERS:  --
#===============================================================================
snmp_fix_default_communities () {

  #file="/etc/snmp/conf/snmpd.conf"

  file=$1

  [ -f "$file" ] || {
    #echo "FAILURE: Target $file is missed"
    return $CODE_MISSED_FILE
  }


  [ -z "$BASE_SNMP_READ_COMMUNITY" ] && {
    echo "FAILURE: BASE_SNMP_READ_COMMUNITY variable is missed"
    return $CODE_MISSED_VAR
  }
  
  [ -z "$BASE_SNMP_WRITE_COMMUNITY" ] && {
    echo "FAILURE: BASE_SNMP_WRITE_COMMUNITY variable is missed"
    return $CODE_MISSED_VAR
  }
  
  sys_grp_read_com=`cat "$file" | grep "^[ \t]\{0,\}system-group-read-community[ \t]\{1,\}"  | awk '{ print $2 }'`
  sys_grp_write_com=`cat "$file" | grep "^[ \t]\{0,\}system-group-write-community[ \t]\{1,\}" | awk '{ print $2 }'`
  read_com=`cat "$file" | grep "^[ \t]\{0,\}read-community[ \t]\{1,\}"  | awk '{ print $2 }'`
  write_com=`cat "$file" | grep "^[ \t]\{0,\}write-community[ \t]\{1,\}" | awk '{ print $2 }'`

  vuln=0
  fix_1=0
  fix_2=0
  fix_3=0
  fix_4=0

  #
  # We must first verify how many parts of snmp.conf are not according
  # to baseline. If there's at least one key with a wrong value, we'll 
  # backup the file and then we'll fix the file.
  #

  # If system-group-read-community is not ok, fix it
  vuln_sysread_comm=""
  oldIFS=$IFS
  IFS="
"
  for community in $sys_grp_read_com; do
    echo "$BASE_SNMP_READ_COMMUNITY" | grep -q "$community" || {
      if [ -z "$BASE_SNMP_READ_COMMUNITY" ]; then
        vuln_sysread_comm="$community"
      else
        vuln_sysread_comm="$vuln_sysread_comm
$community"
      fi
    }
  done
  IFS=$oldIFS

  if [ -z "$sys_grp_read_com" ] || [ -n "$vuln_sysread_comm" ]; then 
      vuln=1
      fix_1=1
  fi

  # If system-group-write-community is not ok, fix it
  vuln_syswrite_comm=""
  oldIFS=$IFS
  IFS="
"
  for community in $sys_grp_write_com; do
    echo "$BASE_SNMP_READ_COMMUNITY" | grep -q "$community" || {
      if [ -z "$BASE_SNMP_READ_COMMUNITY" ]; then
        vuln_syswrite_comm="$community"
      else
        vuln_syswrite_comm="$vuln_syswrite_comm
$community"
        fi
    }
  done
  IFS=$oldIFS

  if [ -z "$sys_grp_write_com" ] || [ -n "$vuln_syswrite_comm" ]; then 
      vuln=1
      fix_2=1
  fi

  # If read-community is not ok, fix it
  vuln_read_comm=""
  oldIFS=$IFS
  IFS="
"
  for community in $read_com; do
    echo "$BASE_SNMP_READ_COMMUNITY" | grep -q "$community" || {
      if [ -z "$BASE_SNMP_READ_COMMUNITY" ]; then
        vuln_read_comm="$community"
      else
        vuln_read_comm="$vuln_read_comm
$community"
      fi
    }
  done
  IFS=$oldIFS

  if [ -z "$read_com" ] || [ "$vuln_read_comm" ]; then 
      vuln=1
      fix_3=1
  fi

  # If write-community is not ok, fix it
  vuln_write_comm=""
  oldIFS=$IFS
  IFS="
"
  for community in $write_com; do
    echo "$BASE_SNMP_READ_COMMUNITY" | grep -q "$community" || {
      if [ -z "$BASE_SNMP_READ_COMMUNITY" ]; then
        vuln_write_comm="$community"
      else
        vuln_write_comm="$vuln_write_comm
$community"
        fi
    }
  done
  IFS=$oldIFS

  if [ -z "$write_com" ] || [ -n "$vuln_write_comm" ]; then 
      vuln=1
      fix_4=1
  fi

  if [ "$vuln" == "1" ]; then
      backupFile "$file" "data"
  else
      return $CODE_CONFORMITY
  fi

  # Fix system-group-read-community
  [ "$fix_1" == "1" ] && {
      fix_file=`mktemp /tmp/.fix_snmp.XXXXXX 2>> "$LOGE"`
      cat "$file" | grep -v "^[ \t]*system-group-read-community[ \t]\{1,\}" > "$fix_file" 2>> "$LOGE"
      for community in $BASE_SNMP_READ_COMMUNITY; do
        echo "system-group-read-community $community" >> "$fix_file" 2>> "$LOGE"
      done
      [ -s "$fix_file" ] && cat "$fix_file" > "$file" 2>> "$LOGE"
      rm "$fix_file"     2>> "$LOGE"
  }

  # Fix system-group-write-community
  [ "$fix_2" == "1" ] && {
      fix_file=`mktemp /tmp/.fix_snmp.XXXXXX 2>> "$LOGE"`
      cat "$file" | grep -v "^[ \t]*system-group-write-community[ \t]\{1,\}" > "$fix_file" 2>> "$LOGE"
      for community in $BASE_SNMP_WRITE_COMMUNITY; do
        echo "system-group-write-community $community" >> "$fix_file" 2>> "$LOGE"
      done
      [ -s "$fix_file" ] && cat "$fix_file" > "$file" 2>> "$LOGE"
      rm "$fix_file"    
  }

  # Fix read-community
  [ "$fix_3" == "1" ] && {
      fix_file=`mktemp /tmp/.fix_snmp.XXXXXX 2>> "$LOGE"`
      cat "$file" | grep -v "^[ \t]*read-community[ \t]\{1,\}" > "$fix_file" 2>> "$LOGE"
      for community in $BASE_SNMP_READ_COMMUNITY; do
        echo "read-community $community" >> "$fix_file" 2>> "$LOGE"
      done
      [ -s "$fix_file" ] && cat "$fix_file" > "$file" 2>> "$LOGE"
      rm "$fix_file"    
  }

  # Fix write-community
  [ "$fix_4" == "1" ] && {
      fix_file=`mktemp /tmp/.fix_snmp.XXXXXX 2>> "$LOGE"`
      cat "$file" | grep -v "^[ \t]*write-community[ \t]\{1,\}" > "$fix_file" 2>> "$LOGE"
      for community in $BASE_SNMP_WRITE_COMMUNITY; do
        echo "write-community $community" >> "$fix_file" 2>> "$LOGE"
      done
      [ -s "$fix_file" ] && cat "$fix_file" > "$file" 2>> "$LOGE"
      rm "$fix_file" 2>> "$LOGE"
  }

  return $CODE_OK
  
}

#===  FUNCTION  ================================================================
#          NAME:  snmp_sma_fix_default_communities
#   DESCRIPTION:  Replace default public and private communities for communnity
#		  previously define on the baseline.
#    PARAMETERS:  --
#===============================================================================
snmp_sma_fix_default_communities () {

  # rocommunity: a SNMPv1/SNMPv2c read-only access community name
  #   arguments:  community [default|hostname|network/bits] [oid]
   
  local snmp_conf
  local all_communities
  local vuln_communities
  local name
  local cmd_suffixes
  local tmp_file

  snmp_conf="/etc/sma/snmp/snmpd.conf"

  [  -f "$snmp_conf" ] || {
    #echo "FAILURE: TARGET $snmp_conf is missed"
    MISSED_FILE="$snmp_conf"
    return $CODE_MISSED_FILE
  }

  # If BASE_SNMP_COMMUNITY is not setted, then comment only public or private community and
  #   do not add any community.
  # Otherwise, look at BASE_SNMP_COMMUNITY baseline variable for valid communities names and
  #   add the missing communities on snmp configuration file.
  base_exists=`set | grep "BASE_SNMP_COMMUNITY="`

  [ -z "${base_exists}" ] && {
    echo "FAILURE: BASE_SNMP_COMMUNITY variable is missed"
    return $CODE_MISSED_VAR
  }

  all_communities=`sed -n -e "/^[ \t]\{0,\}#/d" -e "/^[ \t]\{0,\}r[ow]community/p" $snmp_conf`
  vuln_communities=""

  # For each community found check if it is in accordance with specified baseline.
  oldIFS=$IFS
  IFS="
"
  for community in $all_communities; do
    name=`printf "$community" | awk '{ print $2 }'`
    perm=`printf "$community" | awk '{ print $1 }'`

    [ -z "$name"] || [ -z "$perm" ] && continue

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
  #

  do_not_backup=""

  # If communities are not present on baseline definition is found, comment them.
  [ -n "$vuln_communities" ] && {
    backupFile "$snmp_conf" "data"
    do_not_backup="true"

    # Building sed command to comment all vulnerable communities.
    cmd_suffixes=""
    oldIFS=$IFS
    IFS="
"
    for community in $vuln_communities; do
      cmd_suffixes="$cmd_suffixes -e 's:^\\($community\):#\\1:'"
    done
    IFS=$oldIFS

    tmp_file=`mktemp /tmp/tmp.XXXXXX`
    eval "sed $cmd_suffixes $snmp_conf > $tmp_file"
    cat $tmp_file > $snmp_conf
    rm $tmp_file
  }
  #

  [ -z "${base_exists}" ] && [ -z "$vuln_communities" ] && return $CODE_CONFORMITY
  [ -z "${base_exists}" ] && [ -n "$vuln_communities" ] && return $CODE_OK

  missing_communities=""

  # Looking for communities specified on baseline and not present on snmpd file.
  for community in $BASE_SNMP_COMMUNITY; do
    found=`sed -n "/^[ \t]\{0,\}r[w|o]community[ \t]\{1,\}$community/p" $snmp_conf`
    [ -z "$found" ] &&  {
      if [ -z "$missing_communities" ]; then
        missing_communities="$community"
      else
        missing_communities="$missing_communities
$community"
      fi
    }
  done
  #

  [ -z "${missing_communities}" ] && [ -z "$vuln_communities" ] && return $CODE_CONFORMITY
  [ -z "${missing_communities}" ] && [ -n "$vuln_communities" ] && return $CODE_OK

  [ -z "$do_not_backup" ] && backupFile "$snmp_conf" "data"

  # Adding missing communities do snmpd configuration file.
  oldIFS=$IFS
  IFS="
"
  for community in $missing_communities; do
    echo "rocommunity ${community}" >> $snmp_conf
  done
  IFS=$oldIFS

  return $CODE_OK

}

#===  FUNCTION  ================================================================
#          NAME:  fix_variable_configuration 
#   DESCRIPTION:  Change the variable's value from a text file.
#		  The variable's format must be VARIABLE=VALUE
#    PARAMETERS:  $1 => Variable name.
#		  $2 => Value to be change.
#		  $3 => Target file.
#       RETURNS:  0 = succes ; 1 = failure ; 34 = configuration file not found.
#		  33 = baseline not defined
#===============================================================================

fix_variable_configuration () {

  [ $# -lt 3 ] && {
    [ $verbosity ] && echo "Not enough parameters when calling fix_variable_configuration"
    echo "Not enough parameters when calling fix_variable_configuration" >> "$LOGF"
    return $CODE_ERROR 
  }

  variable_name=$1
  new_value=$2
  file=$3
  is_writable="no"

  [ ! -f $file ] && {
    MISSED_FILE="$file"
    return $CODE_MISSED_FILE
  }

  [ -z "$new_value" ] && {
    return $CODE_MISSED_VAR 
  }

  [ -w $file ] && is_writable="yes"

  nconf=`grep -c "^[ \t]*${variable_name}=" $file 2>> "$LOGE"`

  #If there is more than one [variable_name] option in the file, delet all
  #[variable_name] options and add a new one with the baseline value.
  [ $nconf -gt 1 ] && {

    tmp_file=`mktemp /tmp/correction.XXXXXX 2>> "$LOGE"`
    sed "/^[ \t]\{0,\}[^#]\{0,\}[ \t]\{0,\}${variable_name}[ \t]\{0,\}=.*$/d" $file > $tmp_file 2>> "$LOGE"

    echo "${variable_name}=${new_value}" >> $tmp_file 2>> "$LOGE"

    [ "$is_writable" = "no" ] && chmod +w $file 2>> "$LOGE"
    cat $tmp_file > $file 2>> "$LOGE"
    [ "$is_writable" = "no" ] && chmod -w $file 2>> "$LOGE"

    rm $tmp_file "$LOGE"

    return $CODE_OK 

  }

  #Already in accordance with baseline
  baseline_accordance=`grep -c "^[ \t]\{0,\}${variable_name}[ \t]\{0,\}=[ \t]\{0,\}${new_value}$" $file 2>> "$LOGE"`
  [ $baseline_accordance -ge 1 ] && return $CODE_CONFORMITY 

  #There is only one [variable_name] configuration and it's not in accordance with the baseline
  [ $nconf -eq 1 ] && {

    tmp_file=`mktemp /tmp/correction.XXXXXX 2>> "$LOGE"`
    sed "s/^[ \t]\{0,\}[^#]\{0,\}${variable_name}[ \t]\{0,\}=.*/${variable_name}=${new_value}/" $file > $tmp_file 2>> "$LOGE"

    [ "$is_writable" = "no" ] && chmod +w $file 2>> "$LOGE"
    cat $tmp_file > $file 2>> "$LOGE"
    [ "$is_writable" = "no" ] && chmod -w $file 2>> "$LOGE"

    rm $tmp_file 2>> "$LOGE"

    return $CODE_OK 

  }

  #Adding [variable_name]=[new_value] if it not exists
    
  [ $nconf -eq 0 ] && {

    [ "$is_writable" = "no" ] && chmod +w $file 2>> "$LOGE"
    echo "${variable_name}=${new_value}" >> $file 2>> "$LOGE"
    [ "$is_writable" = "no" ] && chmod -w $file 2>> "$LOGE"

    return $CODE_OK 

  }

  return $CODE_ERROR

}

is_solaris10 () {

  solaris_name=`uname | awk '{ print $1 }' 2>> "$LOGE"`
  solaris_version=`uname -a | awk '{ print $3 }' | sed -n 's/[0-9]\.\([0-9]\{1,\}\)/\1/p' 2>> "$LOGE"`

  [ "$solaris_name" != "SunOS" ] || [ "$solaris_version" != "10" ] && {
    echo "false"
    return $CODE_OK
  }

  echo "true"
  return $CODE_OK

}

solaris10_smallzone_shared_dirs () {

  [ "`is_solaris10`" = "false" ] && return $CODE_OK

  cat /etc/mnttab | grep lofs | grep -w ro | awk ' $1 == $2 { print $1 }' 2>> "$LOGE"
  return

}

solaris10_is_smallzone () {

  [ "`is_solaris10`" = "false" ] && {
    echo "false"
    return $CODE_OK
  }

  zoneadm list -vc | grep running | awk '{ print $2 }' | grep global > "/dev/null" 2>> "$LOGE"

  [ $? -eq $CODE_OK ] && {
    echo "false"
    unset solaris_version solaris_name
    return $CODE_OK 
  }

  shared_dirs=`solaris10_smallzone_shared_dirs`

  [ -n "$shared_dirs" ] && {
    echo "true"
    unset solaris_version solaris_name
    return $CODE_OK
  }

  echo "false"
  unset solaris_version solaris_name
  return $CODE_OK 

}


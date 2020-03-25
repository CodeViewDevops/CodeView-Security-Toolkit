#===============================================================================
#
#          FILE:  include.sh
# 
#         USAGE:  -- 
# 
#   DESCRIPTION: Provides a set of vulnerability fix functions for AIX.
# 
#===============================================================================

#===  FUNCTION  ================================================================
#          NAME:  expand_community_parameters 
#   DESCRIPTION:  Parse all comminuty parameters, normalizing it based on 
#		  default values.
#    PARAMETERS:  --
#===============================================================================
expand_community_parameters () {

  # 2. Set the community names and access privileges for hosts that can make
  #    requests of this snmpd agent.  Define these restrictions as follows:
  #
  #       community  <name>  <address>  <netmask>  <permissions>  <view name>
  #
  #    where <name> is the community name, <address> is either a hostname or
  #    an IP address in dotted notation, and <permissions> is one of:  none,
  #    readOnly, writeOnly, readWrite.  The default permission is readOnly.
  #    <netmask> specifies the network mask.  The default address and netmask
  #    are 0.0.0.0.  If an address other than 0.0.0.0 is specified, the default
  #    netmask is 255.255.255.255.  If a permission is specified, both the
  #    address and netmask must also be specified.  <view name> defines a
  #    portion of the MIB tree to which this community name allows access.
  #    <view name> must be defined as a unique object identifier in dotted
  #    numeric notation.  <view name> is further defined in the view
  #    configuration entry.  If <view name> is not specified, the view for
  #    this community defaults to the entire MIB tree.  Fields to the right
  #    of <name> are optional, with the limitation that no fields to the
  #    left of a specified field are omitted.
  #
  # community <name> 0.0.0.0 0.0.0.0 readOnly
  # community <name> <address> 255.255.255.255 readOnly
  # community <name> <address> <netmask> readOnly
  # community <name> <address> <netmask> <permission>
  # community <name> <address> <netmask> <permission> <view name>
  #
  # Examples:
  #  community       public
  #  community       private 127.0.0.1 255.255.255.255 readWrite
  #  community       system  127.0.0.1 255.255.255.255 readWrite 1.17.2


  [ $# -lt 1 ] && return $CODE_ERROR

  local defaultPerm
  local defaultAddress
  local defaultNetMask
  local defaultNetMask
  local community
  local validation
  local nparams

  # Default access privileges.
  defaultPerm="readOnly"
  defaultAddress="0.0.0.0"
  defaultNetMask="0.0.0.0"
  defaultNetMaskIfAddress="255.255.255.255"

  community=$1

  validation=`printf "$community" | sed -n "/^[ \t]\{0,\}community/p"`
  [ -z "$validation" ] && return $CODE_ERROR

  nparams=`printf "$community" | awk '{ print NF }'`
 
  case "$nparams" in
    2) 
      # community <name> 0.0.0.0 0.0.0.0 readOnly
      echo "$community $defaultAddress $defaultNetMask $defaultPerm"
      ;;
    3)
      # community <name> <address> 255.255.255.255 readOnly
      echo "$community $defaultNetMaskIfAddress $defaultPerm"
      ;;
    4) 
      # community <name> <address> <netmask> readOnly
      echo "$community $defaultPerm"
      ;;
    5|6)
      # community <name> <address> <netmask> <permission>
      # community <name> <address> <netmask> <permission> <view name>
      echo "$community"
      ;;
    *) ;;
  esac

  return $CODE_OK

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
  local release_number
  local os_version

  release_number=`uname -r`
  os_version= `uname -v`

  if [ $os_version -lt 5 ] || [ $os_version -eq 5 -a $release_number -lt 2 ]; then
    snmp_conf="/etc/snmpd.conf"
  else
    snmp_conf="/etc/snmpdv3.conf"
  fi

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

  all_communities=`sed -n -e "/^[ \t]\{0,\}#/d" -e "/^[ \t]\{0,\}community/p" $snmp_conf`
  vuln_communities=""

  # For each community found check if it is in accordance with specified baseline.
  oldIFS=$IFS
  IFS="
"
  for community in $all_communities; do
    expanded_community=`expand_community_parameters "$community"`
    name=`printf "$expanded_community" | awk '{ print $2 }'`
    perm=`printf "$expanded_community" | awk '{ print $5 }'`

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
      cmd_suffixes="$cmd_suffixes -e 's/^\\($community\)/#\\1/'"
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
    found=`sed -n "/^[ \t]\{0,\}community[ \t]\{1,\}$community/p" $snmp_conf`
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
    echo "community ${community}" >> $snmp_conf
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

  local release_number
  local os_version

  release_number=`uname -r`
  os_version= `uname -v`

  if [ $os_version -lt 5 ] || [ $os_version -eq 5 -a $release_number -lt 2 ]; then
    snmp_conf="/etc/snmpd.conf"
  else
    snmp_conf="/etc/snmpdv3.conf"
  fi

  [  -f "$snmp_conf" ] || {
    MISSED_FILE="$snmp_conf"
    return $CODE_MISSED_FILE
  }

  [ -z "${BASE_SNMP_ALLOWED_HOSTS}" ] && {
    MISSED_VAR="BASE_SNMP_ALLOWED_HOSTS"
    return $CODE_MISSED_VAR
  }

  all_communities=`sed -n -e "/^[ \t]\{0,\}#/d" -e "/^[ \t]\{0,\}community/p" $snmp_conf`
  vuln_communities=""

  # Looking for communities with invalid managers
  oldIFS=$IFS
  IFS="
"
  for community in $all_communities; do
    expanded_community=`expand_community_parameters "$community"`
    name=`printf "$expanded_community" | awk '{ print $2 }'`
    address=`printf "$expanded_community" | awk '{ print $3 }'`
    netmask=`printf "$expanded_community" | awk '{ print $4 }'`
 
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

    # Manager configured as network.
    [ "$netmask" != "255.255.255.255" ] && {
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
      cmd_suffixes="$cmd_suffixes -e 's/^\\($community\)/#\\1/'"
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
    managers=`awk -v name="$comm_name" '$1 == "community" && $2 == name { print $3 }' $snmp_conf`

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
    echo "community $missing" >> $snmp_conf
  done
  IFS=$oldIFS

  return $CODE_OK
}

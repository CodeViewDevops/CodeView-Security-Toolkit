#!/bin/sh

#===  FUNCTION  ================================================================
#          NAME:  setPerm 
#   DESCRIPTION:  Set file or directory permission.
#    PARAMETERS:  $1 = target file path
#		  $2 = permission (using chmod syntax)
#       RETURNS:  CODE_OK = success ; CODE_ERROR = failure
#===============================================================================
setPerm() {

  [ $# -lt 2 ] && return 1

  file="$1"
  perm="$2"
  cmd="chmod $perm $file"

  $cmd 2>> /dev/null 
  echo "$cmd returned status $?" >> "$LOG" 
        
  [ $? -eq 0 ] && return $CODE_OK

  return $CODE_ERROR
      
} 


#===  FUNCTION  ================================================================
#          NAME:  setPerm 
#   DESCRIPTION:  Set file or directory permission.
#    PARAMETERS:  - 
#       RETURNS:  CODE_OK = success ; CODE_ERROR = failure
#                 CODE_CONFORMITY = fix is no necessary 
#===============================================================================
setLogPerm() {

  files=`find /var/log/* /var/adm/* -prune -type f \( -perm -g=w -o -perm -o=w -o -perm -o=r \) 2> /dev/null | grep -v "[uw]tmp[xs]*" 2>> /dev/null`
  dirs=`find /var/log/* /var/adm/* -prune -type d \( -perm -g=w -o -perm -o=w -o -perm -o=r \) 2>> /dev/null`
  [ -n "$dirs" ] && files=`printf "%s\n%s\n" "$files" "$dirs" 2>> /dev/null`

  extra_files=""
  case "`uname 2>> /dev/null`" in
    "Linux")
        extra_perm=640
	extra_files=`find /var/{adm,log}/{b,u,w}tmp{x,s,}* -type f \( -perm -g=w -o -perm -o=r -o -perm -o=w \) 2>> /dev/null`
      ;;

    "SunOS")
        extra_perm=644
	extra_files=`find /var/adm/[buw]tmp[xs]* /var/log/[buw]tmp[xs]* -type f \( -perm -g=w -o -perm -o=w \) 2>> /dev/null`
      ;;

    "AIX")
        extra_perm=640
	extra_files=`find /var/adm/[buw]tmp* /var/log/[buw]tmp* -type f \( -perm -g=w -o -perm -o=r -o -perm -o=w \) 2>> /dev/null`
      ;;

    "HP-UX")
        extra_perm=640
	extra_files=`find /var/{adm,log}/{b,u,w}tmp{x,s,}* -type f \( -perm -g=w -o -perm -o=r -o -perm -o=w \) 2>> /dev/null`
      ;;
  esac
  
  [ -z "$files" ] && [ -z "$extra_files" ] && return $CODE_CONFORMITY 

  for f in $files; do
    if [ -d "$f" ]; then 
      setPerm "$f" "0750" || return $CODE_ERROR
    else
      setPerm "$f" "0640" || return $CODE_ERROR
    fi
  done

  for f in $extra_files; do
    setPerm "$f" "$extra_perm" || return $CODE_ERROR
  done
  return 0
}

#===  FUNCTION  ================================================================
#          NAME:  fix_perms_on_audit_files
#   DESCRIPTION:  Prevents audit files to be created with wrong permissions.
#    PARAMETERS:  - 
#       RETURNS:  CODE_OK = success ; CODE_ERROR = failure ; 
#                 CODE_CONFORMITY = fix is no necessary 
#===============================================================================
fix_perms_on_audit_files () {

  audit_dir="/etc/logrotate.d"

  [ ! -d $audit_dir ] && {
    return $CODE_ERROR 
  }

  audit_files=`grep create ${audit_dir}/* | grep -v 60 | cut -d: -f1 | sort -u 2>> /dev/null`

  [ -z "$audit_files" ] && return $CODE_CONFORMITY

  for file in $audit_files; do


    tmp_file=`mktemp /tmp/XXXXXX 2>> /dev/null`

    if [ "$file" = "/etc/logrotate.conf" ]; then

      targets=`sed -n -e '/{/,/}/ { /^\//h; /create/{g; s:^\(/[^ \t]\{1,\}\)[ \t]\{0,\} {:\1:p;} }' $file`
      printf "Modifying file $file: $targets \n" >> "$LOG"

      tmp_file1=`mktemp /tmp/XXXXXX 2>> /dev/null`

      sed "/wtmp.\{0,\}{/,/}/ { s/\(create[ \t]\{1,1\}\)[0-9]\{1,\}\(.*\)/\10640\2/ }" $file > $tmp_file 2>>  /dev/null
      sed "/wtmp.\{0,\}{/,/}/! { s/\(create[ \t]\{1,1\}\)[0-9]\{1,\}\(.*\)/\10600\2/ }" $tmp_file > $tmp_file1 2>> /dev/null 
      cat $tmp_file1 > $file 2>> /dev/null 
      rm $tmp_file $tmp_file1 2>> /dev/null 

    else

      sed "s/\(create[ \t]\{1,1\}\)[0-9]\{1,\}\(.*\)/\10600\2/" $file > $tmp_file 2>> /dev/null
      cat $tmp_file > $file 2>> /dev/null 
      rm $tmp_file 2>> /dev/null 

     fi
  done

  return $CODE_OK 
}

#===  FUNCTION  ================================================================
#          NAME:  aix_fix_perms_on_audit_files
#   DESCRIPTION:  Prevents audit files to be created with wrong permissions.
#    PARAMETERS:  - 
#       RETURNS:  CODE_OK = success ; CODE_ERROR = failure ; 
#                 CODE_CONFORMITY = fix is no necessary 
#===============================================================================
aix_fix_perms_on_audit_files () {
  setLogPerm
  return $?
}

#===  FUNCTION  ================================================================
#          NAME:  hpux_fix_perms_on_audit_files
#   DESCRIPTION:  Prevents audit files to be created with wrong permissions.
#    PARAMETERS:  - 
#       RETURNS:  CODE_OK = success ; CODE_ERROR = failure ; 
#                 CODE_CONFORMITY = fix is no necessary 
#===============================================================================
hpux_fix_perms_on_audit_files () {
  setLogPerm
  return $?
}

#===  FUNCTION  ================================================================
#          NAME:  sunos_perms_on_audit_files
#   DESCRIPTION:  Prevents audit files to be created with wrong permissions.
#    PARAMETERS:  - 
#       RETURNS:  CODE_OK = success ; CODE_ERROR = failure ; 
#                 CODE_CONFORMITY = fix is no necessary 
#===============================================================================
sunos_fix_perms_on_audit_files () {
  setLogPerm
  return $?
}

#===  FUNCTION  ================================================================
#          NAME:  linux_perms_on_audit_files
#   DESCRIPTION:  Prevents audit files to be created with wrong permissions.
#    PARAMETERS:  - 
#       RETURNS:  CODE_OK = success ; CODE_ERROR = failure ; 
#                 CODE_CONFORMITY = fix is no necessary 
#===============================================================================
linux_fix_perms_on_audit_files () {
  fix_perms_on_audit_files
  setLogPerm
}

#=== GLOBAL VARIABLES  ================================================================
CODE_OK=0
CODE_ERROR=1
CODE_CONFORMITY=55
LOG_DIR="/var/security/fix_audit_files/"
LOG="$LOG_DIR/`date | sed 's/ /_/g'`"

#=== MAIN  ================================================================
cd /tmp
system=`uname 2>> /dev/null | tr '[:upper:]' '[:lower:]' | sed 's/-//g'`
[ -n "$system" ] && {
  [ ! -d "$LOG_DIR" ] && mkdir -p $LOG_DIR && touch "$LOG"
  eval "${system}_fix_perms_on_audit_files"
}

#!/bin/sh

TOOL_PATH=`dirname $0`
is_absolute_path=`printf "$CODEVIEW_PATH" | sed -n "/^\//p"`
[ -z "$is_absolute_path" ] && TOOL_PATH=`pwd`/$TOOL_PATH

SESSIONS_PATH=$TOOL_PATH/sessions
GROUPS_PATH=$TOOL_PATH/groups
ACTION="rm"

##########################################################
#
#
#
##########################################################
is_root() {

  user_id=`id | sed -n "s/^uid=\([0-9]\{1,\}\)(.\{1,\}$/\1/p"`

  [ "$user_id" = "0" ] && return 0

  return 1

}



##########################################################
#
#
#
##########################################################
create_dirs() {

  [ $# -ne 2 ] && return 1
  [ -z "$1" ] || [ -z "$2" ] && return 1

  group_path=$1
  sessions_path=$2

  [ ! -d "$group_path" ] && mkdir $group_path
  [ ! -d "$sessions_path" ] && mkdir $sessions_path

  return 0

}

##########################################################
#
#
#
##########################################################
load_files() {

  [ $# -ne 2 ] && return 1
  [ -z "$1" ] && return 1

  group_path=$1
  session_log=$2
  files=""

  for group_file in `ls $group_path 2>> "$session_log"`; do
    group=`printf "$group_file\n" | sed "s/\.[a-zA-Z]\{1,\}$//"`
    for file in `cat $group_path/$group_file 2>> "$session_log"`; do
      [ -f "$file" ] && {
        has_sid=`find $file \( -perm -4000 -o -perm -2000 \) -type f 2>> "$session_log"`
        [ -n "$has_sid" ] && {
          perm=`ls -dl $file 2>> "$session_log" | sed -n "s/.\{0,\}\([-d]\{1\}[-rwxtsS]\{9\}\).\{1,\}/\1/p"`
          fields="$group:$file:$perm"
          if [ -z "$files" ]; then
            files="$fields"
          else
            files="$files\n$fields"
          fi
        }
      }
    done
  done

  printf "$files\n"

  return 0

}

##########################################################
#
#
#
##########################################################
session_load_files() {
  [ $# -ne 2 ] && return 1
  [ -z "$1" ] && return 1

  group_path=$1
  session_log=$2
  files=""

  for group in `ls $group_path 2>> "$session_log"`; do
    group_name=`basename "$group"`
    for file_fields in `cat $group 2>> "$session_log"`; do
      file=`printf "$file_fields\n" | awk -F":" '{print $1}'`
      perm=`printf "$file_fields\n" | awk -F":" '{print $2}'`
      if [ -f "$file" ]; then
        fields="$group_name:$file:$perm"
        if [ -z "$files" ]; then
          files="$fields"
        else
          files="$files\n$fields"
        fi
      else
        log "* There is no such file $file" "$session_log" 
      fi
    done
  done

  printf "$files\n"

  return 0

}

##########################################################
#
#
#
##########################################################
session_show() {
  [ $# -ne 1 ] && return 1
  [ -z "$1" ] && return 1

  group_path=$1

  for group in `ls $group_path`; do
    printf "  * Group: $group\n"
    for file_fields in `cat $group_path/$group`; do
      file=`printf "$file_fields\n" | awk -F":" '{print $1}'`
      perm=`printf "$file_fields\n" | awk -F":" '{print $2}'`
      printf "    * File: $file ($perm)\n"
    done
  done

  return 0

}

##########################################################
#
#
#
##########################################################
session_create() {

  [ $# -ne 1 ] && return 1

  sessions_path=$1

  [ ! -d "$sessions_path" ] && return 1

  session_id=`date '+%Y%m%d%H%M%S'`

  mkdir $sessions_path/$session_id || return 1
  mkdir $sessions_path/$session_id/groups || return 1

  session_log="$sessions_path/$session_id/session.log"
  touch $sessions_path/$session_id/session.log && chmod 0400 $sessions_path/$session_id/session.log

  printf "$session_id:$session_log\n"

  return 0

}

##########################################################
#
#
#
##########################################################
session_get() {
  [ $# -ne 2 ] && return 1

  sessions_path=$1
  session_id=$2
  session_path=$sessions_path/$session_id

  [ ! -d "$sessions_path" ] && {
    log_cli "* Session directory not found." 
    return 1
  }
}

##########################################################
#
#
#
##########################################################
session_add() {

  [ $# -ne 5 ] && return 1

  file=$1
  perm=$2
  group=$3
  sessions_path=$4
  session_id=$5

  group_path=$sessions_path/$session_id/groups

  [ ! -d "$group_path" ] && return 1

  [ ! -f "$group_path/$group" ] && {
    touch $group_path/$group
    chmod 0400 $group_path/$group
  }

  printf "$file:$perm\n" >> $group_path/$group

}


##########################################################
#
#
#
##########################################################
remove_sids_from() {

  [ $# -ne 4 ] && return 1

  targets=$1
  sessions_path=$2
  session_id=$3
  session_log=$4

  for target in $targets; do
    group=`echo $target | awk -F":" '{print $1}'`
    file=`echo $target | awk -F":" '{print $2}'`
    perm=`echo $target | awk -F":" '{print $3}'`

    log "  * $file in group $group." "$session_log" 

    [ -f "$file" ] && {
      chmod -s $file 2>> "$session_log" && session_add "$file" "$perm" "$group" "$sessions_path" "$session_id"
    }
  done

  return 0
}

##########################################################
#
#
#
##########################################################
restore() {

  [ $# -ne 4 ] && return 1

  targets=$1
  sessions_path=$2
  session_id=$3
  session_log=$4

  for target in $targets; do
    group=`echo $target | awk -F":" '{print $1}'`
    file=`echo $target | awk -F":" '{print $2}'`
    perm=`echo $target | awk -F":" '{print $3}'`

    log "  * $file in group $group to $perm." "$session_log" 

    [ -f "$file" ] && {
      restore_perm "$file" "$perm" "$session_log"
    }
  done

  return 0
}


##########################################################
#
#
#
##########################################################
restore_perm() {

  [ $# -ne 3 ] && return 1

  file=$1
  perm=$2
  session_log=$3

  cmd=`echo "" | awk -vF=$file -vP=$perm '
  BEGIN { "uname -s" | getline OS }

  {
    U=substr(P,2,3); G=substr(P,5,3); O=substr(P,8,3)

    # u=xs para SUID
    gsub(/s/,"xs",U)
    gsub(/s/,"xs",G)

    gsub(/-/,"",U); gsub(/-/,"",G); gsub(/-/,"",O)

    if(match(OS,/HP-UX/)){
      if(length(U))
        CHMOD="chmod u=" U
      else
        CHMOD="chmod u-rwxs"
      if(length(G))
        CHMOD=CHMOD ",g=" G
      else
        CHMOD=CHMOD ",g-rwxs"
      if(length(O))
        CHMOD=CHMOD ",o=" O
      else
        CHMOD=CHMOD ",o-rwxt"
        CHMOD=CHMOD " " F
    } else {
        CHMOD="chmod u=" tolower(U) ",g=" tolower(G) ",o=" O " " tolower(F)
    }

    # sticky bit
    if(match(CHMOD,"rwt"))
      CHMOD="chmod 1777 " F

    print CHMOD
  }'`

  log_session "  * Restoring with $cmd" "$session_log" 
  eval "$cmd" 2>> "$session_log"
  return
}

##########################################################
#
#
#
##########################################################
log_session() {

  [ $# -ne 2 ] && return 1

  msg=$1
  session_log=$2

  [ -z "$msg" ] && return 1

  [ ! -f "$session_log" ] && touch $session_log && chmod 0400 $session_log

  printf "$msg\n" >> $session_log

  return 0
}

##########################################################
#
#
#
##########################################################
log_cli() {

  [ $# -ne 1 ] && return 1

  msg=$1

  [ -z "$msg" ] && return 1

  printf "$msg\n"

  return 0
}

##########################################################
#
#
#
##########################################################
log() {
  [ $# -ne 2 ] && return 1

  msg=$1
  session_log=$2

  [ -z "$msg" ] && return 1

  log_cli "$msg"
  log_session "$msg" "$session_log"
}

#

is_root || {
  log_cli "Only root can run this tool, sorry."
  exit 1
}

# Command line parameters handler
while [ $# -gt 0 ]; do

  case $1 in

    #ignore list
    -s)
      shift
      ACTION="restore"
      session_id=`echo "$1" | grep "^[^-]"`
      shift

      [ -z "$session_id" ] && {
        log_cli "You must provide a session id to restore the files permission."
        exit 1
      }

      ;;

    -g)
      shift
      group=`echo "$1" | grep "^[^-]"`
      shift
      [ -z "$group" ] && {
        log_cli "You must provide a group name to restore the files permission."
        exit 1
      }
      ;;

    -l)
      shift
      ACTION="list"
      session_id=`echo "$1" | grep "^[^-]"`
      shift
      
      [ -z "$session_id" ] && {
        log_cli "You must provide a session id to list the files inside this session."
        exit 1
      }
      ;;


    *)
      log_cli "Illegal parameter $1."
      exit 1
      ;;
  esac
done

case "$ACTION" in
  "rm")
    create_dirs "$GROUPS_PATH" "$SESSIONS_PATH"
    session_fields=`session_create "$SESSIONS_PATH"`
    [ $? -ne 0 ] && {
      log_cli "* Error creating session. Aborting execution."
      exit 1
    }

    session_id=`printf "$session_fields" | awk -F":" '{print $1}'`
    session_log=`printf "$session_fields" | awk -F":" '{print $2}'`
    log "* Session id: ${session_id}" "$session_log" 

    log "* Loading group files and filtering files with active setuid bit." "$session_log"
    targets=`load_files "$GROUPS_PATH" "$session_log"`
    [ $? -ne 0 ] && {
      log "* Error while loading files. Aborting execution." "$session_log"
      exit 1
    }
    
    nfiles="0"
    [ -n "$targets" ] && nfiles=`printf "$targets\n" | awk 'END { print NR }'`
    log "* ${nfiles} files found with active setuid bit." "$session_log" 
    [ "$nfiles" = "0" ] && {
      log "* Exiting ..." "$session_log" 
      exit 0
    }
    
    log "* Removing setuid from:" "$session_log" 
    remove_sids_from "$targets" "$SESSIONS_PATH" "$session_id" "$session_log"
    ;;
  "restore")
    [ -z "$group" ] || [ -z "$session_id" ] && {
      log_cli "* You must provide the session id and the group name to restore the files permission."
      exit 1
    }

    session_path=$SESSIONS_PATH/$session_id

    [ ! -d "$session_path" ] && {
      log_cli "* Session directory [$session_path] not found. Aborting execution." 
      exit 1
    }

    group_path="$session_path/groups/$group"

    [ ! -f "$group_path" ] && {
      log_cli "* There is no such group $group in session $session_id. Aborting execution." 
      exit 1
    }

    restore_log="$session_path/restore.`date '+%Y%m%d%H%M%S'`.log"
    log "* Loading group files and filtering files with active setuid bit." "$restore_log"
    targets=`session_load_files "$group_path" "$restore_log"`
    [ $? -ne 0 ] && {
      log "* Error while loading files. Aborting execution." "$restore_log"
      exit 1
    }

    nfiles="0"
    [ -n "$targets" ] && nfiles=`printf "$targets\n" | awk 'END { print NR }'`
    log "* ${nfiles} files found to be restored." "$restore_log" 
    [ "$nfiles" = "0" ] && {
      log "* Exiting ..." "$restore_log" 
      exit 0
    }

    log "* Restoring files permission:" "$session_log" 
    restore "$targets" "$SESSIONS_PATH" "$session_id" "$session_log"

    ;;
  "list")

    session_path=$SESSIONS_PATH/$session_id

    [ ! -d "$session_path" ] && {
      log_cli "* Session directory [$session_path] not found. Aborting execution." 
      exit 1
    }

    group_path=$session_path/groups

    printf "* Session: $session_id\n"
    session_show "$group_path"

    ;;
esac


exit 0

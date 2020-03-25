#!/bin/sh
#
#  CST Security Toolkit
#  Copyright (c) 2020 CodeView Consultoria, All Rights Reserved
#

banner() {

  cat <<END
-----------------------------------------------------------------------------
 CST - CodeView Security Toolkit  - Version $SCRIPT_VER
-----------------------------------------------------------------------------
 Run this script in order to apply security settings previously
 Prepare your Server to be audit secutity with scipt CodeView

 (c) Copyright (c) 2020 CodeView Consultoria, All Rights Reserved
------------------------------------------------------------------------------

END

  return
}

check_baseline_files() {

  if [ ! -f "$APP_PATH/lib/$OS/$OS" ]; then

    echo "[*] ERROR: No correction script available for this operating system!"
    echo
    echo "exiting..."
    return 1
  fi

  if [ ! -d "$APP_PATH/baselines/$OS" ]; then

    echo "[*] ERROR: No baseline available. Wrong OS??"
    echo
    echo "exiting..."
    return 1
  fi

  return 0
}

OS=$(uname -s)
revision=$(uname -r)
APP_PATH=$(dirname $0)
TOOLS_PATH=$APP_PATH/tools
[ "$OS" != "HP-UX" ] && {
  LANG="en_US.UTF-8"
  export LANG
}
CORRECTION_PERFORMED=1

. $APP_PATH/lib/param_handler.sh
[ -n "$NO_INTERACTIVE_TECH_NAME" ] && OS="$NO_INTERACTIVE_TECH_NAME"

# header scripts
. $APP_PATH/lib/script_header
. $APP_PATH/lib/common

if [ -n "$TECH_TYPE" -a "$TECH_TYPE" = "SERVICE" ]; then

  . "$APP_PATH/lib/Services/$OS/Default"
  . "$APP_PATH/desc/$OS"
else

  . "$APP_PATH/lib/$OS/$OS"
  . "$APP_PATH/desc/$OS"
fi

. $APP_PATH/lib/menu

# load common functions
common_libs=$(ls -1 $APP_PATH/lib/common_libs)
for lib in $common_libs; do

  . "$APP_PATH/lib/common_libs/$lib"
done
unset common_libs

# load configuration database
[ -f "$APP_PATH/db/configurations.db" ] && . $APP_PATH/db/configurations.db
cnt=1

banner
startup

#if [ "$interactive" = "no" ] && [ -f "$baseline" ] && [ "$rollback_mode" = "off" ] ; then
if [ "$started_with_options" -eq "1" ] && [ -f "$baseline" ] && [ "$rollback_mode" = "off" ]; then

  [ "$TECH_TYPE" = "SERVICE" ] && {

    case "$NO_INTERACTIVE_TECH_NAME" in

    "Apache")
      apacheFile="$NO_INTERACTIVE_TARGET_PATH"
      ;;

    "Lighttpd")
      lighttpdHome="$NO_INTERACTIVE_TARGET_PATH"
      ;;

    "Postfix")
      postfixHome="$NO_INTERACTIVE_TARGET_PATH"
      ;;

    "Resin")
      resinHome="$NO_INTERACTIVE_TARGET_PATH"
      ;;

    "Samba")
      sambaFile="$NO_INTERACTIVE_TARGET_PATH"
      ;;

    "Sendmail")
      sendmailFile="$NO_INTERACTIVE_TARGET_PATH"
      ;;

    "SSH")
      sshFile="$NO_INTERACTIVE_TARGET_PATH"
      ;;

    esac
  }

  # starting the deployment in non-interactive mode
  . "$baseline"
  apply_corrections
  show_manual_items "$APP_PATH/desc/$OS"
  exit 0
else

  # starting rollback in non-interactive mode
  [ "$rollback_mode" = "on" ] && {

    [ "$interactive" = "no" ] && {

      interactiveRestore="no"
    }
    restore_backup
    exit 0
  }

  # loading the main menu
  option=0

  while [ $option -ne 11 ]; do

    menu
    option=$?

    case $option in
    1)
      menu_baseline
      # baseline workaround
      if [ -f "$baseline" ]; then
        . "$baseline"
      fi
      ;;
    2)
      menu_interactivy
      ;;
    3)
      menu_log
      ;;
    4)
      menu_backup
      ;;
    5)
      option_restore=1

      while [ "$option_restore" != "7" ]; do
        menu_restore
        option_restore=$?

        case $option_restore in
        1) menu_directory_backup ;;
        2) menu_log_backup ;;
        3) list_sessions ;;
        4) restore_backup ;;
        5) change_interactive_restore ;;
        6) show_items_to_be_restored ;;
        esac
      done
      ;;
    6)
      list_routines
      ;;
    7)
      list_ignoreds
      ;;
    8)
      if [ ! -f "$baseline" ]; then
        echo "Baseline not defined."
        echo
        echo "press enter to return to menu"
        read
        option=0
      else
        . "$baseline"
        apply_corrections
        show_manual_items "$APP_PATH/desc/$OS"
      fi
      ;;
    9)
      option_service=1
      while [ "$option_service" != "8" ]; do
        menu_services
        option_service=$?

        case $option_service in

        1) # load configuration to apache
          . "$APP_PATH/lib/Services/Apache/Default"
          . "$APP_PATH/desc/Apache"
          OS="Apache"

          option_apache=1
          while [ "$option_apache" != "7" ]; do
            menu_apache
            option_apache=$?

            case $option_apache in
            1) menu_baseline_service ;;
            2) menu_file_apache ;;
            3)
              option_restore=1

              while [ "$option_restore" != "7" ]; do
                menu_restore apache
                option_restore=$?

                case $option_restore in
                1) menu_directory_backup ;;
                2) menu_log_backup ;;
                3) list_sessions ;;
                4) restore_backup apache ;;
                5) change_interactive_restore ;;
                6) show_items_to_be_restored "apache" ;;
                esac
              done
              ;;
            4) list_routines ;;
            5) list_ignored_service ;;
            6)
              unset error
              [ -z "$apacheFile" ] && {
                echo "Configuration file is not set"
                error=1
              }

              [ -z "$apacheBaseline" ] && {
                echo "Baseline is not defined"
                continue
              }

              [ -n "$error" ] && continue

              [ ! -f "$apacheFile" ] && {
                echo "$apacheFile not found."
                continue
              }

              [ ! -f "$apacheBaseline" ] && {
                echo "$apacheBaseline not found."
                continue
              }

              . "$apacheBaseline"
              apply_corrections
              show_manual_items "$APP_PATH/desc/Apache"
              ;;
            esac
          done
          ;;
        2)
          # load configuration to ssh
          . "$APP_PATH/lib/Services/SSH/Default"
          . "$APP_PATH/desc/SSH"
          OS="SSH"

          option_ssh=1
          while [ "$option_ssh" != "7" ]; do
            menu_ssh
            option_ssh=$?

            case $option_ssh in
            1) menu_baseline_service ;;
            2) menu_file_ssh ;;
            3)
              option_restore=1
              while [ "$option_restore" != "7" ]; do
                menu_restore ssh
                option_restore=$?

                case $option_restore in
                1) menu_directory_backup ;;
                2) menu_log_backup ;;
                3) list_sessions ;;
                4) restore_backup ssh ;;
                5) change_interactive_restore ;;
                6) show_items_to_be_restored "ssh" ;;
                esac
              done
              ;;
            4) list_routines ;;
            5) list_ignored_service ;;
            6)
              unset error
              [ -z "$sshFile" ] && {
                echo "Configuration file is not set."
                error=1
              }

              [ -z "$sshBaseline" ] && {
                echo "Baseline is not defined."
                continue
              }

              [ -n "$error" ] && continue

              [ ! -f "$sshFile" ] && {
                echo "$sshFile not found."
                continue
              }

              [ ! -f "$sshBaseline" ] && {
                echo "$sshBaseline not found."
                continue
              }

              . "$sshBaseline"

              clean_itens_ssh
              load_itens_ssh

              apply_corrections
              show_manual_items "$APP_PATH/desc/SSH"
              ;;
            esac
          done
          ;;
        3)

          # load configuration to samba
          . "$APP_PATH/lib/Services/Samba/Default"
          . "$APP_PATH/desc/Samba"
          OS="Samba"

          option_samba=1
          while [ "$option_samba" != "7" ]; do
            menu_samba
            option_samba=$?

            case $option_samba in
            1) menu_baseline_service ;;
            2) menu_file_samba ;;
            3)
              option_restore=1
              while [ "$option_restore" != "7" ]; do
                menu_restore samba
                option_restore=$?

                case $option_restore in
                1) menu_directory_backup ;;
                2) menu_log_backup ;;
                3) list_sessions ;;
                4) restore_backup samba ;;
                5) change_interactive_restore ;;
                6) show_items_to_be_restored "samba" ;;
                esac
              done
              ;;
            4) list_routines ;;
            5) list_ignored_service ;;
            6)
              unset error
              [ -z "$sambaFile" ] && {
                echo "Configuration file is not set"
                error=1
              }

              [ -z "$sambaBaseline" ] && {
                echo "Baseline is not defined"
                continue
              }

              [ -n "$error" ] && continue

              [ ! -f "$sambaFile" ] && {
                echo "$sambaFile not found."
                continue
              }

              [ ! -f "$sambaBaseline" ] && {
                echo "$sambaBaseline not found."
                continue
              }

              . "$sambaBaseline"
              apply_corrections
              show_manual_items "$APP_PATH/desc/Samba"
              ;;

            esac
          done
          ;;
        4)

          # load configuration to samba
          . "$APP_PATH/lib/Services/Sendmail/Default"
          . "$APP_PATH/desc/Sendmail"
          OS="Sendmail"

          option_sendmail=1
          while [ "$option_sendmail" != "7" ]; do
            menu_sendmail
            option_sendmail=$?

            case $option_sendmail in
            1) menu_baseline_service ;;
            2) menu_file_sendmail ;;
            3)
              option_restore=1
              while [ "$option_restore" != "7" ]; do
                menu_restore sendmail
                option_restore=$?

                case $option_restore in
                1) menu_directory_backup ;;
                2) menu_log_backup ;;
                3) list_sessions ;;
                4) restore_backup sendmail ;;
                5) change_interactive_restore ;;
                6) show_items_to_be_restored "sendmail" ;;
                esac
              done
              ;;
            4) list_routines ;;
            5) list_ignored_service ;;
            6)
              unset error
              [ -z "$sendmailFile" ] && {
                echo "Configuration file is not set"
                error=1
              }

              [ -z "$sendmailBaseline" ] && {
                echo "Baseline is not defined"
                continue
              }

              [ -n "$error" ] && continue

              [ ! -f "$sendmailFile" ] && {
                echo "$sendmailFile not found."
                continue
              }

              [ ! -f "$sendmailBaseline" ] && {
                echo "$sendmailBaseline not found."
                continue
              }

              . "$sendmailBaseline"
              apply_corrections
              show_manual_items "$APP_PATH/desc/Sendmail"
              ;;

            esac
          done
          ;;
        5)
          . "$APP_PATH/lib/Services/Resin/Default"
          . "$APP_PATH/desc/Resin"
          OS="Resin"

          option_resin=1
          while [ "$option_resin" != "7" ]; do
            menu_resin
            option_resin=$?

            case $option_resin in
            1) menu_baseline_service ;;
            2) menu_file_resin ;;
            3)
              option_restore=1
              while [ "$option_restore" != "7" ]; do
                menu_restore resin
                option_restore=$?

                case $option_restore in
                1) menu_directory_backup ;;
                2) menu_log_backup ;;
                3) list_sessions ;;
                4) restore_backup resin ;;
                5) change_interactive_restore ;;
                6) show_items_to_be_restored "resin" ;;
                esac
              done
              ;;
            4) list_routines ;;
            5) list_ignored_service ;;
            6)
              unset error
              [ -z "$resinHome" ] && {
                echo "Resin home directory is not set."
                error=1
              }

              [ -z "$resinBaseline" ] && {
                echo "Baseline is not defined."
                continue
              }

              [ -n "$error" ] && continue

              [ ! -d "$resinHome" ] && {
                echo "$resinHome not found."
                continue
              }

              [ ! -f "$resinBaseline" ] && {
                echo "$resinBaseline not found."
                continue
              }

              [ ! -d "$resinHome/conf" ] || [ ! -d "$resinHome/log" ] ||
                [ ! -d "$resinHome/logs" ] || [ ! -f "$resinHome/conf/resin.conf" ] && {
                echo "$resinHome does not appear a Resin installation directory."
                continue
              }

              . "$resinBaseline"
              apply_corrections
              show_manual_items "$APP_PATH/desc/Resin"
              ;;
            esac
          done
          ;;
        6)
          . "$APP_PATH/lib/Services/Lighttpd/Default"
          . "$APP_PATH/desc/Lighttpd"
          OS="Lighttpd"

          option_lighttpd=1
          while [ "$option_lighttpd" != "7" ]; do
            menu_lighttpd
            option_lighttpd=$?

            case $option_lighttpd in
            1) menu_baseline_service ;;
            2) menu_file_lighttpd ;;
            3)
              option_restore=1
              while [ "$option_restore" != "7" ]; do
                menu_restore lighttpd
                option_restore=$?

                case $option_restore in
                1) menu_directory_backup ;;
                2) menu_log_backup ;;
                3) list_sessions ;;
                4) restore_backup lighttpd ;;
                5) change_interactive_restore ;;
                6) show_items_to_be_restored "lighttpd" ;;
                esac
              done
              ;;
            4) list_routines ;;
            5) list_ignored_service ;;
            6)
              unset error
              [ -z "$lighttpdHome" ] && {
                echo "Lighttpd home directory is not set."
                error=1
              }

              [ -z "$lighttpdBaseline" ] && {
                echo "Baseline is not defined."
                continue
              }

              [ -n "$error" ] && continue

              [ ! -d "$lighttpdHome" ] && {
                echo "$lighttpdHome not found."
                continue
              }

              [ ! -f "$lighttpdBaseline" ] && {
                echo "$lighttpdBaseline not found."
                continue
              }

              [ ! -d "$lighttpdHome/conf-enabled" ] || [ ! -f "$lighttpdHome/lighttpd.conf" ] && {
                echo "$lighttpdHome does not appear a Lighttpd installation directory."
                continue
              }

              . "$lighttpdBaseline"
              apply_corrections
              show_manual_items "$APP_PATH/desc/Lighttpd"
              ;;
            esac
          done
          ;;
        7)
          . "$APP_PATH/lib/Services/Postfix/Default"
          . "$APP_PATH/desc/Postfix"
          OS="Postfix"

          option_postfix=1
          while [ "$option_postfix" != "7" ]; do
            menu_postfix
            option_postfix=$?

            case $option_postfix in
            1) menu_baseline_service ;;
            2) menu_file_postfix ;;
            3)
              option_restore=1
              while [ "$option_restore" != "7" ]; do
                menu_restore postfix
                option_restore=$?

                case $option_restore in
                1) menu_directory_backup ;;
                2) menu_log_backup ;;
                3) list_sessions ;;
                4) restore_backup postfix ;;
                5) change_interactive_restore ;;
                6) show_items_to_be_restored "postfix" ;;
                esac
              done
              ;;
            4) list_routines ;;
            5) list_ignored_service ;;
            6)
              unset error
              [ -z "$postfixHome" ] && {
                echo "Postfix home directory is not set."
                error=1
              }

              [ -z "$postfixBaseline" ] && {
                echo "Baseline is not defined."
                continue
              }

              [ -n "$error" ] && continue

              [ ! -d "$postfixHome" ] && {
                echo "$postfixHome not found."
                continue
              }

              [ ! -f "$postfixBaseline" ] && {
                echo "$postfixBaseline not found."
                continue
              }

              [ ! -f "$postfixHome/postconf" ] && {
                echo "$postfixHome does not appear a Postfix installation directory."
                continue
              }

              . "$postfixBaseline"
              apply_corrections
              show_manual_items "$APP_PATH/desc/Postfix"
              ;;
            esac
          done
          ;;

        esac
      done

      OS=$(uname -s)
      . "$APP_PATH/lib/$OS/$OS"
      . "$APP_PATH/desc/$OS"
      ;;

    10)
      if [ -f "LEIAME" ]; then
        more LEIAME
      else
        [ -f "README" ] && more README
      fi
      ;;
    11) #exit 0
      ;;
    esac
  done

fi

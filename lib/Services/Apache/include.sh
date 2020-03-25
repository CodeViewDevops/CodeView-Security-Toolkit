#===  FUNCTION  ================================================================
#          NAME:  fix_apache_exec_by_name
#   DESCRIPTION:  Disable file execution by name.
#    PARAMETERS:  --
#       RETURNS:  0 = success ; 1 = failure
#===============================================================================

fix_apache_exec_by_name () {

  tmp_file=`mktemp /tmp/correction.XXXXXX`

  backupFile "$apacheFile" "data"

  #sed '/<Directory/,/<\/Directory/s/^\([ \t]\{0,\}AddHandler[ \t]\{1,\}cgi-script[ \t]\{1,\}.*\.cgi.*\)/#\1/' $apacheFile > $tmp_file
  sed 's/^[ \t]\{0,\}AddHandler.*\.shtml/# &/g; s/^[ \t]\{0,\}AddHandler.*\cgi\-script.*/# &/g' $apacheFile > $tmp_file
  mv $tmp_file $apacheFile

  return 0
}

#===  FUNCTION  ================================================================
#          NAME:  fix_perm_on_cert_files
#   DESCRIPTION:  Fix the permissions on certifies files.
#    PARAMETERS:  --
#       RETURNS:  0 = success
#===============================================================================

fix_perm_on_cert_files () {

  # Apache2 (Debian) : /etc/ssl/certs
  # Apache1 (Debian) : /etc/apache/ssl.crt/
  # Suse Enterprise 10 : /etc/apache2/ssl.crt
  # Red hat Enterprise e Fedora : /etc/pki/tls/certs
  # Slackware : /etc/apache/ssl.crt 

  cert_dirs="/etc/ssl/certs /etc/apache/ssl.crt /etc/apache2/ssl.crt /etc/pki/tls/certs /etc/apache/ssl.crt"

  backupFiles=""

  for dir in $cert_dirs; do

    [ ! -d "$dir" ] && continue

    backupFiles="$backupFiles `ls -R ${dir}/*.crt 2> /dev/null`"

  done

  backupFile "$backupFiles" "data"

  chmod -R go-w $backupFiles

  return 0
}

#===============================================================================

#===  FUNCTION  ================================================================
#          NAME:  set_property_value
#   DESCRIPTION:  Replaces or creates a line with the property and value
#                 in the file especified.
#    PARAMETERS:  $1 = filename ; $2 = property name ; $3 = separator char
#                 $4 = new value
#       RETURNS:  0 = succes ; 1 = failure.
#===============================================================================
set_property_value () {
  
        [ $# -lt 4 ] && return 1       
 
        local file=$1        
        local property=$2
        local separator=$3
        local value=$4

        [ ! -e $file ] && return 1

        backupFile "$file" "data"
       
        local tmp_file=`mktemp /tmp/correction.XXXXXX`

        sed "/^[[:blank:]]*\(#[[:blank:]]*\)\{0,1\}$property[[:blank:]]*$separator/d" $file > $tmp_file

        echo "$property$separator$value" >> $tmp_file

        cat $tmp_file > $file

        rm $tmp_file
	
	return 0
}

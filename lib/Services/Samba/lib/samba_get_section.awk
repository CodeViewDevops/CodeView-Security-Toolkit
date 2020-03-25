
BEGIN {
  INSIDE=1
  parseable_section_name=SECTION
  sub("\\$","\\\$",parseable_section_name)
  REGEX_SECTION="\\[" parseable_section_name "\\]"
  REGEX_ALL_SECTIONS="\\[.*\\]"
  BUFFER=""
  JOIN_NEXT_LINE=1

}

{

  #removing commentaries and blank lines
  if ( !match($0,/^[ \t]*[;#]/) && !match($0,/^[ \t]*$/) ) {

    if ( INSIDE == 1 && match($0,REGEX_SECTION) ) {
      INSIDE=0
    } else {
      if (INSIDE == 0) {
        if ( match($0,REGEX_ALL_SECTIONS) ) {
          INSIDE=1
          exit 0
        } else {
          #line break with \ at the end, must be joined on a single line
          if (match($0,"\\\\$")) {
            line = substr($0,1,length($0)-1)
            BUFFER = BUFFER line 
            JOIN_NEXT_LINE=0
          } else {

            if (JOIN_NEXT_LINE == 0 ) {
              line = substr($0,1,length($0))
              BUFFER = BUFFER line 
              JOIN_NEXT_LINE=1
            }

            if (length(BUFFER) > 0 ) {
              print BUFFER

              BUFFER=""
              JOIN_NEXT_LINE=1
            } else {
              print $0
            }
          }
        }
      }
    }
  }
}

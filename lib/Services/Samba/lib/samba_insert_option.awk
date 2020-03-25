
BEGIN {
  INSIDE=1
  parseable_section_name=SECTION
  sub("\\\$","\\\$",parseable_section_name)
  REGEX_SECTION="^[ \t]*\\[" parseable_section_name "\\]"
}

{

  if ($0 ~ REGEX_SECTION) {
    print $0
    print OPTION
  } else {
    print $0
  }

}



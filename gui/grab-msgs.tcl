#***********************************************************************
#
# grab-msgs
#
# Find all [m {foo}] or [m "bar"] instances for translation.
#
# Copyright (C) 2001 Roaring Penguin Software Inc.
#
# LIC: GPL
#
# $Id$
#***********************************************************************

proc process_line { line } {
    set match [regexp -indices {\[m [{"]([^}"]*)["\}]} $line dummy sub]
    while {$match} {
	set sub [string range $line [lindex $sub 0] [lindex $sub 1]]
        puts "::msgcat::mcset en \"$sub\" \"$sub\""
	set line [string range $line [expr 1 + [lindex $dummy 1]] end]
        set match [regexp -indices {\[m [{"]([^}"]*)["\}]} $line dummy sub]
    }
}

while {[gets stdin line] >= 0} {
    process_line $line
}

exit 0


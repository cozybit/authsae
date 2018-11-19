#!/bin/bash
# junit-ize the results from testout.log
logfile=$1
numtests=$(cat $logfile | grep -E "^test" | wc -l)
echo '<testsuites name="vmtests">'
echo '  <testsuite tests="'$numtests'">'
cat $logfile | grep -E "^test" | awk '{
   split($0, x, "PASS|FAIL: ", seps)
   testname=x[1];
   if (seps[1] == "PASS") {
     print "    <testcase classname=\"authsae\" name=\"" testname "\"/>";
   } else {
     print "    <testcase classname=\"authsae\" name=\"" testname "\">";
     print "      <failure type=\"fail\">" x[2] "</failure>";
     print "    </testcase>";
   }
}'
echo '  </testsuite>'
echo '</testsuites>'

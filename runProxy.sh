#JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
JAVA="java"
IPv4='-Djava.net.preferIPv4Stack=true'

CP="-cp bin/"

$JAVA $IPv4 $CP proxy.hjUDPproxy $@

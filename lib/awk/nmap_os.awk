BEGIN { 
    current_ip=="";
    partial_match="";
    aggressive="";
    device_type="";
    running="";
    os_cpe="";
    os_details="";
    os_aggressive="";
}
{
    ip=$1;
    riga=$2;
    for(n=3;n<=NF;n++) riga=riga" "$n;
}
current_ip != ip {
    if (current_ip) {
	printf("%s partial_match %s\n",current_ip,partial_match);
	printf("%s aggressive %s\n",current_ip,aggressive);
	printf("%s device_type %s\n",current_ip,device_type);
	printf("%s running %s\n",current_ip,running);
	printf("%s os_cpe %s\n",current_ip,os_cpe);
	printf("%s os_details %s\n",current_ip,os_details);
	printf("%s os_aggressive %s\n",current_ip,os_aggressive);
    }
    current_ip=ip;
    partial_match="";
    aggressive="";
    device_type="";
    running="";
    os_cpe="";
    os_details="";
    os_aggressive="";
}
riga ~ /^Running.*/ {
    # print $0;
    running=$3;
    for(n=4;n<=NF;n++) running=running" "$n;
    next
} 
riga ~ /^Device type.*/ {
    # print $0;
    device_type=$4;
    for(n=5;n<=NF;n++) device_type=device_type" "$n;
    next
}
riga ~ /^OS CPE.*/ {
    # print $0;
    os_cpe=$4;
    for(n=5;n<=NF;n++) os_cpe=os_cpe" "$n;
    next
}
riga ~ /^OS details.*/ {
    # print $0;
    os_details=$4;
    for(n=5;n<=NF;n++) os_details=os_details" "$n;
    next
}
riga ~ /^No exact OS matches.*/ {
    # print $0;
    partial_match="Y";
    next
}
riga ~ /^Aggressive OS guesses.*/ {
    # print $0;
    aggressive="Y";
    os_aggressive=$5;
    for(n=6;n<=NF;n++) os_aggressive=os_aggressive" "$n;
    next
}
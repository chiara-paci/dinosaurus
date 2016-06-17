BASE { 
    accoda="no";
    prev_owner="";
}
$0 ~ /^ / { 
    if (accoda!="yes"){
	printf("%s %s\n",prev_owner,$0);
	next;
    }
    printf(" %s",$0);
    if ($0 ~ /.*\) *$/) {
	printf("\n");
	accoda="no";
    }
    next;
}
{
    prev_owner=$1;
}
$0 ~ /.*\( *$/ {
    accoda="yes";
    printf("%s",$0);
    next;
}
{ 
    print $0; 
    next;
}
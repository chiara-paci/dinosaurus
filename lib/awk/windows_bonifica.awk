BEGIN { owner="."; }
{
    switch ($1) {
	case "@": owner=zona "."; break;
	case "===": break;
	default: owner=$1 "." zona "."; break;
    }
    printf("%s %s %s",view,zona,owner);

    t=2;
    if ($t ~ /^[0-9]+$/) {
	printf(" %s",$t);
	t++;
    } else {
	printf(" %s","_");
    }
    if ( ($t == "IN") || ($t == "CH") || ($t == "HS") ) {
	printf(" %s",$t);
	t++;
    } else {
	printf(" %s","IN");
    }
    
    for (n=t;n<=NF;n++) printf(" %s",$n);
    printf("\n");
}
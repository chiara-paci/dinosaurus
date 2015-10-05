
class GetSequence(object):
    def __init__(self):
        self.val=-1

    def __call__(self):
        self.val+=1
        return self.val

get_name_id=GetSequence()
get_cname_id=GetSequence()
get_ip_id=GetSequence()

class ResName(object):
    def __init__(self,name):
        self.name=name
        self.res={}
        self.res_cname_list=[]
        self.res_ip_list=[]
        self.id=get_name_id()

    def __hash__(self):
        return hash(self.id)

    def merge(self): 
        # self.res_cname_list=list(set(self.res_cname_list))
        # self.res_ip_list=list(set(self.res_ip_list))
        # for k,val in self.res.items():
        #     self.res[k]=list(set(val))
        pass

    def __str__(self): return "["+str(self.id)+"] "+self.name+" (A)"

    def add_res(self,ip,record,view_list):
        if not self.res.has_key(ip):
            self.res[ip]=[]
        self.res[ip].append( (view_list,record) )

    def table_header(self): return ""

    def html_row(self):
        S='<tbody>'
        S+='<tr>'
        S+='<td class="right">'+self.name+'</td>'
        S+='<td>A</td>'
        S+='<td>'+str(self.res_cname_list)+'</td>'
        S+='<td>'+str(self.res_ip_list)+'</td>'
        S+='</tr>'
        S+='</tbody>'
        return S

    def __eq__(self,other): return self.name==other.name
    def __lt__(self,other):
        s_t=self.name.split(".")
        o_t=other.name.split(".")
        s_t.reverse()
        o_t.reverse()
        s_L=len(s_t)
        o_L=len(o_t)
        L=min(s_L,o_L)
        for n in range(0,L):
            if s_t[n]<o_t[n]: return True
            if s_t[n]>o_t[n]: return False
        return s_L<o_L

    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

class ResCName(object):
    def __init__(self,name):
        self.name=name
        self.res={}
        self.res_name_list=[]
        self.id=get_cname_id()

    def merge(self): 
        # self.res_name_list=list(set(self.res_name_list))
        # for k,val in self.res.items():
        #     self.res[k]=list(set(val))
        pass

    def __str__(self): return "["+str(self.id)+"] "+self.name+" (CNAME)"

    def __hash__(self):
        return hash(self.id)

    def add_res(self,name,record,view_list):
        if not self.res.has_key(name):
            self.res[name]=[]
        self.res[name].append( (view_list,record) )

    def add_res_name(self,res_name,view_list):
        self.res_name_list.append( (view_list,res_name) )
        res_name.res_cname_list.append( (view_list,self) )

    def table_header(self): return ""

    def html_row(self):
        S='<tbody>'
        S+='<tr>'
        S+='<td class="right">'+self.name+'</td>'
        S+='<td>CNAME</td>'
        S+='<td>'+str(self.res_name_list)+'</td>'
        S+='</tr>'
        S+='</tbody>'
        return S

    def __eq__(self,other): return self.name==other.name
    def __lt__(self,other):
        s_t=self.name.split(".")
        o_t=other.name.split(".")
        s_t.reverse()
        o_t.reverse()
        s_L=len(s_t)
        o_L=len(o_t)
        L=min(s_L,o_L)
        for n in range(0,L):
            if s_t[n]<o_t[n]: return True
            if s_t[n]>o_t[n]: return False
        return s_L<o_L

    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

class VList(list):
    def __init__(self,L):
        list.__init__(self,list(set(L)))
        self.sort()

    def __str__(self):
        return ", ".join(map(str,self))


    def __hash__(self): return hash(str(self))

class ResIp(object): 
    def __init__(self,ip):
        self.ip=ip.replace(".in-addr.arpa.","")
        self.res={}
        self.res_name_list=[]
        self.id=get_ip_id()

    def __hash__(self):
        return hash(self.id)

    def print_res_name_list(self):
        for vlist,rec in self.res_name_list:
            print rec
            for v in vlist:
                print "    ",v
            

    ### non funziona
    def merge(self): 
        def f_conv(row):
            view_list,r=row
            return ( VList(view_list),r )
        print 
        print "PRIMA"
        self.print_res_name_list()
        self.res_name_list=list(set(map(f_conv,self.res_name_list)))
        print "DOPO"
        self.print_res_name_list()

        if not self.res: return

        for k,val in self.res.items():
            self.res[k]=list(set(map(f_conv,val)))

    def add_res(self,name,record,view_list):
        if not self.res.has_key(name):
            self.res[name]=[]
        self.res[name].append( (view_list,record) )

    def add_res_name(self,res_name,view_list):
        self.res_name_list.append( (view_list,res_name) )
        res_name.res_ip_list.append( (view_list,self) )

    def __str__(self): return "["+str(self.id)+"] "+self.ip

    def table_header(self): 
        S=""
        S='<tr><th rowspan="2">IP</th>'
        S+='<th colspan="2">IN PTR</th>'
        S+='<th colspan="2">IN A</th>'
        S+='<th colspan="2">IN CNAME</th>'
        S+='</tr>'
        S+='<tr>'
        S+='<th>views</th><th>name</th>'
        S+='<th>views</th><th>name</th>'
        S+='<th>views</th><th>name</th>'
        S+='</tr>'
        return S

    def html_row(self):
        def html_cols(n):
            S=""
            Q=[]
            if n<len(self.res_name_list):
                view_list,res_name=self.res_name_list[n]
                LC=len(res_name.res_cname_list)
            else:
                LC=0
            if LC<=1: rowspan=""
            else: rowspan=' rowspan="'+str(LC)+'"'
            if n<len(self.res):
                name,data=self.res.items()[n]
                if len(data)>1: S+='<td'+rowspan+' style="background-color:#ffff00">'
                else: S+='<td'+rowspan+'>'
                t=[]
                for view_list,record in data:
                    t.append(", ".join(map(str,view_list)))
                S+="; ".join(t)
                S+='</td>'
                S+='<td'+rowspan+'>'+name+'</td>'
            else:
                S+='<td'+rowspan+'></td>'
                S+='<td'+rowspan+'></td>'

            if n>=len(self.res_name_list): 
                S+='<td></td>'
                S+='<td></td>'
                S+='<td></td>'
                return S,Q
            view_list,res_name=self.res_name_list[n]
            S+='<td'+rowspan+'>'
            S+=", ".join(map(str,view_list))+'</td>'
            S+='<td'+rowspan+'>'+str(res_name)+'</td>'
            if LC==0:
                S+='<td></td>'
                S+='<td></td>'
                return S,Q

            view_list,res_cname=res_name.res_cname_list[0]
            S+='<td>'
            S+=", ".join(map(str,view_list))+'</td>'
            S+='<td>'+str(res_cname)+'</td>'
            
            if LC==1:
                return S,Q
            for view_list,res_cname in res_name.res_cname_list[1:]:
                x='<td style="background:#ffff00">'
                x+=", ".join(map(str,view_list))+'</td>'
                x+='<td style="background:#ffff00">'+str(res_cname)+'</td>'
                Q.append(x)
            return S,Q

        def len_res_name_list():
            L=0
            if not self.res_name_list: return L
            for view_list,res_name in self.res_name_list:
                L+=max(1,len(res_name.res_cname_list))
            return L

        NR=max(len(self.res),len_res_name_list())
        if NR==1:
            S='<tbody>'
            S+='<tr>'
            S+='<td>'+self.ip+'</td>'
            x,Q=html_cols(0)
            S+=x
            S+='</tr>'
            if Q:
                for q in Q: S+='<tr>'+q+'</tr>'
            S+='</tbody>'
            return S
        S='<tbody>'
        S+='<tr>'
        S+='<td rowspan="'+str(NR)+'">'+self.ip+'</td>'
        for n in range(0,NR):
            if n!=0: S+="<tr>"
            x,Q=html_cols(n)
            S+=x
            S+='</tr>'
            if Q:
                for q in Q: S+='<tr>'+q+'</tr>'
        S+='</tbody>'
        return S
        
    def __eq__(self,other): return self.ip==other.ip
    def __lt__(self,other):
        if other.ip=="::1": return False
        if self.ip=="::1": 
            return True
        try:
            s_t=map(int,self.ip.split(".")[:4])
        except ValueError, e:
            return True
        try:
            o_t=map(int,other.ip.split(".")[:4])
        except ValueError, e:
            return False
        if (s_t[0] in [ 127,0,10 ]) and (o_t[0] not in [ 127,0,10 ]):
            return True
        if (s_t[0] not in [ 127,0,10 ]) and (o_t[0] in [ 127,0,10 ]):
            return False
        if (s_t[0]==172) and (s_t[1] in range(16,32)):
            if (o_t[0]!=172): return True
            if (o_t[1] not in range(16,32)): return True
        if (o_t[0]==172) and (o_t[1] in range(16,32)):
            if (s_t[0]!=172): return False
            if (s_t[1] not in range(16,32)): return False
        if (s_t[0]==192) and (s_t[1]==168):
            if (o_t[0]!=192): return True
            if (o_t[1]!=168): return True
        if (o_t[0]==192) and (o_t[1]==168):
            if (s_t[0]!=192): return False
            if (s_t[1]!=168): return False
        if (s_t[0]==169) and (s_t[1]==254):
            if (o_t[0]!=169): return True
            if (o_t[1]!=254): return True
        if (o_t[0]==169) and (o_t[1]==254):
            if (s_t[0]!=169): return False
            if (s_t[1]!=254): return False
        for n in range(0,4):
            if s_t[n]<o_t[n]: return True
            if s_t[n]>o_t[n]: return False
        return False
         
    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

class IPFamily(list):
    def __init__(self,name):
        list.__init__()
        self.name=name

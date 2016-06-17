from dinosaurus_lib.config import *

get_name_id=GetSequence()
get_ip_id=GetSequence()

class ResName(object):
    record_type="XXX"

    def __init__(self,name):
        self.name=name
        self.id=get_name_id()
        self.res={}

    def __hash__(self):
        return hash(self.id)

    def __str__(self): 
        return "["+str(self.id)+"] "+self.name+" ("+self.record_type+")"

    def __eq__(self,other): return self.name.lower()==other.name.lower()
    def __lt__(self,other):
        s_t=self.name.lower().split(".")
        o_t=other.name.lower().split(".")
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

    def add_res(self,key,record,view_list):
        if not self.res.has_key(key):
            self.res[key]=[]
        self.res[key].append( (view_list,record) )

class ResAName(ResName):
    record_type = "A"

    def __init__(self,name):
        ResName.__init__(self,name)
        self.res_cname_list=[]
        self.res_ip_list=[]

class ResCName(ResName):
    record_type = "CNAME"

    def __init__(self,name):
        ResName.__init__(self,name)
        self.res_name_list=[]
        self.res_ip_list=[]

    def add_res_name(self,res_name,view_list):
        self.res_name_list.append( (view_list,res_name) )
        res_name.res_cname_list.append( (view_list,self) )

    def add_res_ip(self,res_ip,view_list):
        self.res_ip_list.append( (view_list,res_ip) )

class ResPTRName(ResName):
    record_type = "PTR"

    def __init__(self,name):
        ResName.__init__(self,name)
        self.res_ip_list=[]

    def add_res_ip(self,res_ip,view_list):
        self.res_ip_list.append( (view_list,res_ip) )

class ResIp(object): 
    def __init__(self,ip):
        self.ip=ip.replace(".in-addr.arpa.","")
        self.res={}
        self.res_name_list=[]
        self.id=get_ip_id()

    def __hash__(self):
        return hash(self.id)

    def __str__(self): return "["+str(self.id)+"] "+self.ip

    def __eq__(self,other): return self.ip==other.ip

    def __lt__(self,other):
        return ip_cmp(self.ip,other.ip) < 0

        # if other.ip=="::1": return False
        # if self.ip=="::1": 
        #     return True
        # try:
        #     s_t=map(int,self.ip.split(".")[:4])
        # except ValueError, e:
        #     return True
        # try:
        #     o_t=map(int,other.ip.split(".")[:4])
        # except ValueError, e:
        #     return False
        # if (s_t[0] in [ 127,0,10 ]) and (o_t[0] not in [ 127,0,10 ]):
        #     return True
        # if (s_t[0] not in [ 127,0,10 ]) and (o_t[0] in [ 127,0,10 ]):
        #     return False
        # if (s_t[0]==172) and (s_t[1] in range(16,32)):
        #     if (o_t[0]!=172): return True
        #     if (o_t[1] not in range(16,32)): return True
        # if (o_t[0]==172) and (o_t[1] in range(16,32)):
        #     if (s_t[0]!=172): return False
        #     if (s_t[1] not in range(16,32)): return False
        # if (s_t[0]==192) and (s_t[1]==168):
        #     if (o_t[0]!=192): return True
        #     if (o_t[1]!=168): return True
        # if (o_t[0]==192) and (o_t[1]==168):
        #     if (s_t[0]!=192): return False
        #     if (s_t[1]!=168): return False
        # if (s_t[0]==169) and (s_t[1]==254):
        #     if (o_t[0]!=169): return True
        #     if (o_t[1]!=254): return True
        # if (o_t[0]==169) and (o_t[1]==254):
        #     if (s_t[0]!=169): return False
        #     if (s_t[1]!=254): return False
        # for n in range(0,4):
        #     if s_t[n]<o_t[n]: return True
        #     if s_t[n]>o_t[n]: return False
        # return False
         
    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

    def print_res_name_list(self):
        for vlist,rec in self.res_name_list:
            print rec
            for v in vlist:
                print "    ",v
            
    def add_res(self,name,record,view_list):
        if not self.res.has_key(name):
            self.res[name]=[]
        self.res[name].append( (view_list,record) )

    def add_res_name(self,res_name,view_list):
        self.res_name_list.append( (view_list,res_name) )
        res_name.res_ip_list.append( (view_list,self) )


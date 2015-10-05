import os
import re

from dinosaurus_lib.config import *
from dinosaurus_lib.resolutions import *

class WrongRecordSize(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class View(object):
    def __init__(self,vid,name):
        self.name=name
        self.id=vid

    def __str__(self): return "["+str(self.id)+"] "+self.name

    def __eq__(self,other): return self.id==other.id
    def __ne__(self,other): return self.id!=other.id

    def __lt__(self,other): 
        if self.name[0]=="_":
            if other.name[0]=="_": return self.id<other.id
            return False
        if other.name[0]=="_":
            if self.name[0]=="_": return self.id<other.id
            return True
        return self.id<other.id

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

### QUIC
class Zone(object):
    def __init__(self,zid,name):
        self.name=name
        self.id=zid
        self.rows=[]
        self.def_rows=[]
        self.reduced=""

        self.soa_record=None
        self.special_records={ "MX": set(),"NS": set(),"TXT": set(),"SPF": set(), "SRV": set(), "AFSDB": set() }
        self.data_records={ "A": set(),"CNAME": set(),"AAAA": set(),"PTR": set() }
        self.dns_type_list=set()

        self.re_zone_suffix=re.compile(r"\."+self.name+r"\.$")

    def __str__(self): return "["+str(self.id)+"] "+self.name+" ("+self.classification()+")"

    def __eq__(self,other): return self.name==other.name
    def __ne__(self,other): return self.name!=other.name

    def __lt__(self,other):
        t_s=self.name.split(".")
        t_o=other.name.split(".")
        if t_s[0].isdigit():
            if t_o[0].isdigit(): return self.name<other.name
            return False
        if t_o[0].isdigit():
            if t_s[0].isdigit(): return self.name<other.name
            return True
        t_o.reverse()
        t_s.reverse()
        l_o=len(t_o)
        l_s=len(t_s)
        l=min(l_o,l_s)
        for n in range(0,l):
            if t_o[n]>t_s[n]: return True
            if t_o[n]<t_s[n]: return False
        return l_o > l_s

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

    def is_reverse(self):
        t_s=self.name.split(".")
        return t_s[0].isdigit()

    def views_set(self):
        views=set()
        for r in self.def_rows+self.rows:
            views=views.union(r.views_set())
        return views

    def append_record(self,record):
        if not record: return
        if not record.zone_def:
            if record not in self.rows:
                self.rows.append(record)
        else:
            if record not in self.def_rows:
                self.def_rows.append(record)
        self.dns_type_list.add(record.dns_type)
        if record.dns_type.dns_type not in [ "SOA" ]+self.special_records.keys()+self.data_records.keys():
            return
        if record.dns_type.dns_type=="SOA":
            self.soa_record=SoaRecord(record)
            return
        if record.dns_type.dns_type in self.special_records.keys():
            self.special_records[record.dns_type.dns_type].add(record)
            return
        self.data_records[record.dns_type.dns_type].add(record)


    def merge_views(self): 
        for r in self.def_rows: r.merge_views()
        for r in self.rows: r.merge_views(debug=False)
        self.soa_record.set_merged_data()
        v_set=self.views_set()
        if len(v_set)==1:
            self.reduced="single view"
            return
        if self.multiple_not_merged():
            self.reduced="multiple"
            return
        self.reduced="merged"
        
        for k in self.special_records.keys():
            self.special_records[k]=list(self.special_records[k])
            self.special_records[k].sort()

    def multiple_not_merged(self):
        base_views=None
        for r in self.def_rows:
            if len(r.merged)>1: return True
            if not base_views:
                base_views=set(r.merged[0][0])
                continue
            if base_views!=set(r.merged[0][0]): 
                return True
        for r in self.rows:
            if len(r.merged)>1: return True
            if not base_views:
                base_views=set(r.merged[0][0])
                continue
            if base_views!=set(r.merged[0][0]): 
                return True
        return False

    def merged_views_sets(self):
        merged_views_sets=set()
        for r in self.def_rows:
            for view_list,rec_list in r.merged:
                view_list.sort()
                merged_views_sets.add( tuple(view_list) )
        for r in self.rows:
            for view_list,rec_list in r.merged:
                view_list.sort()
                merged_views_sets.add( tuple(view_list) )
        return merged_views_sets

    def get_url(self):
        return "./"+self.html_fname()

    def html_fname(self):
        return "zones/zone_"+str(self.id)+"_"+self.name+".html"

    def printable_zone(self,full=False):
        if self.is_reverse(): p="R"
        else: p="D"
        return "    %s %-30.30s %s\n" % (p,self," ".join(map(str,list(self.views_set()))))

    # zone
    def classification_by_view(self):
        T={}
        if self.is_reverse():
            C=self.classification()
            for vtuple in self.merged_views_sets():
                label="_".join(map(lambda x: x.name,vtuple))
                T[label]=C
            return T

        for vtuple in self.merged_views_sets():
            label="_".join(map(lambda x: x.name,vtuple))
            T[label]=set()

        for r in self.rows:
            ip_v=r.classification_by_view()
            if not ip_v: continue
            for label,ip_t in ip_v.items():
                T[label].add(ip_t)

        ret={}
        for k in T.keys():
            if len(T[k])>2: 
                ret[k]="mixed"
                continue
            if len(T[k])==2:
                if "cname" not in T[k]: 
                    ret[k]="mixed"
                    continue
                T[k].remove("cname")
            if len(T[k])==0: 
                ret[k]="boh"
                continue
            ret[k]=T[k].pop()
        return ret

    # zone
    def classification(self):
        if not self.is_reverse():
            ret=set()
            for r in self.rows:
                ip_t=r.classification()
                if not ip_t: continue
                ret.add(ip_t)
            if len(ret)>2: return "mixed"
            if len(ret)==2:
                if "cname" not in ret: return "mixed"
                ret.remove("cname")
            if len(ret)==0: return "boh"
            return ret.pop()
        ip_t=filter(lambda x: x.isdigit(),self.name.split("."))
        ip_t.reverse()
        if ip_t[0] in [ "10" ]: 
            return "private"
        if ip_t[0] in [ "127" ]: 
            return "localdomain"
        if ip_t[0] in map(str,range(224,240)):
            return "private" #multicast
        if ip_t[0] not in [ "192","172","169" ]: return "public"
        if len(ip_t)<=1: 
            if ip_t[0] in [ "192","172" ]: return "private"
            return "boh"
        if ip_t[0]=="192":
            if ip_t[1]=="168": return "private"
            return "public"
        if ip_t[0]=="172":
            if ip_t[1] in map(str,range(16,32)): return "private"
            return "public"
        if ip_t[0]=="169":
            if ip_t[1]=="254": return "private" #link-local
            return "public"

    def printable_merged_zone(self):
        if self.is_reverse(): 
            p="R"
            return "    %s %-40.40s %s\n" % (p,self," ".join(map(str,list(self.views_set()))))
        p="D"
        S="    %s %-40.40s %s\n" % (p,self," ".join(map(str,list(self.views_set()))))
        for r in self.def_rows:
            S+=r.printable_merged_record("      ")
        for r in self.rows:
            S+=r.printable_merged_record("      ")
        return S

    def mk_ttl(self,data):
        if type(data)!=list:
            return str(data)
        L=filter(lambda x: x!="_",map(lambda x: x[1],data))
        L=map(int,L)
        if len(L)==0: 
            return "_"
        return str(max(L))

    def get_ttl(self):
        ttl=self.mk_ttl(self.soa_record.data["default_ttl"])
        if ttl!="_": return ttl
        nx_ttl=self.mk_ttl(self.soa_record.data["nx_ttl"])
        if nx_ttl=="_": return "86400"
        return nx_ttl

    def get_nx_ttl(self):
        ttl=self.mk_ttl(self.soa_record.data["nx_ttl"])
        if ttl=="_": return "3600"
        return ttl

    def _get_non_default(self,data,defaults):
        if type(data)!=list:
            return str(data)
        L=filter(lambda x: x!="_",map(lambda x: x[1],data))
        L=filter(lambda x: x not in defaults,L)
        if len(L)==0: return defaults[0]
        if len(L)==1: return L[0]
        return data

    def get_refresh(self):
        data=self.soa_record.data["refresh"]
        return self._get_non_default(data,["86400","900"])
    
    def get_retry(self):
        data=self.soa_record.data["retry"]
        return self._get_non_default(data,["1800","600"])
    
    def get_expiry(self):
        data=self.soa_record.data["expiry"]
        return self._get_non_default(data,["2592000","86400"])

    def get_merged_views_labels(self):
        T=[]
        for vtuple in self.merged_views_sets():
            label="_".join(map(lambda x: x.name,vtuple))
            T.append(label)
        return T

class DnsType(object):
    def __init__(self,dns_type):
        self.dns_type=dns_type
        self.zone_def=self.dns_type in [ "SOA", "WINS", "KEYDATA", "SRV" ]
        self.ip_database=self.dns_type in [ "A", "AAAA", "CNAME", "PTR" ]

    def __hash__(self):
        return hash(self.dns_type)

    def __str__(self):
        return self.dns_type

    def __eq__(self,other): return self.dns_type==other.dns_type

    def __lt__(self,other):
        if self.dns_type==other.dns_type: return False
        for t in [ "SOA", "WINS", "KEYDATA", "SRV", "NS", "MX", "A", "AAAA", "CNAME", "PTR", "TXT", "SPF" ]:
            if self.dns_type==t: return True
            if other.dns_type==t: return False
        return self.dns_type < other.dns_type

    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

    def __add__(self,other):
        if type(other)==DnsType: return self.dns_type+other.dns_type
        if type(other)==str:
            return self.dns_type+other
        return NotImplemented

    def __radd__(self,other):
        if type(other)==DnsType: return self.dns_type+other.dns_type
        if type(other)==str:
            return self.dns_type+other
        return NotImplemented

class RecordData(object):
    def __init__(self,data,ttl):
        self.data=data
        self.ttl=ttl

    def __str__(self): return str(self.ttl)+" "+str(self.data)

    def __hash__(self):
        T=str(self)
        return hash(T)

    def __eq__(self,other):
        if self.ttl!=other.ttl: return False
        return self.data==other.data

    def __lt__(self,other):
        if self.data<other.data: return True
        if self.data>other.data: return False
        return self.ttl<other.ttl

    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

    # record data
    def classification(self,dns_type="A"):
        if dns_type=="CNAME": return "cname"
        if dns_type!="A": return ""
        ip_t=self.data[0].split(".")
        if ip_t[0]=="127": return "localdomain"
        if ip_t[0] in [ "10" ]: 
            return "private"
        if ip_t[0]=="192":
            if ip_t[1]=="168": return "private"
            return "public"
        if ip_t[0]=="172":
            if ip_t[1] in map(str,range(16,32)): return "private"
            return "public"
        if ip_t[0]=="169":
            if ip_t[1]=="254": return "private" #link-local
            return "public"
        if ip_t[0] in map(str,range(224,240)):
            return "private" #multicast
        return "public"

class RecordDataList(list):
    def append_data(self,data,ttl):
        self.append( RecordData(data,ttl) )

    def sort(self,*args,**kwargs):
        self.__init__(list(set(self)))
        list.sort(self,*args,**kwargs)

    # recorddatalist
    def classification(self,dns_type):
        ret=set()
        for r in self:
            ip_t=r.classification(dns_type)
            if not ip_t: continue
            ret.add(ip_t)
        if len(ret)>2: return "mixed"
        if len(ret)==2:
            if "cname" not in ret: return "mixed"
            ret.remove("cname")
        if len(ret)==0: return ""
        return ret.pop()

    def __eq__(self,other): 
        L_self=len(self)
        L_other=len(other)
        if L_self!=L_other: return False
        for n in range(0,L_self):
            if self[n]!=other[n]: return False
        return True

    def __lt__(self,other): 
        L_self=len(self)
        L_other=len(other)
        L=min(L_self,L_other)
        for n in range(0,L):
            if self[n]<other[n]: return True
            if self[n]>other[n]: return False
        return L_self<L_other

    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

### QUIC verificare che i dati siano quelli vecchi e non quelli nuovi
class SoaRecord(object):
    def __init__(self,record):
        self.record=record
        self.multiple=False
        self.data={ "default_ttl": None,
                    "name_server": None,
                    "email_addr": None,
                    "serial_number": None,
                    "refresh": None,
                    "retry": None,
                    "expiry": None,
                    "nx_ttl": None }

    def set_merged_data(self):
        self.multiple=(len(self.record.merged)>1)
        if not self.multiple:
            view_list,rdata_list=self.record.merged[0]
            rdata=rdata_list[0]
            self.data["default_ttl"]=rdata.ttl 
            self.data["name_server"]=rdata.data[0] 
            self.data["email_addr"]=rdata.data[1] 
            self.data["serial_number"]=rdata.data[2] 
            self.data["refresh"]=rdata.data[3] 
            self.data["retry"]=rdata.data[4] 
            self.data["expiry"]=rdata.data[5] 
            self.data["nx_ttl"]=rdata.data[6] 
            return

        self.data={ "default_ttl": [],
                    "name_server": [],
                    "email_addr": [],
                    "serial_number": [],
                    "refresh": [],
                    "retry": [],
                    "expiry": [],
                    "nx_ttl": [] }
        for view_list,rdata_list in self.record.merged:
            views=",".join(map(str,view_list))
            rdata=rdata_list[0]
            self.data["default_ttl"].append( (views,rdata.ttl) )
            self.data["name_server"].append( (views,rdata.data[0]) )
            self.data["email_addr"].append( (views,rdata.data[1]) )
            self.data["serial_number"].append( (views,rdata.data[2]) )
            self.data["refresh"].append( (views,rdata.data[3]) )
            self.data["retry"].append( (views,rdata.data[4]) )
            self.data["expiry"].append( (views,rdata.data[5]) )
            self.data["nx_ttl"].append( (views,rdata.data[6]) )
        for k,vals in self.data.items():
            old_val=vals[0][1]
            uguali=True
            for v,d in vals:
                if d=="_": continue
                if d!=old_val:
                    uguali=False
                    break
            if not uguali: continue
            self.data[k]=old_val

class Record(object):
    def __init__(self,zone,owner,dns_class,dns_type):
        self.owner=owner
        self.dns_class=dns_class
        self.dns_type=DnsType(dns_type)
        self.data=[]
        self.zone=zone
        self.zone_def=self.dns_type.zone_def
        self.merged=[]

    def __eq__(self,other):
        if self.zone!=other.zone: return False
        if self.owner!=other.owner: return False
        if self.dns_class!=other.dns_class: return False
        if self.dns_type!=other.dns_type: return False
        return True

    def __lt__(self,other):
        if self.zone.id<other.zone.id: return True
        if self.zone.id>other.zone.id: return False
        if self.dns_class<other.dns_class: return True
        if self.dns_class>other.dns_class: return False
        if self.dns_type<other.dns_type: return True
        if self.dns_type>other.dns_type: return False
        if self.owner<other.owner: return True
        return False

    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

    def __str__(self):
        return "%2s %-5s %s" % (self.dns_class,self.dns_type,self.owner)

    def append_data(self,view,data,ttl):
        data=filter(lambda x: x!="(" and x!=")",data)
        self.data.append( (view,data,ttl) )

    def views_set(self):
        views=set()
        for d in self.data:
            views.add(d[0])
        return views

    def merge_views(self,debug=False):
        D={}
        for view,data,ttl in self.data:
            if not D.has_key(view.id):
                D[view.id]={ "view": view, "list": RecordDataList() }
            D[view.id]["list"].append_data( data,ttl )
        for desc in D.values():
            desc["list"].sort()
            
        temp_merged=[]
        for vid,desc in D.items():
            N=len(temp_merged)
            if N==0:
                temp_merged.append( ( [desc["view"]], desc["list"] ) )
                continue
            trovato=False
            for n in range(0,N):
                if desc["list"]==temp_merged[n][1]:
                    temp_merged[n][0].append(desc["view"])
                    trovato=True
                    break
            if trovato: continue
            temp_merged.append( ( [desc["view"]], desc["list"] ) )
        self.merged=temp_merged

    # record
    def classification_by_view(self):
        def g(ret):
            if len(ret)>2: return "mixed"
            if len(ret)==2:
                if "cname" not in ret: return "mixed"
                ret.remove("cname")
            if len(ret)==0: return ""
            return ret.pop()
        T={}
        for view_list,rdata_list in self.merged:
            label="_".join(map(lambda x: x.name,view_list))
            ip_t=rdata_list.classification(self.dns_type.dns_type)
            if not ip_t: continue
            if not T.has_key(label): T[label]=set()
            T[label].add(ip_t)
        R={}
        for k in T.keys():
            R[k]=g(T[k])
        return R


    # record
    def classification(self):
        ret=set()
        for view_list,rdata_list in self.merged:
            ip_t=rdata_list.classification(self.dns_type.dns_type)
            if not ip_t: continue
            ret.add(ip_t)
        if len(ret)>2: return "mixed"
        if len(ret)==2:
            if "cname" not in ret: return "mixed"
            ret.remove("cname")
        if len(ret)==0: return ""
        return ret.pop()


    def get_owner(self):
        if self.owner == self.zone.name+".": return "@"
        o=self.zone.re_zone_suffix.subn("",self.owner)[0]
        if not o: return "@"
        return o

    def get_dns_type(self):
        return self.dns_type.dns_type
    
    def get_dns_class(self):
        if self.dns_class=="IN": return ""
        return self.dns_class
    
    def get_ttl(self,r_ttl): 
        t=str(r_ttl)
        if t==self.zone.get_ttl(): return ""
        if t=="_": return ""
        return t
    
    def get_data(self,r_data):
        return " ".join(r_data)

    def printable_record(self,prefix):
        S="%s%2s %-5s %s\n" % (prefix,self.dns_class,self.dns_type,self.owner)
        for view,data,ttl in self.data:
            S+="      %-10s %-6.6s %s\n" % (view,ttl,data)
        return S

    def printable_merged_record(self,prefix):
        S="%s%2s %-5s %s\n" % (prefix,self.dns_class,self.dns_type,self.owner)
        for view_list,rdata_list in self.merged:
            views=",".join(map(str,view_list))
            for rdata in rdata_list:
                S+="      %-30s %-6.6s %s\n" % (views,rdata.ttl,rdata.data)
        return S


class DnsDatabase(object):
    def __init__(self):
        self.zones={}
        self.zones_ip6={}
        self.views={}
        self.zones_by_views={}
        self.zones_multiple_views=[]
        self.zones_multiple_merged=[]
        self.res_names={}
        self.res_ips={}
        self.dns_type_set=set()
        
    def merge_zones(self):
        self.views=self.views.values()
        self.zones=self.zones.values()
        self.zones_ip6=self.zones_ip6.values()
        
        self.views.sort()
        self.zones.sort()
        self.zones_ip6.sort()
    
        for v in self.views:
            self.zones_by_views[v.id]=[]
        
        for zone in self.zones:
            zone.merge_views()
            if zone.reduced=="multiple":
                self.zones_multiple_views.append(zone)
                continue
            if zone.reduced=="merged":
                self.zones_multiple_merged.append(zone)
                continue
            v_set=zone.views_set()
            self.zones_by_views[v_set.pop().id].append(zone)
        
    def build_resolutions(self):
        data_records={ "A": set(),"CNAME": set(),"AAAA": set(),"PTR": set() }
        
        for zone in self.zones:
            for k in data_records.keys():
                data_records[k].update(zone.data_records[k])
        
        res_cnames={}
        
        for k in [ "A","AAAA" ]:
            for r in data_records[k]:
                name=r.owner
                if not self.res_names.has_key(name):
                    self.res_names[name]=ResName(name)
                for view_list,rdata_list in r.merged:
                    for rdata in rdata_list:
                        ip=rdata.data[0]
                        self.res_names[name].add_res(ip,r,view_list)
                        if not self.res_ips.has_key(ip):
                            self.res_ips[ip]=ResIp(ip)
                        self.res_ips[ip].add_res_name(self.res_names[name],view_list)
        
        for k in [ "PTR" ]:
            for r in data_records[k]:
                ip=r.owner
                ip=ip.replace(".in-addr.arpa.","")
                t=ip.split(".")
                t.reverse()
                ip=".".join(t)
                if not self.res_ips.has_key(ip):
                    self.res_ips[ip]=ResIp(ip)
                for view_list,rdata_list in r.merged:
                    for rdata in rdata_list:
                        name=rdata.data[0]
                        self.res_ips[ip].add_res(name,r,view_list)
        
        for k in [ "CNAME" ]:
            for r in data_records[k]:
                cname=r.owner
                if not res_cnames.has_key(cname):
                    res_cnames[cname]=ResCName(cname)
                for view_list,rdata_list in r.merged:
                    for rdata in rdata_list:
                        name=rdata.data[0]
                        res_cnames[cname].add_res(name,r,view_list)
                        if not self.res_names.has_key(name):
                            self.res_names[name]=ResName(name)
                        res_cnames[cname].add_res_name(self.res_names[name],view_list)
        
        self.res_ips=self.res_ips.values()
        self.res_names=self.res_names.values()+res_cnames.values()
        
        self.res_ips.sort()
        self.res_names.sort()

class DnsDatabaseFile(DnsDatabase):
    def __init__(self,datafile):
        super(DnsDatabaseFile,self).__init__()
        self.datafile=datafile
        self.records={}

        print "DNS Database File - Read Datafile"
        self._read_data()

        print "DNS Database File - Merge Zones"
        self.merge_zones()

        print "DNS Database File - Build Resolutions"
        self.build_resolutions()
    

    def _record_factory(self,view,zone,row):
        if len(row)<5: 
            raise WrongRecordSize(len(row))
        owner=row[0]
        if owner=="@":
            owner=zone.name+"."
        elif owner[-1]!=".":
            owner+="."+zone.name+"."
        ttl=row[1]
        dns_class=row[2]
        dns_type=row[3]
        data=row[4:]
        if not self.records.has_key( (zone,owner,dns_class,dns_type) ):
            self.records[(zone,owner,dns_class,dns_type)]=Record(zone,owner,dns_class,dns_type)
            self.dns_type_set.add(dns_type)
        self.records[(zone,owner,dns_class,dns_type)].append_data(view,data,ttl)
        return self.records[(zone,owner,dns_class,dns_type)]

    def _read_data(self):
        view_id=0
        zone_id=0
        fd=open(self.datafile,"r")
        for r in fd.readlines():
            r=r.strip()
            t=r.split()
            view_name=t[0]
            if view_name=="_meta": continue
            zone_name=t[1].replace("'","").split("/")[0]
            if not self.views.has_key(view_name):
                self.views[view_name]=View(view_id,view_name)
                view_id+=1
            if zone_name[-9:]==".ip6.arpa":
                if not self.zones_ip6.has_key(zone_name):
                    self.zones_ip6[zone_name]=Zone(zone_id,zone_name)
                    zone_id+=1
                record=self._record_factory(self.views[view_name],self.zones_ip6[zone_name],t[2:])
                self.zones_ip6[zone_name].append_record(record)
                continue
            if not self.zones.has_key(zone_name):
                self.zones[zone_name]=Zone(zone_id,zone_name)
                zone_id+=1
            record=self._record_factory(self.views[view_name],self.zones[zone_name],t[2:])
            self.zones[zone_name].append_record(record)
        fd.close()

        

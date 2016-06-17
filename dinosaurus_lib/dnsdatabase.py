import os
import re
import copy

from dinosaurus_lib.config import *
from dinosaurus_lib.resolutions import *

def normalize_classification(ret):
    if len(ret)>2: return "mixed"
    if len(ret)==2:
        if "cname" not in ret: return "mixed"
        ret.remove("cname")
    if len(ret)==0: return ""
    return ret.pop()


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

    def __hash__(self):
        return hash(self.id)

class DnsType(object):
    def __init__(self,dns_type):
        self.dns_type=dns_type
        self.zone_def=dns_type in [ "SOA", "WINS", "KEYDATA", "SRV" ]
        self.ip_database=dns_type in [ "A", "AAAA", "CNAME", "PTR" ]

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
            c=r.classification(dns_type)
            if not c: continue
            ret.add(c)
        return normalize_classification(ret)
        # if len(ret)>2: return "mixed"
        # if len(ret)==2:
        #     if "cname" not in ret: return "mixed"
        #     ret.remove("cname")
        # if len(ret)==0: return ""
        # return ret.pop()

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

######

class ViewSet(tuple):
    def __new__ (cls, L):
        return super(ViewSet, cls).__new__(cls, L)

    def __init__(self,L):
        L=list(set(L))
        L.sort()
        self.label="_".join(map(lambda x: x.name,self))

    def __str__(self):
        return "("+", ".join(map(lambda x: str(x),self))+")"

    def cell(self):
        return ", ".join(map(lambda x: x.name,self))

    def __repr__(self): 
        return "("+", ".join(map(lambda x: str(x),self))+")"

    def has_view_by_name(self,view_name):
        return ( view_name in map(lambda v: v.name,self) )

    def has_view(self,view):
        return ( view in self )

    def issubset(self,other): 
        for v in self:
            if not v in other: return False
        return True

    def issuperset(self,other): 
        return other.issubset(self)

    def isdisjoint(self,other):
        for v in self:
            if v in other: return False
        return True

    def union(self,other): 
        L=list(self)+list(other)
        return ViewSet(L)

    def __or__(self,other):
        return self.union(other)

    def __ror__(self,other):
        return other.union(self)

    def intersection(self,other):
        L=[]
        for v in self:
            if v in other: 
                L.append(v)
        return ViewSet(L)

    def __and__(self,other):
        return self.intersection(other)

    def __rand__(self,other):
        return other.intersection(self)

    def difference(self,other):
        L=[]
        for v in self:
            if not (v in other): 
                L.append(v)
        return ViewSet(L)
        
    def __sub__(self,other):
        return self.difference(other)

    def __rsub__(self,other):
        return other.difference(self)

    def symmetric_difference(self,other): 
        U=self.union(other)
        I=self.intersection(other)
        return U.difference(I)

    def __xor__(self,other):
        return self.symmetric_difference(other)

    def __rxor__(self,other):
        return other.symmetric_difference(self)

    # def __deepcopy__

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
        self.merged_views_sets=set()
        self.classifications_per_view_set={}
        self.classification=""

        self.re_zone_suffix=re.compile(r"\."+self.name+r"\.$")

    def remove_zone_suffix(self,owner):
        if owner == self.name+".": 
            return "@"
        new_owner=self.re_zone_suffix.subn("",owner)[0]
        if not new_owner: 
            return "@"
        return new_owner

    def normalize_ttl_by_view_set(self,view_set,ttl):
        t=str(ttl)
        if t==self.get_ttl_by_view_set(view_set): return ""
        if t=="_": return ""
        return t
        

    def __str__(self): return "["+str(self.id)+"] "+self.name

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

    def _reduced(self):
        if len(self.views_list)==1:
            return "single view"
        base_views=None
        for r in self.def_rows:
            if len(r.merged)>1: return "multiple"
            if not base_views:
                base_views=set(r.merged[0][0])
                continue
            if base_views!=set(r.merged[0][0]): 
                return "multiple"
        for r in self.rows:
            if len(r.merged)>1: return "multiple"
            if not base_views:
                base_views=set(r.merged[0][0])
                continue
            if base_views!=set(r.merged[0][0]): 
                return "multiple"
        return "merged"

    def merge_views(self): 
        for r in self.def_rows: r.merge_views()
        for r in self.rows: r.merge_views(debug=False)

        self.merged_views_sets=self._merged_views_set()

        for k in self.special_records.keys():
            self.special_records[k]=list(self.special_records[k])
            self.special_records[k].sort()
        self.soa_record.set_merged_data()
        self.views_list=self._views_list()
        self.reduced=self._reduced()
        self.classifications_per_view_set=self._classifications_per_view_set()
        self.classification=self._classification()

    def _merged_views_set(self):
        vsets=set()
        for r in self.def_rows:
            for view_set,rec_list in r.merged:
                vsets.add( view_set )
        for r in self.rows:
            for view_set,rec_list in r.merged:
                vsets.add( view_set )

        vsets,changed=self._verify_merged_views_sets(vsets,False)
        if not changed: return vsets
        for r in self.def_rows:
            r.replace_views_sets(vsets)
        for r in self.rows:
            r.replace_views_sets(vsets)
        return vsets

    def _verify_merged_views_sets(self,vsets,changed):
        if len(vsets)==1: return vsets,changed
        L=list(vsets)
        for i in range(0,len(L)):
            x=L[i]
            for j in range(0,len(L)):
                if i==j: continue
                y=L[j]
                if x.isdisjoint(y):
                    continue
                changed=True
                L.remove(x)
                L.remove(y)
                if x.issuperset(y):
                    L.append(y)
                    L.append(x-y)
                    return self._verify_merged_views_sets(set(L),changed)
                if x.issubset(y):
                    L.append(x)
                    L.append(y-x)
                    return self._verify_merged_views_sets(set(L),changed)
                i=x&y
                L.append(i)
                L.append(x-i)
                L.append(y-i)
                return self._verify_merged_views_sets(set(L),changed)
        return vsets,changed

    # zone
    def _classifications_per_view_set(self):
        T={}
        if self.is_reverse():
            C=self._classification()
            for view_set in self.merged_views_sets:
                T[view_set]=C
            return T

        for view_set in self.merged_views_sets:
            T[view_set]=set()

        for r in self.rows:
            ip_v=r.classifications_per_view_set
            if not ip_v: continue
            for view_set,ip_t in ip_v.items():
                T[view_set].add(ip_t)

        ret={}
        for k in T.keys():
            c=normalize_classification(T[k])
            if not c: c="boh"
            ret[k]=c
        return ret

    # zone
    def _classification(self):
        if not self.is_reverse():
            ret=set()
            for r in self.rows:
                ip_t=r.classification
                if not ip_t: continue
                ret.add(ip_t)
            c=normalize_classification(ret)
            if not c: c="boh"
            return c

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

    def is_reverse(self):
        t_s=self.name.split(".")
        return t_s[0].isdigit()

    def _views_list(self):
        views=ViewSet([])
        for vset in self.merged_views_sets:
            views=views.union(vset)
        return views

    ###

    def _mk_ttl(self,data):
        if type(data)!=list:
            return str(data)
        def f(x):
            if type(x)==list: return x
            return [x]
        L=filter(lambda x: x!="_",reduce(lambda a,b: a+b,map(lambda x: f(x[1]),data)))
        if len(L)==0: 
            return "_"
        L=map(int,L)
        return str(max(L))

    def get_ttl(self):
        ttl=self._mk_ttl(self.soa_record.data["default_ttl"])
        if ttl!="_": return ttl
        nx_ttl=self._mk_ttl(self.soa_record.data["nx_ttl"])
        if nx_ttl=="_": return "86400"
        return nx_ttl

    def get_nx_ttl(self):
        ttl=self._mk_ttl(self.soa_record.data["nx_ttl"])
        if ttl=="_": return "3600"
        return ttl

    def get_primary_master(self):
        return self.soa_record.data["name_server"]

    def get_email_admin(self):
        return self.soa_record.data["email_addr"]

    def get_serial_number(self):
        return self.soa_record.data["serial_number"]

    def get_refresh(self):
        data=self.soa_record.data["refresh"]
        return max_or_default(map(lambda x: x[1],data),DEFAULTS["refresh"])
    
    def get_retry(self):
        data=self.soa_record.data["retry"]
        return get_non_default(map(lambda x: x[1],data),DEFAULTS["retry"])
    
    def get_expiry(self):
        data=self.soa_record.data["expiry"]
        return get_non_default(map(lambda x: x[1],data),DEFAULTS["expiry"])

    ###

    def get_ttl_by_view_set(self,vset):
        ttl=self.soa_record.data_per_view_set[vset]["default_ttl"]
        if ttl not in ["_",""]: return ttl
        nx_ttl=self.soa_record.data_per_view_set[vset]["nx_ttl"]
        if nx_ttl in ["_",""]: return str(DEFAULTS["ttl"][0])
        return nx_ttl

    def get_nx_ttl_by_view_set(self,vset):
        nx_ttl=self.soa_record.data_per_view_set[vset]["nx_ttl"]
        if nx_ttl in ["_",""]: return str(DEFAULTS["nx_ttl"][0])
        return nx_ttl

    def get_primary_master_by_view_set(self,vset):
        return self.soa_record.data_per_view_set[vset]["name_server"]

    def get_email_admin_by_view_set(self,vset):
        return self.soa_record.data_per_view_set[vset]["email_addr"]

    def get_serial_number_by_view_set(self,vset):
        return self.soa_record.data_per_view_set[vset]["serial_number"]

    def get_refresh_by_view_set(self,vset):
        return self.soa_record.data_per_view_set[vset]["refresh"]

    def get_retry_by_view_set(self,vset):
        return self.soa_record.data_per_view_set[vset]["retry"]
    
    def get_expiry_by_view_set(self,vset):
        return self.soa_record.data_per_view_set[vset]["expiry"]

    ###

    def printable_zone(self,full=False):
        if self.is_reverse(): p="R"
        else: p="D"
        return "    %s %-30.30s %s\n" % (p,self," ".join(map(str,self.views_list)))

    def printable_merged_zone(self):
        if self.is_reverse(): 
            p="R"
            return "    %s %-40.40s %s\n" % (p,self," ".join(map(str,self.views_list)))
        p="D"
        S="    %s %-40.40s %s\n" % (p,self," ".join(map(str,self.views_list)))
        for r in self.def_rows:
            S+=r.printable_merged_record("      ")
        for r in self.rows:
            S+=r.printable_merged_record("      ")
        return S

class Record(object):
    def __init__(self,rid,zone,owner,dns_class,dns_type):
        self.id=rid
        self.owner=owner
        self.dns_class=dns_class
        self.dns_type=DnsType(dns_type)
        self.zone=zone
        self.zone_def=self.dns_type.zone_def

        self.data=[]

        self.merged=[]
        self.classifications_per_view_set={}
        self.classification=""

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
        for v_list,data_list in temp_merged:
            self.merged.append( (ViewSet(v_list),data_list) )
        self.classifications_per_view_set=self._classifications_per_view_set()
        self.classification=self._classification()

    def replace_views_sets(self,zone_views_sets):
        new_merged=[]
        for view_set,data_list in self.merged:
            for zvs in zone_views_sets:
                if view_set.issuperset(zvs):
                    new_merged.append( (zvs,data_list) )
        self.merged=new_merged
        self.classifications_per_view_set=self._classifications_per_view_set()
        self.classification=self._classification()

    # record
    def _classifications_per_view_set(self):
        T={}
        for view_set,rdata_list in self.merged:
            ip_t=rdata_list.classification(self.dns_type.dns_type)
            if not T.has_key(view_set): T[view_set]=set()
            if not ip_t: continue
            T[view_set].add(ip_t)
        R={}
        for k in T.keys():
            R[k]=normalize_classification(T[k])
        return R

    # record
    def _classification(self):
        ret=set()
        for view_list,rdata_list in self.merged:
            ip_t=rdata_list.classification(self.dns_type.dns_type)
            if not ip_t: continue
            ret.add(ip_t)
        return normalize_classification(ret)

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
        self.data_per_view_set={}

    def set_merged_data(self):
        self.multiple=(len(self.record.merged)>1)
        self.data={ "default_ttl": None,
                    "name_server": None,
                    "email_addr": None,
                    "serial_number": None,
                    "refresh": None,
                    "retry": None,
                    "expiry": None,
                    "nx_ttl": None }
        self.data_per_view_set={}
        if len(self.record.merged)==1:
            vset,rdata_list=self.record.merged[0]
            rdata=rdata_list[0]
            self.data["default_ttl"]=rdata.ttl 
            self.data["name_server"]=rdata.data[0] 
            self.data["email_addr"]=rdata.data[1] 
            self.data["serial_number"]=rdata.data[2] 
            self.data["refresh"]=rdata.data[3] 
            self.data["retry"]=rdata.data[4] 
            self.data["expiry"]=rdata.data[5] 
            self.data["nx_ttl"]=rdata.data[6] 
            self.data_per_view_set[vset]={}
            self.data_per_view_set[vset]["default_ttl"]=rdata.ttl 
            self.data_per_view_set[vset]["name_server"]=rdata.data[0] 
            self.data_per_view_set[vset]["email_addr"]=rdata.data[1] 
            self.data_per_view_set[vset]["serial_number"]=rdata.data[2] 
            self.data_per_view_set[vset]["refresh"]=rdata.data[3] 
            self.data_per_view_set[vset]["retry"]=rdata.data[4] 
            self.data_per_view_set[vset]["expiry"]=rdata.data[5] 
            self.data_per_view_set[vset]["nx_ttl"]=rdata.data[6] 
            return

        uni_data={ "default_ttl": set(),
                   "name_server": set(),
                   "email_addr": set(),
                   "serial_number": set(),
                   "refresh": set(),
                   "retry": set(),
                   "expiry": set(),
                   "nx_ttl": set() }

        for vset,rdata_list in self.record.merged:
            rdata=rdata_list[0]
            self.data_per_view_set[vset]={}
            self.data_per_view_set[vset]["default_ttl"]=rdata.ttl 
            self.data_per_view_set[vset]["name_server"]=rdata.data[0] 
            self.data_per_view_set[vset]["email_addr"]=rdata.data[1] 
            self.data_per_view_set[vset]["serial_number"]=rdata.data[2] 
            self.data_per_view_set[vset]["refresh"]=rdata.data[3] 
            self.data_per_view_set[vset]["retry"]=rdata.data[4] 
            self.data_per_view_set[vset]["expiry"]=rdata.data[5] 
            self.data_per_view_set[vset]["nx_ttl"]=rdata.data[6] 

            uni_data["default_ttl"].add(rdata.ttl )
            uni_data["name_server"].add(rdata.data[0] )
            uni_data["email_addr"].add(rdata.data[1] )
            uni_data["serial_number"].add(rdata.data[2] )
            uni_data["refresh"].add(rdata.data[3] )
            uni_data["retry"].add(rdata.data[4] )
            uni_data["expiry"].add(rdata.data[5] )
            uni_data["nx_ttl"].add(rdata.data[6] )

        for k in uni_data.keys():
            if len(uni_data[k])==1:
                self.data[k]=uni_data[k].pop()
                continue
            self.data[k]=[]
            for vset in self.data_per_view_set.keys():
                self.data[k].append( (vset,self.data_per_view_set[vset][k]) )

class DnsDatabase(object):
    def __init__(self,name):
        self.name=name

        self.zones=[]
        self.zones_ip6=[]
        self.views=[]
        self.dns_type_set=set()

        ### calculate
        self.zones_by_views={}
        self.zones_multiple_views=[]
        self.zones_multiple_merged=[]
        self.res_names={}
        self.res_ips={}

    def clone_view(self,view,memo={}):
        new_view=View( copy.deepcopy(view.id,memo),
                       copy.deepcopy(view.name,memo) )
        return new_view

    def clone_zone(self,zone,views={},memo={}):
        new_zone=Zone(copy.deepcopy(zone.id,memo),
                      copy.deepcopy(zone.name,memo))
        for record in zone.rows+zone.def_rows:
            new_record=Record(record.id,
                              new_zone,
                              copy.deepcopy(record.owner,memo),
                              copy.deepcopy(record.dns_class,memo),
                              copy.deepcopy(record.dns_type.dns_type,memo))
            for view,data,ttl in record.data:
                if views.has_key(view.name):
                    new_view=views[view.name]
                else:
                    new_view=copy.deepcopy(view,memo)
                new_record.data.append( ( new_view,
                                          copy.deepcopy(data,memo),
                                          copy.deepcopy(ttl,memo) ) )
            new_zone.append_record(new_record)
        return new_zone

    def __deepcopy__(self,memo):
        new_db=DnsDatabase(self.name)
        new_db.dns_type_set=copy.deepcopy(self.dns_type_set,memo)

        def c_view(view):
            return self.clone_view(view,memo=memo)

        views_dict={}
        for v in new_db.views:
            views_dict[v.name]=v

        def c_zone(zone):
            return self.clone_zone(zone,views=views_dict,memo=memo)

        new_db.views=map(c_view,self.views)
        new_db.zones=map(c_zone,self.zones)
        new_db.zones_ip6=map(c_zone,self.zones_ip6)

        # for view in self.views:
        #     new_view=c_view(view)
        #     new_db.views.append(new_view)
        # for zone in self.zones_ip6:
        #     new_zone=c_zone(zone)
        #     new_db.zones_ip6.append(new_zone)
        # for zone in self.zones:
        #     new_zone=c_zone(zone)
        #     new_db.zones.append(new_zone)
        return new_db


    def calculate(self):
        self.merge_zones()
        self.build_resolutions()
        
    def merge_zones(self):
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
            self.zones_by_views[zone.views_list[0].id].append(zone)
        
    def build_resolutions(self):
        data_records={ "A": set(),"CNAME": set(),"AAAA": set(),"PTR": set() }
        
        for zone in self.zones:
            for k in data_records.keys():
                data_records[k].update(zone.data_records[k])
        
        res_cnames={}
        res_ptrnames={}
        res_anames={}
        
        for k in [ "A","AAAA" ]:
            for r in data_records[k]:
                name=r.owner
                if not res_anames.has_key(name):
                    res_anames[name]=ResAName(name)
                for view_list,rdata_list in r.merged:
                    for rdata in rdata_list:
                        ip=rdata.data[0]
                        res_anames[name].add_res(ip,r,view_list)
                        if not self.res_ips.has_key(ip):
                            self.res_ips[ip]=ResIp(ip)
                        self.res_ips[ip].add_res_name(res_anames[name],view_list)
        
        for k in [ "CNAME" ]:
            for r in data_records[k]:
                cname=r.owner
                if not res_cnames.has_key(cname):
                    res_cnames[cname]=ResCName(cname)
                for view_list,rdata_list in r.merged:
                    for rdata in rdata_list:
                        name=rdata.data[0]
                        res_cnames[cname].add_res(name,r,view_list)
                        if not res_anames.has_key(name):
                            res_anames[name]=ResAName(name)
                        res_cnames[cname].add_res_name(res_anames[name],view_list)
        
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
                        if res_cnames.has_key(name):
                            res_cnames[name].add_res_ip(self.res_ips[ip],view_list)
                        if not res_anames.has_key(name) and not res_cnames.has_key(name):
                            if not res_ptrnames.has_key(name):
                                res_ptrnames[name]=ResPTRName(name)
                            res_ptrnames[name].add_res(ip,r,view_list)
                            res_ptrnames[name].add_res_ip(self.res_ips[ip],view_list)
        

        self.res_ips=self.res_ips.values()
        self.res_names=res_anames.values()+res_cnames.values()+res_ptrnames.values()
        
        self.res_ips.sort()
        self.res_names.sort()

class DnsDatabasePickled(DnsDatabase):
    def __init__(self,fname):
        fd=open(fname,'r')
        pickle.load(self,fd)
        fd.close()

class DnsDatabaseFile(DnsDatabase):
    class RecordFactory(object):
        def __init__(self):
            self._records={}
            self._record_index=0
            self.dns_type_set=set()

        def __call__(self,view,zone,row):
            if len(row)<5: 
                print view,zone,row
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
            owner=owner.lower()
            if not self._records.has_key( (zone,owner,dns_class,dns_type) ):
                self._records[(zone,owner,dns_class,dns_type)]=Record(self._record_index,zone,owner,dns_class,dns_type)
                self._record_index+=1
                self.dns_type_set.add(dns_type)
            self._records[(zone,owner,dns_class,dns_type)].append_data(view,data,ttl)
            return self._records[(zone,owner,dns_class,dns_type)]

    def __init__(self,datafile,name):
        super(DnsDatabaseFile,self).__init__(name)
        self.datafile=datafile

        print "DNS Database File - Read Datafile"
        self._read_data()

        print "DNS Database File - Merge Zones"
        self.calculate()

    def _read_data(self):
        record_factory=self.RecordFactory()
        view_id=0
        zone_id=0
        zones={}
        zones_ip6={}
        views={}
        fd=open(self.datafile,"r")
        for r in fd.readlines():
            r=r.strip()
            t=r.split()
            view_name=t[0]
            if view_name=="_meta": continue
            zone_name=t[1].replace("'","").split("/")[0]
            if not views.has_key(view_name):
                views[view_name]=View(view_id,view_name)
                view_id+=1
            if zone_name[-9:]==".ip6.arpa":
                if not zones_ip6.has_key(zone_name):
                    zones_ip6[zone_name]=Zone(zone_id,zone_name)
                    zone_id+=1
                record=record_factory(views[view_name],zones_ip6[zone_name],t[2:])
                zones_ip6[zone_name].append_record(record)
                continue
            if not zones.has_key(zone_name):
                zones[zone_name]=Zone(zone_id,zone_name)
                zone_id+=1
            record=record_factory(views[view_name],zones[zone_name],t[2:])
            zones[zone_name].append_record(record)
        fd.close()
        self.dns_type_set=record_factory.dns_type_set
        self.views=views.values()
        self.zones=zones.values()
        self.zones_ip6=zones_ip6.values()
        

        

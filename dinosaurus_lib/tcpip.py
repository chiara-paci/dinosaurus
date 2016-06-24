# -*- coding: utf-8 -*-
import sys,re
import os,datetime
import shutil
import math
import bisect
import collections

from dinosaurus_lib.config import *
from dinosaurus_lib.functions import *
from dinosaurus_lib.dnsdatabase import Zone,Record
from dinosaurus_lib.tables import Table
from dinosaurus_lib.resolutions import ResName,ResIp

def to_ip(s):
    if isinstance(s,Ip): return s
    if not s: return None
    d=map(int,s.split("."))
    if len(d)!=4: return None
    return Ip(d[0],d[1],d[2],d[3])

def split_vlans(first,last):
    """ Prende un range di ip e ritorna un insieme di VLan correttamente suddivise.

    :param first: primo ip del range
    :param last:  ultimo ip del range

    :return: lista di VLan
    """
    first=to_ip(first)
    last=to_ip(last)
    if first==last: return []
    q=int(first)

    # il massimo divisore, potenza di due, di int(first) è la
    # lunghezza della rete massima di cui first è netaddress
    n=1
    while n<=math.pow(2,32):
        if (q%n)!=0:
            break
        n*=2
    # n esce dal ciclo come il primo non divisore
    n/=2

    while last<first+n-1: n/=2
    if last==first+n-1:
        return [VLan(first,last=first+n-1)]
    return [VLan(first,last=first+n-1)]+split_vlans(first+n,last)

class Ip(collections.Sequence):
    def __init__(self,p3,p2,p1,p0):
        self.p0=int(p0)
        self.p1=int(p1)
        self.p2=int(p2)
        self.p3=int(p3)
        self.public=self._public()
        self.localhost=(self.p3==127)

    def _public(self):
        if self.p3 in [10,127]: return False
        if self.p3==192 and self.p2==168: return False
        if self.p3==172 and self.p2 in range(16,32): return False
        return True

    def __len__(self): return 4

    def __getitem__(self,ind):
        if type(ind) not in [int,slice]: 
            raise TypeError("%s is unsupported as key for Ip used as tuple" % str(type(ind)))
        if type(ind)==int:
            if ind in [0,-4]: return self.p3
            if ind in [1,-3]: return self.p2
            if ind in [2,-2]: return self.p1
            if ind in [3,-1]: return self.p0
            raise IndexError("%d is unsupported as key for Ip used as tuple" % ind)
        start,stop,step=ind.indices(4)
        ind_range=range(start,stop,step)
        if not ind_range: return ()
        ret=map(self.__getitem__,ind_range)
        return tuple(ret)

    def __eq__(self,other):
        return ( (self.p0==other.p0) and (self.p1==other.p1) and (self.p2==other.p2) and (self.p3==other.p3) )

    def __lt__(self,other):
        if self.p3==127 and other.p3!=127:
            return True
        if other.p3==127 and self.p3!=127:
            return False
        if self.p3==10 and other.p3!=10:
            return True
        if other.p3==10 and self.p3!=10:
            return False
        if ( ((self.p3==172) and (self.p2 in range(16,32))) and 
             ((other.p3!=172) or (other.p2 not in range(16,32))) ):
            return True
        if ( ((other.p3==172) and (other.p2 in range(16,32))) and 
             ((self.p3!=172) or (self.p2 not in range(16,32))) ):
            return False
        if ( ((self.p3==192) and (self.p2==168)) and 
             ((other.p3!=192) or (other.p2!=168)) ):
            return True
        if ( ((other.p3==192) and (other.p2==168)) and 
             ((self.p3!=192) or (self.p2!=168)) ):
            return False
        if self.p3 < other.p3: return True
        if self.p3 > other.p3: return False
        if self.p2 < other.p2: return True
        if self.p2 > other.p2: return False
        if self.p1 < other.p1: return True
        if self.p1 > other.p1: return False
        if self.p0 < other.p0: return True
        return False

    def __ne__(self,other): return not self.__eq__(other)
    def __gt__(self,other): return other.__lt__(self)
    def __le__(self,other): return self.__eq__(other) or self.__lt__(other)
    def __ge__(self,other): return self.__eq__(other) or self.__gt__(other)

    # ip+num
    def __add__(self,other):
        if type(other)!=int:
            return NotImplemented
        if self.p0+other<=255:
            return(Ip(self.p3,self.p2,self.p1,self.p0+other))
        S=self.p0+other
        riporto=S/256
        new_p0=S%256
        if self.p1+riporto<=255:
            return(Ip(self.p3,self.p2,self.p1+riporto,new_p0))
        S=self.p1+riporto
        riporto=S/256
        new_p1=S%256
        if self.p2+riporto<=255:
            return(Ip(self.p3,self.p2+riporto,new_p1,new_p0))
        S=self.p2+riporto
        riporto=S/256
        new_p2=S%256
        if self.p3+riporto<=255:
            return(Ip(self.p3+riporto,new_p2,new_p1,new_p0))
        return(Ip(255,new_p2,new_p1,new_p0))

    # num+ip
    def __radd__(self,other): return self.__add__(other)

    # ip=ip-num o num=ip-ip
    def __sub__(self,other): 
        if type(other)==int: return self._sub_int(other)
        return self._sub_ip(other)

    def _sub_int(self,other):
        if self.p0-other>=0:
            return(Ip(self.p3,self.p2,self.p1,self.p0-other))
        S=other-self.p0
        riporto=S/256+1
        new_p0=256-S%256
        if self.p1-riporto>=0:
            return(Ip(self.p3,self.p2,self.p1-riporto,new_p0))
        S=riporto-self.p1
        riporto=S/256+1
        new_p1=256-S%256
        if self.p2-riporto>=0:
            return(Ip(self.p3,self.p2-riporto,new_p1,new_p0))
        S=riporto-self.p2
        riporto=S/256+1
        new_p2=256-S%256
        if self.p3-riporto>=0:
            return(Ip(self.p3-riporto,new_p2,new_p1,new_p0))
        return(Ip(0,new_p2,new_p1,new_p0))

    def _sub_ip(self,other): 
        return self.__int__()-other.__int__()

    def __int__(self):
        return self.p0+256*self.p1+256*256*self.p2+256*256*256*self.p3

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return u".".join(map(unicode,[self.p3,self.p2,self.p1,self.p0]))

    def __hash__(self):
        return hash(str(self))

class VLanDesc(dict):
    def __init__(self,data,competenza_map):
        dict.__init__(self)

        self[u"net"]= data[0]
        self[u"netmask"]=data[1]
        self[u"vid"]=data[2]
        self[u"desc"]=data[3]
        aggiuntivi = [ u"location",
                       u"address",
                       u"dubbio",
                       u"competenza",
                       u"note",
                       u"tabella" ]
        
        for n in range(0,len(aggiuntivi)):
            if len(data)>4+n:
                self[aggiuntivi[n]]=unicode_convert(data[n+4])
            else:
                self[aggiuntivi[n]]=u""

        if not self[u"vid"]: self[u"vid"]=u"="
        if not self[u"netmask"]: 
            self[u"netmask"]=24
        else: 
            self[u"netmask"]=int(self[u"netmask"])
        if not self[u"desc"]: 
            if self[u"vid"] and self[u"vid"]!=u"=":
                self[u"desc"]=u"vlan "+unicode(self[u"vid"])

        if self.has_key(u"competenza") and self[u"competenza"]:
            if competenza_map.has_key(self[u"competenza"]):
                self[u"competenza_color"]=competenza_map[self[u"competenza"]]
            else:
                self[u"competenza_color"]=u"yellow"
        else:
            self[u"competenza_color"]=u""


class VLan(object):
    def __init__(self,net,netmask=-1,last="",desc={},public=None):
        self.desc=desc

        self.net=to_ip(net)
        self.last=to_ip(last)
        self.netmask=netmask

        if (self.netmask<0) and self.last:
            L=self.last-self.net+1
            self.netmask=32-int(math.log(L,2))
        elif (self.netmask>=0) and not self.last:
            L=int(math.pow(2,32-self.netmask))
            self.last=self.net+L-1

        self.fixed=(desc!=None)

        if self.net:
            self.localhost=self.net.localhost
        else:
            self.localhost=False

        if public!=None:
            self.public=public
        elif self.netmask==0:
            self.public=True
        else:
            self.public=self.net.public

        if desc:
            self.vid=desc[u"vid"]
        else:
            self.vid=None

    def __hash__(self):
        return hash(unicode(self))

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        if self.localhost:
            return u"localhost"
        if self.netmask==32:
            return unicode(self.net)
        return unicode(self.net)+u"/"+unicode(self.netmask)

    def __eq__(self,other):
        return self.net==other.net and self.netmask==other.netmask

    def __lt__(self,other):
        return self.net<other.net

    def __ne__(self,other): return not self.__eq__(other)
    def __gt__(self,other): return other.__lt__(self)
    def __le__(self,other): return self.__eq__(other) or self.__lt__(other)
    def __ge__(self,other): return self.__eq__(other) or self.__gt__(other)

    def contains(self,ip):
        return (ip>=self.net) and (ip<=self.last)

class ImplicitVLan(VLan):
    def __init__(self,ip,netmask=24):
        ip=to_ip(ip)
        net=Ip(ip.p3,ip.p2,ip.p1,0)
        VLan.__init__(self,net,netmask)

class VirtualVLan(VLan):
    def __init__(self,name,pos,public=False):
        VLan.__init__(self,u"",public=public)
        self.name=name
        self.pos=pos
        self.adr_list=[]

    def append(self,ip):
        self.adr_list.append(to_ip(ip))

    def contains(self,ip):
        ip=to_ip(ip)
        return (ip in self.adr_list)

    def __str__(self):
        return self.name

    def __eq__(self,other):
        if isinstance(other,VirtualVLan):
            return self.name==other.name and self.pos==other.pos
        return False

    def __lt__(self,other):
        if isinstance(other,VirtualVLan):
            return self.pos<other.pos
        return False

    def __ne__(self,other): 
        if isinstance(other,VirtualVLan):
            return not self.__eq__(other)
        return True

    def __gt__(self,other): 
        if isinstance(other,VirtualVLan):
            return other.__lt__(self)
        return True

class VLanManager(dict):
    def __init__(self,fname,competenza_map={}):
        dict.__init__(self)
        self._ordered_vlans=[]
        self._load(fname,competenza_map)

    def _load(self,fname,competenza_map):
        v_net_list=[]
        fd=open(fname,"r")
        for r in fd.readlines():
            t=r.strip().split(":")
            desc=VLanDesc(t,competenza_map)
            v_net_list.append(VLan(desc[u"net"],netmask=int(desc[u"netmask"]),desc=desc))
            fd.close()
        v_net_list.sort()

        first=Ip(10,0,0,0)
        aggiungi=True
        for vnet in v_net_list:
            aggiungi,first=self._add_vlans(aggiungi,first,vnet)

    def _fill_vlans(self,first,last):
        map(self._append_vlan,split_vlans(first,last))

    def _add_vlans(self,aggiungi,first,vnet):
        """ Riempie i buchi finché ci sono reti private.

        :param aggiungi: flag
        :param first:    primo ip da considerare
        :param vnet:     prima vlan nota

        :return: flag,nuove_vlan,prossimo_first
        """

        ## reti private terminate
        if not aggiungi: 
            self._append_vlan(vnet)
            return (False,None)

        ## vnet viene prima di first
        if first>=vnet.net:
            self._append_vlan(vnet)
            return (True,vnet.last+1)

        ## il primo ottetto è uguale
        if first.p3==vnet.net.p3:
            self._fill_vlans(first,vnet.net-1)
            self._append_vlan(vnet)
            return (True,vnet.last+1)

        if first.p3==10:
            self._fill_vlans(first,u"10.255.255.255")
            if vnet.net.p3==172 and vnet.net.p2 in range(16,32):
                new_first=Ip(172,16,0,0)
                if new_first!=vnet.net:
                    self._fill_vlans(new_first,vnet.net-1)
                self._append_vlan(vnet)
                return (True,vnet.last+1)
            self._fill_vlans(u"172.16.0.0",u"172.31.255.255")
            if vnet.net.p3==192 and vnet.net.p2==168:
                new_first=Ip(192,168,0,0)
                if new_first!=vnet.net:
                    self._fill_vlans(new_first,vnet.net-1)
                self._append_vlan(vnet)
                return (True,vnet.last+1)
            self._fill_vlans(u"192.168.0.0",u"192.168.255.255")
            self._append_vlan(vnet)
            return (False,None)

        if first.p3==172 and first.p2 in range(16,32):
            self._fill_vlans(first,u"172.31.255.255")
            if vnet.net.p3==192 and vnet.net.p2==168:
                new_first=Ip(192,168,0,0)
                if new_first!=vnet.net:
                    self._fill_vlans(new_first,vnet.net-1)
                self._append_vlan(vnet)
                return (aggiungi,vnet.last+1)
            self._fill_vlans(u"192.168.0.0",u"192.168.255.255")
            self._append_vlan(vnet)
            return (False,None)

        if first.p3==192 and first.p2==168:
            self._fill_vlans(first,u"192.168.255.255")
            self._append_vlan(vnet)
            return (False,None)

        self._append_vlan(vnet)
        return False,None

    def all_vlans(self):
        return self._ordered_vlans

    def _append_vlan(self,vlan):
        self[vlan.net]=vlan
        i=bisect.bisect_right(self._ordered_vlans,vlan)
        self._ordered_vlans.insert(i,vlan)

    def __call__(self,obj):
        if isinstance(obj,VLan):
            return obj
        ip_obj=to_ip(obj)
        for vlan in self._ordered_vlans:
            if vlan.contains(ip_obj):
                return vlan
        vlan=ImplicitVLan(ip_obj)
        self._append_vlan(vlan)
        return vlan


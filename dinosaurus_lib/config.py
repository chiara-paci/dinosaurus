# -*- coding: utf-8 -*-
import datetime

PAGINATION=250

PRIMARY_MASTER="rvvmdns03pl.server.intra.rve." 
EMAIL_ADMIN="nsmaster.regione.veneto.it."

BASE_DIR="/home/chiara/dinosaurus"

VERSION_FILE="/home/chiara/dinosaurus/VERSION"
fd=open(VERSION_FILE,'r')
VERSION="".join(fd.readlines()).strip()
fd.close()

THEMES_DIR=BASE_DIR+"/share/themes"

TEMPLATES_HTML=BASE_DIR+"/var/templates/html"
TEMPLATES_CSS=BASE_DIR+"/var/templates/css"
TEMPLATES_IMG=BASE_DIR+"/var/templates/img"
TEMPLATES_JS=BASE_DIR+"/var/templates/js"
TEMPLATES_FONTS=BASE_DIR+"/var/templates/fonts"

t=datetime.datetime.today()
SERIAL_NUMBER="%4.4d%2.2d%2.2d%2.2d" % (t.year,t.month,t.day,00)

HTML_BASE_VAR = { "VERSION": VERSION,
                  "TIMESTAMP": t.strftime("%A, %d %B %Y - %H:%M") }

DEFAULTS={
    "ttl": [86400],
    "nx_ttl": [3600],
    "refresh": [86400,900],
    "retry": [1800,600],
    "expiry": [2592000,86400],
}

def get_non_default(data,defaults):
    """ Ritorna gli elementi che non hanno un valore di default, o il primo dei valori di default. 
    
    :param data: Array di valori. Gli elementi uguali a "_" vengono ignorati.
    :param defaults: Array di valori di default.
    :return: * Se nessun elemento di data ha un valore non di default, ritorna il primo elemento di defaults.
             * Se un solo elemento ha un valore non di default, ritorna quell'elemento.
             * Altrimenti ritorna un array con gli elementi non di default. 
    """
    defaults=map(str,defaults)
    if type(data)!=list:
        return str(data)
    L=filter(lambda x: x!="_",data)
    L=filter(lambda x: x not in defaults,L)
    if len(L)==0: return defaults[0]
    if len(L)==1: return L[0]
    return L

def max_or_default(data,defaults):
    """ Ritorna il maggiore degli elementi che non hanno un valore di default, o il primo dei valori di default. 
    
    :param data: Array di valori. Gli elementi uguali a "_" vengono ignorati.
    :param defaults: Array di valori di default.
    :return: * Se nessun elemento di data ha un valore non di default, ritorna il primo elemento di defaults.
             * Altrimenti ritorna il maggiore degli elementi non di default, trasfromato in stringa. 
    """
    x=get_non_default(data,defaults)
    if not x: return defaults[0]
    if type(x)!=list: return str(x)
    return str( max(map(int,x)) )

def min_or_default(data,defaults):
    """ Ritorna il minore degli elementi che non hanno un valore di default, o il primo dei valori di default. 
    
    :param data: Array di valori. Gli elementi uguali a "_" vengono ignorati.
    :param defaults: Array di valori di default.
    :return: * Se nessun elemento di data ha un valore non di default, ritorna il primo elemento di defaults.
             * Altrimenti ritorna il minore degli elementi non di default, trasformato in stringa. 
    """
    x=get_non_default(data,defaults)
    if not x: return defaults[0]
    if type(x)!=list: return str(x)
    return str( min(map(int,x)) )
    
class GetSequence(object):
    """ Oggetti callable che generano numeri in sequenza. """
    def __init__(self):
        self.val=-1

    def __call__(self):
        self.val+=1
        return self.val

def ip_cmp(x,y):
    """ 
    Confronto tra due ip. 

    :param x: ip
    :param y: ip
    :return: * 1 se x>y; 
             * 0 se x==y; 
             * -1 se x<y. 

    """

    if x==y: return 0
    if y=="::1": return  1
    if x=="::1": return -1
    try:
        x_t=map(int,x.split(".")[:4])
    except ValueError, e:
        return -1
    try:
        y_t=map(int,y.split(".")[:4])
    except ValueError, e:
        return 1
    if (x_t[0]==127) and (y_t[0]!=127):
        return -1
    if (x_t[0]!=127) and (y_t[0]==127):
        return 1

    if (x_t[0] in [ 127,0,10 ]) and (y_t[0] not in [ 127,0,10 ]):
        return -1
    if (x_t[0] not in [ 127,0,10 ]) and (y_t[0] in [ 127,0,10 ]):
        return 1
    if (x_t[0]==172) and (x_t[1] in range(16,32)):
        if (y_t[0]!=172): return -1
        if (y_t[1] not in range(16,32)): return -1
    if (y_t[0]==172) and (y_t[1] in range(16,32)):
        if (x_t[0]!=172): return 1
        if (x_t[1] not in range(16,32)): return 1
    if (x_t[0]==192) and (x_t[1]==168):
        if (y_t[0]!=192): return -1
        if (y_t[1]!=168): return -1
    if (y_t[0]==192) and (y_t[1]==168):
        if (x_t[0]!=192): return 1
        if (x_t[1]!=168): return 1
    if (x_t[0]==169) and (x_t[1]==254):
        if (y_t[0]!=169): return -1
        if (y_t[1]!=254): return -1
    if (y_t[0]==169) and (y_t[1]==254):
        if (x_t[0]!=169): return 1
        if (x_t[1]!=254): return 1
    for n in range(0,4):
        if x_t[n]<y_t[n]: return -1
        if x_t[n]>y_t[n]: return 1
    return 0






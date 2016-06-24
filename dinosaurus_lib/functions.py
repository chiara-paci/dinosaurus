def unicode_convert(txt):
    if type(txt)==unicode: return txt
    if type(txt)!=str: return unicode(txt)
    return unicode(txt.decode('utf-8'))



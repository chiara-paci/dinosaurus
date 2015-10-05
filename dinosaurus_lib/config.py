import datetime

PAGINATION=250

PRIMARY_MASTER="rvvmdns03pl.server.intra.rve." 
EMAIL_ADMIN="nsmaster.regione.veneto.it."

BASE_DIR="/home/chiara/dinosaurus"
TEMPLATES_HTML=BASE_DIR+"/var/templates/html"
TEMPLATES_CSS=BASE_DIR+"/var/templates/css"

t=datetime.datetime.today()
SERIAL_NUMBER="%4.4d%2.2d%2.2d%2.2d" % (t.year,t.month,t.day,00)





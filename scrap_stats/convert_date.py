org_date = 'Thu Aug 24 14:00:00 2006'
o_date = org_date[:11]+org_date[-4:]
o_time = org_date[11:-4]
r_date = o_date+' '+o_time
import time

from datetime import datetime                
ds=time.strptime(o_date+' '+o_time,"%a %b %d %Y %H:%M:%S ")
dt = datetime.fromtimestamp(time.mktime(ds))
epoch = datetime.utcfromtimestamp(0)
print((dt-epoch).total_seconds())

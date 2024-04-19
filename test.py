import datetime
import time

# create a datetime object for the desired date
dt = datetime.datetime(year=2023, month=5, day=23, hour=0, minute=0, second=0)

# convert the datetime object to UTC epoch time
epoch_time = int(time.mktime(dt.timetuple()))

print(epoch_time)

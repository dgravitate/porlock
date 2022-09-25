from datetime import timedelta

UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def convert_to_seconds(s):
    count = int(s[:-1])
    unit = UNITS[s[-1]]
    td = timedelta(**{unit: count})
    return td.seconds + 60 * 60 * 24 * td.days


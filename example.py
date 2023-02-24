from datetime import datetime, timedelta

from porlock.mixins import BaseRiskMixin
from porlock.rules import registry

test_rules = [
    ["Password Change After OTP Login", "otp login", "followed by", "any", ["password change"], "after", "2d", "user", ["password change"], "before", "1h", "14d", "30d"]
    # ["Password Change After OTP Login", "otp login", "followed by", "all", ["password change", "password reset", "account locked"], "after", "2d", "user", ["password change"], "before", "1h", "14d", "30d"]
]

for rule in test_rules:
    registry.register(rule[0], rule[1:])

events = []

print(registry.rules)


class Event(BaseRiskMixin):
    event_type_field = 'event'
    event_date_field = 'event_date'
    event_actor_field = None
    event_instance_field = 'user'

    def __init__(self, **kwargs):
        for item, value in kwargs.items():
            setattr(self, item, value)

    def __str__(self):
        return f"{self.event} for user {self.user}: [{self.event_date}]"

    @classmethod
    def load_related_events(cls, ruleset, match):
        matching_events = []
        for event in events:
            if event.user == match.user:
                matching_events.append(event)
        return matching_events


def load_events_for_analysis():
    """ Load an initial set of rules """
    return events


def load_related_events(ruleset, event):
    """ Load more rules based on the criteria in the matching event """
    return events


events.append(Event(event="otp login", event_date=datetime.now(), user=1))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(minutes=20), user=1))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(days=5), user=1))
events.append(Event(event="password reset", event_date=datetime.now() + timedelta(days=5), user=1))
events.append(Event(event="account locked", event_date=datetime.now() + timedelta(days=5), user=1))

events.append(Event(event="otp2 login", event_date=datetime.now() + timedelta(days=5), user=2))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(days=13), user=1))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(days=5), user=2))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(days=20), user=1))


print("=============================")
for rule, original_event, risk_event in Event.identify_risk(load_events_for_analysis()):
    print(rule)
    print("     ", original_event)
    print("          ", risk_event.event, risk_event.event_date)
print("=============================")

print("=============================")
for rule, original_event, risk_event in Event.identify_risk(load_events_for_analysis(), aggregate_events=True):
    print(rule)
    print("     ", original_event)
    for event in risk_event:
        print("          ", event.event, event.event_date)
print("=============================")

from datetime import datetime, timedelta

from porlock.mixins import BaseRiskMixin
from porlock.rules import registry
from porlock import snoop

test_rules = [
    ["Password Change After OTP Login", "otp login", "followed by", "any", ["password change"], "after", "2d", "user", ["password change"], "before", "1h", "14d", "30d"]
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
        return self.event

    @classmethod
    def load_related_events(cls, ruleset, match):
        return events


def load_events_for_analysis():
    """ Load an initial set of rules """
    return events


def load_related_events(ruleset, event):
    """ Load more rules based on the criteria in the matching event """
    return events


events.append(Event(event="otp login", event_date=datetime.now(), user=1))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(minutes=20), user=1))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(days=5), user=1))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(days=5), user=2))
events.append(Event(event="password change", event_date=datetime.now() + timedelta(days=20), user=1))

#for ruleset, match in snoop.find_rule_match(load_events_for_analysis()):
#    related_events = load_related_events(ruleset, match)
#    for risk in snoop.inspect_related_events(ruleset, match, related_events):
#        print("Risk identified!", risk, risk[1].risk_event_type, risk[1].risk_event_date, risk[1].risk_event_instance)

Event.identify_risk(load_events_for_analysis())

from datetime import timedelta

from .rules import registry


def find_rule_match(events):
    rules = {}

    for event in events:
        # print(event, event.risk_event_type, event.additional_data["events"])
        if event.risk_event_type not in rules:
            rules[event.risk_event_type] = registry.rules_for_event(event.risk_event_type)

        if rules[event.risk_event_type]:
            yield rules[event.risk_event_type], event


def inspect_related_events(ruleset, match, events):
    for rule in ruleset:
        if rule[9] >= 0:
            rule_start_time = match.risk_event_date + timedelta(seconds=rule[9])
            rule_end_time = match.risk_event_date + timedelta(seconds=rule[10])
        else:
            rule_start_time = match.risk_event_date + timedelta(seconds=rule[10])
            rule_end_time = match.risk_event_date + timedelta(seconds=rule[9])

        for event in events:
            if event.risk_event_type.lower() in [x.lower() for x in rule[3]]:
                if rule_start_time <= event.risk_event_date <= rule_end_time:
                    yield rule, event

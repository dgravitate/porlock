import typing

from .enums import Match
from .rules import registry


def find_rule_match(events) -> (str, typing.Any):
    rules = {}

    for event in events:
        if event.risk_event_type not in rules:
            rules[event.risk_event_type] = registry.rules_for_event(event.risk_event_type)

        if rules[event.risk_event_type]:
            yield rules[event.risk_event_type], event


def inspect_related_events(ruleset, match, events) -> (str, typing.Any, typing.Any):
    for rule in ruleset:
        rule_events = set([x.lower() for x in rule.match_events])
        rule_start_time, rule_end_time = match.construct_date_range(rule)

        if rule.match in [Match.ANY.value, Match.NONE.value]:
            for event in events:
                if rule.match == Match.ANY.value:
                    if event.risk_event_type.lower() in rule_events:
                        if rule_start_time <= event.risk_event_date <= rule_end_time:
                            yield rule, match, event
                elif rule.match == Match.NONE.value:
                    if event.risk_event_type.lower() not in rule_events:
                        if rule_start_time <= event.risk_event_date <= rule_end_time:
                            yield rule, match, event
        elif rule.match == Match.ALL.value:
            """ Match all event types """
            matched_events = []
            for event in events:
                if event.risk_event_type.lower() in rule_events:
                    if rule_start_time <= event.risk_event_date <= rule_end_time:
                        matched_events.append(event)

            matched_rule_events = set([event.risk_event_type.lower() for event in matched_events])
            if not rule_events.difference(matched_rule_events):
                for event in matched_events:
                    yield rule, match, event
        elif rule.match == Match.ONE.value:
            """ Match exactly one event type (there could be multiple events that match the event type) """
            matched_events = []
            for event in events:
                if event.risk_event_type.lower() in rule_events:
                    if rule_start_time <= event.risk_event_date <= rule_end_time:
                        matched_events.append(event)

            matched_rule_events = set([event.risk_event_type.lower() for event in matched_events])
            if len(matched_rule_events) == 1:
                for event in matched_events:
                    yield rule, match, event

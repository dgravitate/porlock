from . import converters
from . import enums
from . import exceptions


class NamedList(list):
    def __init__(self, name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = name

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def __getattribute__(self, item):
        # TODO: these names aren't amazingly clear
        item_mapping = {"event": 0, "when": 1, "match": 2, "match_events": 3, "period_when": 4, "period_when_time": 5,
                        "identifier": 6, "ignore_events": 7, "ignore_when": 8, "ignore_when_time": 9,
                        "match_period": 10, "event_period": 11}

        if item in item_mapping:
            return self[item_mapping[item]]

        return super().__getattribute__(item)


def construct_rule(event, when, match, other_event, period_when, period, track, exclude_event, exclude_period_when,
                   exclude_period, limit_period, review_period):
    if when not in enums.When:
        raise exceptions.InvalidWhen(f"{when} is not a valid value for when")

    if exclude_period_when not in enums.PeriodWhen:
        raise exceptions.InvalidPeriodWhen(f"{exclude_period_when} is not a valid value for when")

    if match not in enums.Match:
        raise exceptions.InvalidMatch

    try:
        period_in_seconds = converters.convert_to_seconds(period)
    except Exception:
        raise exceptions.InvalidPeriod

    try:
        exclude_period_in_seconds = converters.convert_to_seconds(exclude_period)
        if period_when == enums.PeriodWhen.BEFORE:
            exclude_period_in_seconds *= -1
    except Exception:
        raise exceptions.InvalidPeriod

    try:
        limit_period_in_seconds = converters.convert_to_seconds(limit_period)
    except Exception:
        raise exceptions.InvalidPeriod

    try:
        review_period_in_seconds = converters.convert_to_seconds(review_period)
    except Exception:
        raise exceptions.InvalidPeriod

    return [event, when, match, other_event, period_when, period_in_seconds, track, exclude_event,
            exclude_period_when, exclude_period_in_seconds, limit_period_in_seconds, review_period_in_seconds]


class RulesRegistry(object):
    def __init__(self):
        self.__rules = {}

    def register(self, rule_name, rule=None, **kwargs):
        if rule_name in self.__rules:
            raise exceptions.AlreadyRegistered()

        if not rule and kwargs:
            rule = construct_rule(**kwargs)
        elif rule:
            rule = construct_rule(*rule)

        self.__rules[rule_name] = NamedList(rule_name, rule)

    def unregister(self, rule_name):
        if rule_name not in self.__rules:
            raise exceptions.RuleNotRegistered

        del self.__rules[rule_name]

    def rules_for_event(self, event_type):
        rules = []
        for label, rule in self.__rules.items():
            if event_type.lower() == rule[0].lower():
                rules.append(rule)

        return rules

    @property
    def rules(self):
        return self.__rules


registry = RulesRegistry()


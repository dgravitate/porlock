import logging
import typing
from datetime import timedelta, datetime

from .. import snoop

logger = logging.getLogger("porlock.risk_event")


class BaseRiskMixin:
    event_type_field = None
    event_date_field = None
    event_actor_field = None
    event_instance_field = None

    @property
    def risk_event_type(self) -> str:
        return getattr(self, self.event_type_field, None)

    @property
    def risk_event_date(self) -> datetime:
        return getattr(self, self.event_date_field, None)

    @property
    def risk_event_instance(self) -> typing.Any:
        return getattr(self, self.event_instance_field, None)

    def get_event_instance_filter(self) -> dict:
        return {self.event_instance_field: getattr(self, self.event_instance_field)}

    def construct_date_range(self, rule):
        if rule.ignore_when_time >= 0:
            rule_start_time = self.risk_event_date + timedelta(seconds=rule.ignore_when_time)
            rule_end_time = self.risk_event_date + timedelta(seconds=rule.match_period)
        else:
            rule_start_time = self.risk_event_date + timedelta(seconds=rule.match_period)
            rule_end_time = self.risk_event_date + timedelta(seconds=rule.ignore_when_time)

        return rule_start_time, rule_end_time

    @classmethod
    def load_events_for_analysis(cls, event_type, start_time, end_time, *args, **kwargs) -> typing.Iterable:
        """ Load events for analysis """
        raise NotImplementedError

    @classmethod
    def load_related_events(cls, ruleset, match) -> typing.Iterable:
        """ Load more rules based on the criteria in the matching event """
        raise NotImplementedError

    @classmethod
    def identify_risk(cls, events, aggregate_events=False):
        aggregated_events = {}

        for ruleset, match in snoop.find_rule_match(events):
            related_events = cls.load_related_events(ruleset, match)
            for risk_event in snoop.inspect_related_events(ruleset, match, related_events):
                if not aggregate_events:
                    logger.info("Risk Identified: [%s]", risk_event)
                    yield risk_event
                else:
                    if match not in aggregated_events:
                        aggregated_events[match] = []
                    aggregated_events[match].append(risk_event[2])

        if aggregate_events:
            for match, events in aggregated_events.items():
                yield "Aggregated Events", match, events # [0]

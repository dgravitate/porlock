from .. import snoop


class BaseRiskMixin:
    event_type_field = None
    event_date_field = None
    event_actor_field = None
    event_instance_field = None

    @property
    def risk_event_type(self):
        return getattr(self, self.event_type_field, None)

    @property
    def risk_event_date(self):
        return getattr(self, self.event_date_field, None)

    @property
    def risk_event_instance(self):
        return getattr(self, self.event_instance_field, None)

    def get_event_instance_filter(self):
        return {self.event_instance_field: getattr(self, self.event_instance_field)}

    @classmethod
    def load_events_for_analysis(cls, event_type, start_time, end_time):
        """ Load an initial set of rules """
        filters = {cls.event_type_field: event_type, f"{cls.event_date_field}__range": (start_time, end_time)}
        return cls.objects.filter(**filters)

    @classmethod
    def load_related_events(cls, ruleset, match):
        """ Load more rules based on the criteria in the matching event """
        raise NotImplementedError

    @classmethod
    def identify_risk(cls, events):
        for ruleset, match in snoop.find_rule_match(events):
            related_events = cls.load_related_events(ruleset, match)
            for risk in snoop.inspect_related_events(ruleset, match, related_events):
                print("Risk identified!", risk)

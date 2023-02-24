from datetime import timedelta

from django.db.models import Q

from . import BaseRiskMixin


class DjangoRiskMixin(BaseRiskMixin):
    @classmethod
    def load_related_events(cls, ruleset, match):
        """ Load more rules based on the criteria in the matching event """
        dates_q = Q()
        event_types_q = Q()
        filters = match.get_event_instance_filter()

        for rule in ruleset:
            if rule[9] >= 0:
                rule_start_time = match.risk_event_date + timedelta(seconds=rule[9])
                rule_end_time = match.risk_event_date + timedelta(seconds=rule[10])
            else:
                rule_start_time = match.risk_event_date + timedelta(seconds=rule[10])
                rule_end_time = match.risk_event_date + timedelta(seconds=rule[9])

            dates_q |= Q(**{f'{cls.event_date_field}__range': [rule_start_time, rule_end_time]})
            event_types_q |= Q(**{cls.event_type_field: rule[3]})

        return cls.objects.filter(**filters).filter(dates_q).filter(event_types_q)

    @classmethod
    def load_events_for_analysis(cls, event_type, start_time, end_time, *args, **kwargs):
        """ Load an initial set of rules """
        filters = {cls.event_type_field: event_type, f"{cls.event_date_field}__range": (start_time, end_time)}
        return cls.objects.filter(**filters)
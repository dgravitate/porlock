import enum


class MemberMatchEnum(enum.EnumMeta):
    def __contains__(cls, item):
        return item in [v.value for v in cls.__members__.values()]


class When(enum.Enum, metaclass=MemberMatchEnum):
    FOLLOWED_BY = "followed by"
    PRECEDED_BY = "preceded by"


class Match(enum.Enum, metaclass=MemberMatchEnum):
    ANY = "any"
    ALL = "all"
    NONE = "none"
    ONE = "one"


class PeriodWhen(enum.Enum, metaclass=MemberMatchEnum):
    BEFORE = "before"
    AFTER = "after"


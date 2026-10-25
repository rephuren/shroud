from dataclasses import dataclass

INFO, WARN, ALERT = "info", "warn", "alert"


@dataclass
class Finding:
    level: str
    code: str
    message: str
    offset: int | None = None
    size: int | None = None

    def as_dict(self):
        return {k: v for k, v in self.__dict__.items() if v is not None}

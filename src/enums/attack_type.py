from enum import Enum

class AttackType(str, Enum):
    BASIC = "BASIC"
    DOS = "DOS"
    DROP = "DROP"
    FUZZY = "FUZZY"
    PROGRESSIVE = "PROGRESSIVE"
    REPLAY = "REPLAY"
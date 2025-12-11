from extensions import db
from .entities import (
    Mahasiswa,
    Admin,
    LogLogin,
    DeteksiAnomali,
    KeputusanAdmin,
    DelayedLogin,
    UserSecurityHistory
)

__all__ = [
    'db',
    'Mahasiswa',
    'Admin',
    'LogLogin',
    'DeteksiAnomali',
    'KeputusanAdmin',
    'DelayedLogin',
    'UserSecurityHistory'
]

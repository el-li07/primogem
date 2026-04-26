from primogem.config import settings

def test_settings_loaded():
    assert settings.ISSUER == "auth.primogem.local"
    assert isinstance(settings.KEY_ROTATION_DAYS, int)
    assert settings.TOKEN_LIFETIME_MINUTES > 0
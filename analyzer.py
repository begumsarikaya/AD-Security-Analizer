ACCOUNTDISABLE = 0x0002
DONT_EXPIRE_PASSWORD = 0x10000


def has_flag(value, flag):
    return (value & flag) == flag


def safe_int(value):
    if isinstance(value, list):
        value = value[0] if value else 0

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def build_status_and_risk(user, is_disabled, is_password_never_expires, is_admin, is_inactive):
    if is_disabled and is_admin:
        return (
            "DISABLED ADMIN ACCOUNT",
            "HIGH",
            "Yönetici hesabı incelenmeli ve yetkileri gözden geçirilmelidir."
        )

    if is_password_never_expires and is_admin:
        return (
            "ADMIN + PASSWORD NEVER EXPIRES",
            "HIGH",
            "Yönetici hesabında parola süresi politikası uygulanmalıdır."
        )

    if is_inactive and is_admin:
        return (
            "INACTIVE ADMIN ACCOUNT",
            "HIGH",
            "Uzun süredir kullanılmayan yönetici hesabı devre dışı bırakılmalıdır."
        )

    if is_password_never_expires:
        return (
            "PASSWORD NEVER EXPIRES",
            "HIGH",
            "Parola süresi politikası uygulanmalıdır."
        )

    if is_disabled:
        return (
            "DISABLED",
            "MEDIUM",
            "Devre dışı hesap gerekli değilse kaldırılmalı veya düzenli kontrol edilmelidir."
        )

    if is_inactive:
        return (
            "INACTIVE",
            "MEDIUM",
            "Uzun süredir kullanılmayan hesap gözden geçirilmelidir."
        )

    if is_admin:
        return (
            "ADMIN ACCOUNT",
            "MEDIUM",
            "Yönetici yetkileri periyodik olarak denetlenmelidir."
        )

    return (
        "NORMAL",
        "LOW",
        "Hesap düzenli güvenlik politikaları kapsamında izlenmelidir."
    )


def analyze_users(users):
    disabled_users = []
    password_never_expires = []
    normal_users = []
    admin_users = []
    inactive_users = []

    high_risk_users = []
    medium_risk_users = []
    low_risk_users = []

    all_users = []

    for user in users:
        uac_value = safe_int(user.get("userAccountControl", 0))

        is_disabled = has_flag(uac_value, ACCOUNTDISABLE)
        is_password_never_expires = has_flag(uac_value, DONT_EXPIRE_PASSWORD)
        is_admin = bool(user.get("is_admin", False))
        last_logon_days_ago = safe_int(user.get("last_logon_days_ago", 0))
        is_inactive = last_logon_days_ago >= 90

        status, risk_level, recommendation = build_status_and_risk(
            user,
            is_disabled,
            is_password_never_expires,
            is_admin,
            is_inactive,
        )

        enriched_user = dict(user)
        enriched_user["status"] = status
        enriched_user["risk_level"] = risk_level
        enriched_user["recommendation"] = recommendation
        enriched_user["is_inactive"] = is_inactive

        all_users.append(enriched_user)

        if is_disabled:
            disabled_users.append(enriched_user)

        if is_password_never_expires:
            password_never_expires.append(enriched_user)

        if is_admin:
            admin_users.append(enriched_user)

        if is_inactive:
            inactive_users.append(enriched_user)

        if risk_level == "HIGH":
            high_risk_users.append(enriched_user)
        elif risk_level == "MEDIUM":
            medium_risk_users.append(enriched_user)
        else:
            low_risk_users.append(enriched_user)
            normal_users.append(enriched_user)

    return {
        "disabled_users": disabled_users,
        "password_never_expires": password_never_expires,
        "normal_users": normal_users,
        "admin_users": admin_users,
        "inactive_users": inactive_users,
        "high_risk_users": high_risk_users,
        "medium_risk_users": medium_risk_users,
        "low_risk_users": low_risk_users,
        "all_users": all_users,
    }

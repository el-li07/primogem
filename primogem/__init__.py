"""Primogem Auth Library - JWT + Ed25519 authentication"""

from .verifier import TokenVerifier
from .key_manager import KeyManager
from .auth_server import app as auth_app

__version__ = "0.1.0"

__all__ = ["TokenVerifier", "KeyManager", "auth_app"]

print("      :::::::::   :::::::::   :::::::::::     :::   :::      ::::::::     ::::::::    ::::::::::     :::   :::")
print("     :+:    :+:  :+:    :+:      :+:        :+:+: :+:+:    :+:    :+:   :+:    :+:   :+:           :+:+: :+:+:")
print("    +:+    +:+  +:+    +:+      +:+       +:+ +:+:+ +:+   +:+    +:+   +:+          +:+          +:+ +:+:+ +:+")
print("   +#++:++#+   +#++:++#:       +#+       +#+  +:+  +#+   +#+    +:+   :#:          +#++:++#     +#+  +:+  +#+")
print("  +#+         +#+    +#+      +#+       +#+       +#+   +#+    +#+   +#+   +#+#   +#+          +#+       +#+")
print(" #+#         #+#    #+#      #+#       #+#       #+#   #+#    #+#   #+#    #+#   #+#          #+#       #+#")
print("###         ###    ###  ###########   ###       ###    ########     ########    ##########   ###       ###")
print(f"\n                                        - Primogem Auth Library v{__version__} -")
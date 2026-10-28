"""Location Services permission, which macOS requires before it reveals network names and BSSIDs."""

from __future__ import annotations

import time
from enum import IntEnum


class LocationStatus(IntEnum):
    """Mirror of CoreLocation's CLAuthorizationStatus."""

    NOT_DETERMINED = 0
    RESTRICTED = 1
    DENIED = 2
    AUTHORIZED = 3
    AUTHORIZED_WHEN_IN_USE = 4

    @property
    def granted(self) -> bool:
        return self in (LocationStatus.AUTHORIZED, LocationStatus.AUTHORIZED_WHEN_IN_USE)


def status() -> LocationStatus:
    import CoreLocation

    return LocationStatus(CoreLocation.CLLocationManager.alloc().init().authorizationStatus())


def can_request() -> bool:
    """Whether macOS will ask the user on this process's behalf.

    It only asks for apps whose Info.plist explains why they want access. Requests from anything
    else, such as a plain python process, are dropped without a prompt.
    """
    from Foundation import NSBundle

    return NSBundle.mainBundle().objectForInfoDictionaryKey_("NSLocationUsageDescription") is not None


class AuthorizationRequest:
    """Shows the macOS Location prompt.

    Only the permission is requested. Location updates are never started: working out a position
    can make macOS send nearby access points to Apple's Wi-Fi positioning service, and the app
    must not cause any network traffic.

    The answer is delivered through the main run loop, so keep it running (an app's
    event loop does) and poll ``status`` until it is no longer NOT_DETERMINED.
    """

    def __init__(self) -> None:
        import CoreLocation

        self._manager = CoreLocation.CLLocationManager.alloc().init()
        self._manager.requestWhenInUseAuthorization()

    @property
    def status(self) -> LocationStatus:
        return LocationStatus(self._manager.authorizationStatus())


def request(timeout: float) -> LocationStatus:
    """Ask macOS for Location access and wait up to ``timeout`` seconds for an answer."""
    from Foundation import NSDate, NSRunLoop

    pending = AuthorizationRequest()
    deadline = time.monotonic() + timeout
    while pending.status is LocationStatus.NOT_DETERMINED and time.monotonic() < deadline:
        NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.25))
    return pending.status

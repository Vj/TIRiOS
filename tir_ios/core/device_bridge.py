from pathlib import Path
from typing import Iterator, Optional
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.syslog import SyslogService
from pymobiledevice3.usbmux import list_devices


class DeviceConnectionError(Exception):
    """Raised when no iOS device is connected or lockdown pairing fails."""


class IOSDeviceBridge:
    def __init__(self, udid: Optional[str] = None):
        self.udid = udid or self._discover_first_udid()
        try:
            self.lockdown = create_using_usbmux(serial=self.udid)
        except Exception as exc:
            raise DeviceConnectionError(f"Failed to establish lockdown session with {self.udid}: {exc}") from exc

    @staticmethod
    def _discover_first_udid() -> str:
        devices = list_devices()
        if not devices:
            raise DeviceConnectionError("No iOS devices detected over usbmuxd. Ensure USB connection and device trust.")
        return devices[0].serial

    def device_summary(self) -> dict:
        return {
            "udid": self.udid,
            "device_name": self.lockdown.display_name,
            "product_type": self.lockdown.product_type,
            "ios_version": self.lockdown.product_version,
        }

    def install_ipa(self, ipa_path: Path) -> None:
        ipa_file = Path(ipa_path).resolve()
        if not ipa_file.is_file():
            raise FileNotFoundError(f"IPA file not found: {ipa_file}")
        with InstallationProxyService(lockdown=self.lockdown) as installer:
            installer.install_from_local(str(ipa_file))

    def stream_syslog(self, process_filter: Optional[str] = None) -> Iterator[str]:
        """Yields live syslog entries, optionally filtered by executable/process name."""
        with SyslogService(lockdown=self.lockdown) as syslog:
            for line in syslog.watch():
                if process_filter and process_filter not in line:
                    continue
                yield line
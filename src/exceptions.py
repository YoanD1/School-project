class NetworkMonitorError(Exception):
    """Base exception for the entire application."""


class PacketParseError(NetworkMonitorError):
    """Raised when a raw record cannot be parsed into a NetworkPacket."""


class InsufficientTrainingDataError(NetworkMonitorError):
    """Raised when the detector is asked to predict before being trained."""


class DetectionError(NetworkMonitorError):
    """Raised when the AI model fails during prediction."""


class DatabaseError(NetworkMonitorError):
    """Raised when a database operation fails."""


class FileExportError(NetworkMonitorError):
    """Raised when writing logs or exports fails."""

from __future__ import annotations


class FIPException(Exception):
    pass


class ScanError(FIPException):
    pass


class ScanCancelledError(ScanError):
    pass


class ScanPausedError(ScanError):
    pass


class AnalysisError(FIPException):
    pass


class FileNotSupportedError(AnalysisError):
    pass


class FileAccessError(AnalysisError):
    pass


class DatabaseError(FIPException):
    pass


class ConfigurationError(FIPException):
    pass


class AIAnalysisError(FIPException):
    pass

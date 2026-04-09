"""Chat channels module with plugin architecture."""

from forensic_claw.channels.base import BaseChannel
from forensic_claw.channels.manager import ChannelManager

__all__ = ["BaseChannel", "ChannelManager"]

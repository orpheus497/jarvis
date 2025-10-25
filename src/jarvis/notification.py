"""
Jarvis - Cross-platform notification system.

Created by orpheus497

Provides notifications for incoming messages with platform-specific implementations:
- Linux: libnotify (notify-send)
- macOS: osascript (AppleScript)
- Windows: Windows notification system
- Termux: termux-notification API
"""

import os
import sys
import subprocess
import platform
from typing import Optional


class NotificationManager:
    """Manages cross-platform notifications."""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.enabled = True
        self._check_availability()
    
    def _check_availability(self):
        """Check if notifications are available on this platform."""
        if self.platform == 'linux':
            # Check for notify-send or termux
            if os.path.exists('/data/data/com.termux'):
                self.platform = 'termux'
            else:
                self.enabled = self._command_exists('notify-send')
        elif self.platform == 'darwin':
            # macOS always has osascript
            self.enabled = True
        elif self.platform == 'windows':
            # Windows 10+ has native notifications
            self.enabled = True
        else:
            self.enabled = False
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists."""
        try:
            subprocess.run(
                ['which', command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def notify(self, title: str, message: str, urgency: str = 'normal'):
        """
        Send a notification.
        
        Args:
            title: Notification title
            message: Notification message
            urgency: Urgency level ('low', 'normal', 'critical')
        """
        if not self.enabled:
            return
        
        try:
            if self.platform == 'linux':
                self._notify_linux(title, message, urgency)
            elif self.platform == 'darwin':
                self._notify_macos(title, message)
            elif self.platform == 'windows':
                self._notify_windows(title, message)
            elif self.platform == 'termux':
                self._notify_termux(title, message)
        except Exception as e:
            pass  # Silently fail if notification fails
    
    def _notify_linux(self, title: str, message: str, urgency: str):
        """Send notification on Linux using notify-send."""
        subprocess.run([
            'notify-send',
            '-u', urgency,
            '-i', 'mail-unread',
            '-a', 'Jarvis',
            title,
            message
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _notify_macos(self, title: str, message: str):
        """Send notification on macOS using osascript."""
        script = f'''
        display notification "{message}" with title "Jarvis" subtitle "{title}"
        '''
        subprocess.run([
            'osascript', '-e', script
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _notify_windows(self, title: str, message: str):
        """Send notification on Windows using PowerShell."""
        # Escape quotes in title and message
        title = title.replace('"', '""')
        message = message.replace('"', '""')
        
        script = f'''
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
        
        $template = @"
        <toast>
            <visual>
                <binding template="ToastText02">
                    <text id="1">{title}</text>
                    <text id="2">{message}</text>
                </binding>
            </visual>
        </toast>
"@
        
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($template)
        $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Jarvis").Show($toast)
        '''
        
        subprocess.run([
            'powershell', '-Command', script
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _notify_termux(self, title: str, message: str):
        """Send notification on Termux using termux-notification."""
        subprocess.run([
            'termux-notification',
            '--title', title,
            '--content', message,
            '--id', 'jarvis'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def play_sound(self):
        """Play notification sound."""
        if not self.enabled:
            return
        
        try:
            if self.platform == 'linux':
                # Try to play system sound
                subprocess.run([
                    'paplay', '/usr/share/sounds/freedesktop/stereo/message.oga'
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif self.platform == 'darwin':
                # Play macOS system sound
                subprocess.run([
                    'afplay', '/System/Library/Sounds/Glass.aiff'
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif self.platform == 'windows':
                # Play Windows system sound
                import winsound
                winsound.MessageBeep()
            elif self.platform == 'termux':
                # Play Termux notification sound
                subprocess.run([
                    'termux-notification',
                    '--sound'
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            pass  # Silently fail if sound fails


# Global notification manager instance
_notification_manager = None


def get_notification_manager() -> NotificationManager:
    """Get the global notification manager instance."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager

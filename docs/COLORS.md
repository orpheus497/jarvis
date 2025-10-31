# UI Color Palette

This document describes the complete color palette used throughout the Jarvis terminal interface.

## Color Palette

Jarvis uses the following colors in its terminal user interface:

- **Red** - Error states, offline status, critical warnings
- **White** - Primary text, message content, standard UI elements
- **Black** - Background, container backgrounds
- **Grey** - Secondary text, metadata, timestamp information
- **Purple** - Branding elements, special highlights
- **Cyan** - Informational accents, status indicators, hyperlinks
- **Amber** - Warning states, partial connectivity indicators

## Usage by Component

### Connection Status Indicators

The application uses a four-level connection status system with distinct colors:

- **Green (●)**: All connections active - all peers online and connected
- **Amber (●)**: Partial connections - some peers online, messages can be sent and received
- **Red (●)**: No active connections - server running but no peers connected
- **Grey (●)**: Server offline - cannot send or receive messages

### Animated ASCII Banner

The animated banner on the welcome and main application screens cycles through a gradient of colors:

1. White
2. Red
3. Bright White
4. Dark Red
5. Purple
6. Grey

The banner also incorporates cyan accents for visual interest.

### Message Display

- **White**: Standard message text content
- **Grey**: Message timestamps, sender information, metadata
- **Cyan**: Links, special formatting accents
- **Red**: Error messages, failed delivery indicators

### Actions and Buttons

- **Cyan**: Interactive elements, clickable buttons, emphasized actions
- **Grey**: Secondary or disabled actions
- **Red**: Destructive actions (delete, remove)

### Informational Elements

- **Cyan**: Tips, help text, informational accents
- **Grey**: Labels, field names, secondary information
- **Purple**: Special announcements, feature highlights

## Design Philosophy

The color palette is designed to provide:

- Clear visual hierarchy with distinct colors for different information types
- High contrast for terminal readability across different terminal emulators
- Consistent color meaning throughout the application
- Accessibility considerations for color-blind users through redundant indicators

---

Created by **orpheus497**

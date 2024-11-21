# Discord Content Filter Bot

A comprehensive Discord moderation bot that provides automated content filtering, custom blacklists/whitelists, and an advanced punishment system.

## Important: SQLite WAL2 Requirement

This bot requires SQLite with WAL2 support, which is available in the [WAL2 branch](https://github.com/sqlite/sqlite/tree/wal2) of SQLite. This requires a custom compilation of SQLite and has been tested with:
- Version: 3.48.0
- Commit: 1adf875

The standard SQLite distribution will not work as this bot specifically uses WAL2 mode for enhanced performance and reliability.

## Features

- **Content Filtering**
  - Custom blacklists and whitelists
  - Pattern matching with regex support
  - Obfuscation detection
  - URL and emoji handling
  - Markdown-aware filtering

- **Advanced Exceptions System**
  - Channel-specific exceptions
  - Category-wide exceptions
  - Role-based exceptions
  - Global exception management

- **Automated Punishments**
  - Configurable violation thresholds
  - Time-based punishment windows
  - Automated role assignments
  - Punishment duration management

- **Display Name Filtering**
  - Optional nickname/display name filtering
  - Automated enforcement
  - Configurable restrictions

- **Comprehensive Logging**
  - Detailed audit logs
  - User notifications
  - Action tracking
  - Violation history

## Requirements

- Python 3.8+
- discord.py 2.0+
- Custom-compiled SQLite with WAL2 support (v3.48.0/1adf875)
- Additional dependencies listed in requirements.txt

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/discord-content-filter.git
cd discord-content-filter
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Install custom SQLite with WAL2:
   - Clone SQLite WAL2 branch
   - Compile following SQLite documentation
   - Verify WAL2 support is available

4. Configure the bot:
   - Add a .env file with BOT_TOKEN defined as your bot token

5. Run the bot:
```bash
python content_filter.py
```

## Commands

### Admin Commands
- `/set_moderator_role` - Set the moderator role
- `/set_log_channel` - Set logging channel
- `/set_dm_notification` - Configure DM notifications
- `/set_punishment` - Configure punishment settings
- `/toggle_display_name_filter` - Toggle name filtering

### Blacklist Management
- `/edit_blacklist` - Create/edit blacklists
- `/quick_add_blacklist` - Quick add terms
- `/delete_blacklist` - Remove blacklists
- `/list_blacklists` - View all blacklists

### Whitelist Management
- `/edit_whitelist` - Create/edit whitelists
- `/quick_add_whitelist` - Quick add terms
- `/delete_whitelist` - Remove whitelists
- `/list_whitelists` - View all whitelists

### Exception Management
- `/add_channel_exception` - Add channel exceptions
- `/add_category_exception` - Add category exceptions
- `/add_role_exception` - Add role exceptions
- `/add_global_channel_exception` - Add global channel exceptions
- `/add_global_category_exception` - Add global category exceptions
- `/add_global_role_exception` - Add global role exceptions
- `/list_exceptions` - View all exceptions
- `/list_global_exceptions` - View all global exceptions

### Moderation Tools
- `/scan_last_messages` - Scan recent messages
- `/lift_punishment` - Remove punishments
- Context menu commands for message management

## Configuration

The bot uses a JSON-based configuration system with the following main components:

```json
{
	"blacklists": {},
	"whitelists": {},
	"exceptions": {
	"categories": {},
	"channels": {},
	"roles": {}
	},
	"global_exceptions": {
	"categories": [],
	"channels": [],
	"roles": []
	},
	"punishments": {
	"max_violations": 10,
	"time_window": {
		"days": 0,
		"seconds": 3600,
		"microseconds": 0
	},
	"punishment_role": 999012168227881051,
	"punishment_duration": {
		"days": 0,
		"seconds": 3600,
		"microseconds": 0
	}
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue on GitHub.

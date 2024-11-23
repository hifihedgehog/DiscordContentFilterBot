# Discord Content Filter Bot

A feature-rich and carefully crafted Discord censoring bot that provides automated content filtering, custom blacklists/whitelists, and an advanced punishment system. This meets and beats algorithmically a certain very popular paid bot service while also packing in support for long Nitro length messages and even allowing users to edit and delete their censored messages.

## Important: SQLite WAL2 Requirement

This bot requires SQLite with WAL2 support, which is available in the [WAL2 branch](https://github.com/sqlite/sqlite/tree/wal2) of SQLite. This requires a custom compilation of SQLite and has been tested with:
- Version: 3.48.0
- Commit: 1adf875

The standard SQLite distribution will not work as this bot specifically uses WAL2 mode for enhanced performance and reliability.

## Features

- **Content Filtering**
  - Right off the bat, we filter all of your new and edited messages, new and edited thread titles, and incoming emojis. Just add a blacklist or whitelist from a variety of sources.
  - Here are just a few favorite blacklist sources of ours to get you started! Note you may need to strip some of them of commas and parentheses as you enter one per line in the bot. [NotePad++](https://notepad-plus-plus.org/) is suited perfectly for that task!
    - [Robert James Gabriel's google-profanity-words](https://github.com/coffee-and-fun/google-profanity-words/blob/main/data/en.txt)
    - [Rodger Araujo's profanity](https://github.com/rodgeraraujo/profanity/blob/main/src/data/dictionary.ts)
    - [mogade's badwords](https://github.com/mogade/badwords/blob/master/en.txt)
    - [FreeWebHeaders.com](https://www.freewebheaders.com/category/profanity/profanity-word-list/)
  - Create, modify, and delete your own blacklists and whitelists with no limits on the number of either, all via the mere stroke of a slash command!
  - Terms in any blacklist or whitelist can be made up of a mix of exact terms or regular expressions. Leave the blacklist name blank to drill through the full list of current blacklists. Or specify a new or current list via the parameter.
  - In a hurry to block a new nasty bit of choice words? Our quick commands also come in handy for such an occasion when speedy fingers are in high demand.
  - Our super sophisticated obfuscation detection stops the most terrible of trolls dead in their tracks from wreaking havoc. Reversed spellings, special lookalike Unicode characters, stray spaces and special characters sandwiched in-between... you name it! We left no stone unturned!
  - We even support URLs and emojis. Add any emoji and it will also be instantly blocked in message reactions! Same thing with URLs. Hate invite spam? We do too! Just paste in https://discord.gg/ to a blacklist, and kiss that invite spam goodbye for good!
  - We've also paid very special care to be doubly certain our filtering is Markdown-aware, so you and your user's formatting is always fully respected in the censoring process.
  - Performance was a very important consideration during the design and optimization phase. Instant replacement is a must and we delivered. Settings and wordlists are not only saved persistently but also pre-processed and cached in-memory for eye-blinkingly fast retrieval and naughty word removal. 

- **Reposted Bot Messages**
  - Best of all, every reposted message looks exactly like your user had posted it. This is exactly like a certain paid bot censoring system.
  - That's right! Each user's profile image and display name is shown exactly as expected in the upper left of their censored messages. But we didn't stop there...
  - Best of all, we exclusively offer full edit and deletion--also fully filtered, so they aren't going to abuse this superpower--on all censored posts. Staff also are empowered to edit and delete them in their behalf as well.
  - And we didn't stop there either: we also exclusively support Nitro-length posts of up to 4000 characters. That's right. No dumb truncation cutting off that full wall of text your users spent hours to painstakingly write. The full text no matter how long it is will always flow through loud and clear--of course, censored wherever necessary on your own terms.


- **Advanced Exceptions System**
  - We understand that no two servers are alike and many have multiple languages, NSFW channels, or just places where you don't want filtering happening at all or at least quite not as much. 
  - For that reason, we offer two levels of granularity: blacklist-specific _exceptions_ and _**global** exceptions_.
  - With exceptions, you can add or remove any given number of roles, channels, and categories to any given number of blacklists and vice versa.
  - Once you set one of any of those with a blacklist, that role, channel, or category is blocked from just that blacklist and that blacklist only. This is perfect for multilingual servers, as well as servers which may need multiple layers of filtering levels.
  - But sometimes simpler solutions are all that is needed. That's where global exceptions come in. They're server wide. Select any roles, channels, and categories. Once you do, they are exempt everywhere... done and done!
  - Better still, you can combine the two of these and it will just automagically work!

- **Automated Punishments**
  - Of course, you may have need to wrangle in some users who need special handling, and you can say exactly when that happens with our bot-controlled mute punishments.
  - These can be set to whatever mute role you specify.
  - They occur after a given number of violations over however many minutes you say.
  - Then the punishment goes for as many hours as you say. You're the boss. You're are in complete command!
  - Once all of these are set, you are off. The bot handles it all automagically. Even if it goes offline momentarily, the database stores exactly when a punishment started and when it should end, so the bot picks up where it left off and removes the mute role precisely when it means to.

- **Display Name Filtering**
  - As another powerful option, you can have display names filtered. Whenever someone joins or updates their profile, the bot will always be one step ahead.
  - Of course as well, global role exclusions also apply here. If there is some role you want not filtered, just select it and it won't get filtered if you enable this optional filtering.
  - Best of all, the violation tracking patches in seamlessly here too. So if someone keeps trying to use a nasty nick in the chat, they will eventually take the hint that enough is enough.

- **Comprehensive Logging**
  - Our audit logs are better still. We note which staff member lifted a mute early and even offer a reason field, which shows up both in the your configured log channel and the server audit logs.
  - Users are instantly notified via DM when they are muted by the bot. So there is zero waiting or wondering.
  - Everything is transparent to both you and them in the DMs and the logs. You can both see exactly what blacklists and terms triggered their censor.
  - You can easily see an at-a-glance history of violations all from the log channel, noting when punishments were applied and whenever they were lifted, either automatically by the bot or manually by a staff member via the lift punishment command.

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
Do you want to help make this bot even better? Follow these five super simple steps!
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue on GitHub.

## Donation

If you found this bot at all helpful, don't pay me a single blessed cent! Seriously. [Instead, donate to the Humanitarian Services of The Church of Jesus Christ of Latter-day Saints!](https://philanthropies.churchofjesuschrist.org/humanitarian-services)

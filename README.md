# Discord Content Filter Bot

A feature-rich and expertly crafted Discord censoring bot that provides automated content filtering, custom blacklists/whitelists, and an advanced punishment system. This meets and beats a certain very popular paid bot Discord censoring service by going a step further and packing in support for long Nitro-length messages, letting users edit and delete their censored messages, letting users and staff see exactly what and why content was censored, and much, much more!

## Important: SQLite WAL2 Requirement

This bot requires SQLite with WAL2 support, which is available in the [WAL2 branch](https://github.com/sqlite/sqlite/tree/wal2) of SQLite. This requires a custom compilation of SQLite and has been tested with:
- Version: 3.48.0
- Commit: 1adf875

The standard SQLite distribution will not work as this bot specifically uses WAL2 mode for enhanced performance and reliability. Of course, you are free of course to edit this source code to use another mode, such as WAL or DELETE, as you please. However, we opted for this mode so the database has high availability even when many users are reading and writing to it from an influx of censored messages. This gives you a neatly packaged, high performance, quite portable database solution.

## Features

- **Blacklist and Whitelist Customization**
  - Add your first blacklist and optionally whitelist from a variety of sources.
  - Here are just a few favorite blacklist sources of ours to get you started! Note you may need to strip some of them of commas and parentheses as you enter one per line in the bot. [NotePad++](https://notepad-plus-plus.org/) is perfectly suited and up to the task!
    - [Robert James Gabriel's google-profanity-words](https://github.com/coffee-and-fun/google-profanity-words/blob/main/data/en.txt)
    - [Rodger Araujo's profanity](https://github.com/rodgeraraujo/profanity/blob/main/src/data/dictionary.ts)
    - [mogade's badwords](https://github.com/mogade/badwords/blob/master/en.txt)
    - [FreeWebHeaders.com](https://www.freewebheaders.com/category/profanity/profanity-word-list/)
  - Create, modify, and delete your own blacklists and whitelists with no limits on the number of either, all via the mere stroke of a slash command!
  - Terms in any blacklist or whitelist can be made up of a mix of exact terms or regular expressions. Leave the blacklist name blank when indicating the blacklist edit command to call up and drill through the full list of current blacklists. Or specify a new or current list via the parameter. Same thing with whitelists as well.

    ![ezgif-1-69ef3929b5](https://github.com/user-attachments/assets/6fa47fa0-99bf-441b-9fc8-95d6083d5391)

  - In a hurry to block a new nasty bit of choice words? Our quick commands also come in handy for such an occasion when freaky fast fingers are in high demand and short supply.

    ![ezgif-7-317117d2a6](https://github.com/user-attachments/assets/0a489350-7331-46c3-b3bc-77c43ef7e986)

  - Our super sophisticated obfuscation detection stops the most terrible of trolls dead in their tracks from wreaking havoc. Reversed spellings, lookalike Unicode characters, stray spaces, and special characters sandwiched in-between... you name it! We left no stone unturned!

    ![ezgif-1-6ce4ff5daf](https://github.com/user-attachments/assets/61358bdc-991c-4b36-ac6a-92eb002d1bcc)

  - We even support URLs and emojis. Add any emoji and it will also be instantly blocked in message reactions! Same thing with URLs. Hate invite spam? We do too! Just paste https://discord.gg/ into a blacklist, and kiss that invite spam goodbye for good!

    ![ezgif-4-e4b36cfe02](https://github.com/user-attachments/assets/59e54158-7fcf-49d7-9f91-968102b5eaca)

  - We've also paid very special care to be doubly certain our filtering is Markdown-aware, so your users' formatting is always fully respected in the censoring process.

    ![ezgif-7-5889783452](https://github.com/user-attachments/assets/a518af96-2f71-4221-8fc5-55afa9e0b082)

- **Reposted Bot Messages**
  - Right off the bat, we filter all of your new and edited messages, new and edited thread titles, and added reactions. Performance was a very important consideration during the design and optimization phase. Instant replacement of a message was a must and we delivered. Settings and wordlists are not only saved persistently but also pre-processed and cached in-memory for eye-blinkingly fast retrieval and naughty word removal. 
  - Best of all, every reposted message looks exactly like your user had posted it. This is exactly like a certain paid bot censoring system.

    ![ezgif-2-f1b0fab562](https://github.com/user-attachments/assets/83a03af6-68b3-469d-b139-10ddc73913ae)

  - That's right! Each user's profile image and display name is shown exactly as expected in the upper left of their censored messages. But we didn't stop there...
  - Best of all, we exclusively offer full editing and deleting on all censored posts to the users they belong to. Of course, we made sure our same tried-and-tested filtering system blocks and advises users there as well. Plus even staff are empowered to edit and delete censored messages in users' behalf as well.

    ![ezgif-7-8eeaec2e31](https://github.com/user-attachments/assets/996308b0-2725-4f59-bc95-e1a7f923a54e)

  - And we didn't stop there either: we also exclusively support Nitro-length posts of up to 4000 characters. That's right. No dumb truncation cutting off half of that full wall of text your users just spent so many hours to painstakingly write. The full text no matter how long it is will always flow through loud and clear—of course, fully censored wherever necessary on your own terms.

    ![ezgif-7-d74beafe37](https://github.com/user-attachments/assets/cbd1818d-ea27-4ebf-9304-b3e7d0e23adb)

- **Advanced Exceptions System**
  - We completely understand that no two servers are alike and many have multiple languages, NSFW channels, or just places where you don't want filtering happening at all or at least not quite as much. 
  - For that reason, we offer two levels of granularity: blacklist-specific _exceptions_ and _**global** exceptions_.
  - With exceptions, you can add or remove any given number of roles, channels, and categories to any given number of blacklists and vice versa.
  - Once you set one of any of those with a blacklist, that role, channel, or category is blocked from just that blacklist and that blacklist only. This is perfect for multilingual servers, as well as servers which may need multiple layers of filtering levels.

    ![ezgif-4-f3fcefb079](https://github.com/user-attachments/assets/a5bae89a-079a-40c2-9261-af9c35959ff2)

  - But sometimes the best solutions are the simplest of ones. That's where global exceptions come into play. They're server wide. Select any roles, channels, and categories. Once you do, they are exempt from all blacklists period... done and done!

    ![ezgif-4-f8616311d3](https://github.com/user-attachments/assets/167d4b1c-e66c-4923-8c44-b7d9212784f1)

  - Better still, you can combine the power of these two _exceptional_ options (pun intended) and they will automagically just work together in perfect harmony!

- **Automated Punishments**
  - Of course, you may have need to wrangle in some users who need special handling, and you can say exactly when that happens with our bot-controlled mute punishments.
    - These can be set to whatever mute role you specify.
    - They occur after a given number of violations over however many minutes you say.
    - Then the punishment goes for as many hours as you say. You're the boss. You're are in complete command!

    ![ezgif-7-481cf8f18f](https://github.com/user-attachments/assets/4f80f52e-d344-4f7f-bc02-9079a0451d58)

  - Once all of these are set, you are off. The bot handles it all automagically. Even if it goes offline momentarily, the database stores exactly when a punishment started and knows exactly when it should end, so the bot picks up where it left off and removes the mute role precisely when it means to.

- **Display Name Filtering**
  - As another powerful option, you can have configure display names to be filtered. Then anytime a user joins or updates their profile, the bot will always be one step ahead.

    ![ezgif-4-4899e194b6](https://github.com/user-attachments/assets/5aa1b2a8-f4ce-4624-b28e-dfd5fc66510a)

    ![ezgif-4-6af9e97560](https://github.com/user-attachments/assets/9d758164-412f-4083-98dd-31d5eee75a17)

  - Of course as well, global role exclusions also apply here. If there is some role you want left unfiltered, just select it and it won't get filtered whenever you do enable this optional filtering.
  - Best of all, the violation tracking patches in seamlessly here too. So if someone keeps trying to use a nasty nick in the chat, they will eventually take the hint that enough is enough.

    ![ezgif-2-7b7b3da24a](https://github.com/user-attachments/assets/bacd4121-0561-4c86-a9ee-f178fcc461d5)

    ![ezgif-2-1b8035b4ea](https://github.com/user-attachments/assets/96df73f9-8bbb-456e-a592-6085ea7aec64)

- **Comprehensive Logging**

  - Everything is transparent to both you and your users in the DMs and the logs. You and your users can both see precisely which blacklists and terms triggered their censor.
 
    ![ezgif-5-7297a8fc84](https://github.com/user-attachments/assets/3abf2fa9-e4d0-4fdf-907b-e378c6231bf4)

    ![ezgif-5-3fc2c1418e](https://github.com/user-attachments/assets/00c34036-5fee-4899-9585-d9ef225c6114)

  - Our audit logs are better still. We note which staff member lifted a mute early and even offer a reason field in the associated commands, which shows up both in your configured log channel and the server audit logs.
 
    ![ezgif-7-bbae15d9d7](https://github.com/user-attachments/assets/b4fa64f8-198b-4999-afb0-0af9d2c44072)
    
  - Users are instantly notified via DM when they are muted by the bot. So there is zero waiting or wondering about their awkward silence.

    ![ezgif-7-203aa7266e](https://github.com/user-attachments/assets/5d40014c-62a4-49c1-a243-ab718c7c3fbf)

  - You can easily see an at-a-glance history of violations all from the log channel, noting when punishments were applied and whenever they were lifted, either automatically by the bot or manually by a staff member via the lift punishment command.

    ![ezgif-7-a6ce9a1d10](https://github.com/user-attachments/assets/8c85401c-ff0c-4c2f-8d3c-e626f9e2f0ec)

## Requirements

- Python 3.8+
- discord.py 2.3+
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

### Message Editing and Deletion
- Context menu - `Edit Censored Message` - Edit a censored message
- Context menu - `Deleete Censored Message` - Delete a censored message
  
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

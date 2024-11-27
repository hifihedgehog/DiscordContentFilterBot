# Discord Content Filter Bot

A feature-rich and expertly crafted Discord censoring bot that provides dual-mode content filtering via term-based pattern matching and regular expressions, customizable blacklists and whitelists, global and blacklist-level exceptions, customizable DM messaging, and a time- and occurrence-based punishment system. This bot feature set surpasses a popular paid Discord censoring service by going the extra mile in doing so. Content Filter Bot supports long Nitro-length messages, allows users to edit and delete their censored messages, provides detailed insight into censors in user DMs and system logging, lets users request terms to get removed from the blacklists, and so much more.

## Important: SQLite WAL2 Requirement

This bot requires SQLite with WAL2 support, which is available in the [WAL2 branch](https://github.com/sqlite/sqlite/tree/wal2) of SQLite. This requires a custom compilation of SQLite and has been tested with:
- Version: 3.48.0
- Commit: 1adf875

By default, the standard SQLite distribution will not work as this bot specifically uses WAL2 mode for enhanced performance and reliability. You are free of course to modify this source code to use another mode, such as WAL or DELETE, in which case it will then function as expected. However, note that WAL2 mode was tested and verified so the database has high availability during times of heavy utilization of the censorship system. WAL2 provides you a consolidated, performant, portable database solution.

## Features

- **View Server Configuration**
  - See your current server configuration and all of the associated commands.

    ![ezgif-4-f55a550bbf](https://github.com/user-attachments/assets/854a21f4-257c-4d1e-9a70-e36ee3d394a8)

- **Blacklist and Whitelist Customization**
  - Add your first blacklist and optionally whitelist from a variety of sources.
  - Here are several blacklist sources to get you started. Note you may need to preprocess them if you want to extract their terms in bulk. [NotePad++](https://notepad-plus-plus.org/) is well-suited for this task.
    - [zacanger's profane-words](https://github.com/zacanger/profane-words/blob/master/words.json)
    - [Robert James Gabriel's google-profanity-words](https://github.com/coffee-and-fun/google-profanity-words/blob/main/data/en.txt)
    - [Rodger Araujo's profanity](https://github.com/rodgeraraujo/profanity/blob/main/src/data/dictionary.ts)
    - [mogade's badwords](https://github.com/mogade/badwords/blob/master/en.txt)
    - [FreeWebHeaders.com](https://www.freewebheaders.com/category/profanity/profanity-word-list/)
  - Create, modify, and delete any number of your own blacklists and whitelists with no limits.
  - Terms in a blacklist or whitelist can be made up of exact terms, URL-only terms, and regular expressions. Prefix your regular expressions with `re:` and the system automatically detects them as regular expressions. Prefix your URL terms with `url:` and the system will apply them exclusively to URLs. URL terms can be exact terms or regular expressions. A URL is defined as link beginning with `http://`, `https://`, `discord.gg/`, or `discord.com/invite/`. Leave the name parameter blank when executing the blacklist edit command to explore through the current set of blacklists. Specify a new or current list by the blacklist name parameter. The same approach applies to whitelists as well.

    ![ezgif-1-69ef3929b5](https://github.com/user-attachments/assets/6fa47fa0-99bf-441b-9fc8-95d6083d5391)

  - Sometimes, speed is of the essence in busy discussions. Quick commands come in handy for such occasions. Add a single term to either a blacklist or whitelist.

    ![ezgif-7-317117d2a6](https://github.com/user-attachments/assets/0a489350-7331-46c3-b3bc-77c43ef7e986)

  - Our sophisticated obfuscation detection deters the most hardened trolls. Reversed spellings, fancy Unicode characters, Zalgo text, and randomly inserted spaces and special characters are all properly detected. Thanks to clever pattern matching which detects word boundaries, complex patterns are found while partial matches are ignored. For example, if `mean` were added to a blacklist, the hypothetical message `you are m̂̃e..a n̈` would have a match with `m̂̃e..a n̈` but `this is a meaningful discussion` would not have a match with `meaningful`.

    ![ezgif-1-6ce4ff5daf](https://github.com/user-attachments/assets/61358bdc-991c-4b36-ac6a-92eb002d1bcc)

  - Support also includes URLs and emojis. Adding an emoji will block it not only in messages, thread titles, and (optionally) profile names, but reactions also. URLs are also supported and can be used to great effect to prevent link and invite spam.

    ![ezgif-4-e4b36cfe02](https://github.com/user-attachments/assets/59e54158-7fcf-49d7-9f91-968102b5eaca)

  - Close attention was paid to be fully Markdown-aware so surrounding formatting is respected.

    ![ezgif-7-5889783452](https://github.com/user-attachments/assets/a518af96-2f71-4221-8fc5-55afa9e0b082)

- **Reposted Bot Messages**
  - Our unique filtering handles new and edited messages, new and edited thread titles, and added message reactions. Performance was a top priority during the design and optimization phase. Instant replacement was a central design goal, and real-world performance is instantaneous. To achieve this goal, settings and wordlists, while also stored persistently, are pre-processed and cached into memory for best-in-class low latency of data retrieval and message processing. 
  - Best of all, every reposted message looks exactly as your user had posted it.

    ![ezgif-2-f1b0fab562](https://github.com/user-attachments/assets/83a03af6-68b3-469d-b139-10ddc73913ae)

  - Each user's profile image and display name is depicted in the upper left of their censored messages identical to that user's real post.
  - There is exclusive support for editing and deleting on all censored posts. The same rigorously tested filtering system blocks and advises users here as well. Moderators are also empowered to edit and delete censored messages on users' behalf as well.

    ![ezgif-7-8eeaec2e31](https://github.com/user-attachments/assets/996308b0-2725-4f59-bc95-e1a7f923a54e)

  - There is exclusive support for Nitro-length posts of up to 4000 characters. This means there is no truncation cutting off half of the lengthy message your users may have spent lengthy periods to enter. The full text no matter how long it is will always come through while respecting your censoring settings.

    ![ezgif-7-d74beafe37](https://github.com/user-attachments/assets/cbd1818d-ea27-4ebf-9304-b3e7d0e23adb)

- **Advanced Exceptions System**
  - No two servers are alike and many servers have multilingual channels, NSFW channels, or areas or members where you do not want filtering happening at all or at least not with every blacklist. 
  - To cater to a variety of needs, we offer two levels of granularity: blacklist-specific _exceptions_ and _**global** exceptions_.
  - With exceptions, add or remove any given number of roles, channels (channels include threads and forum posts), and categories to any given number of blacklists and vice versa.
  - Once exempted from a blacklist, that role, channel, or category ignores that single blacklist of blocked terms. This is perfect for multilingual communities as well as communities which require a tiered or hybrid approach.

    ![ezgif-4-f3fcefb079](https://github.com/user-attachments/assets/a5bae89a-079a-40c2-9261-af9c35959ff2)

  - Global exceptions offer a simpler, broader approach. They cover all blacklists. Select any roles, channels, and categories. Once applied, they are exempt from all blacklists.

    ![ezgif-4-f8616311d3](https://github.com/user-attachments/assets/167d4b1c-e66c-4923-8c44-b7d9212784f1)

  - You can combine both of these exception levels to suit the unique needs of your Discord server community.

- **Automated Punishments**
  - Sometimes, users may try to circumvent or overwhelm the system. This is where the bot's automated mute punishment is helpful. This is how you configure it:
    - First, specify a mute role.
    - Then select the threshold of violations over a given number of minutes.
    - Finally, configure the mute duration over a given number of hours.

    ![ezgif-7-481cf8f18f](https://github.com/user-attachments/assets/4f80f52e-d344-4f7f-bc02-9079a0451d58)

  - Once configured, the bot begins tracking. If the bot ever goes down, the SQLite database persistently stores when a mute punishment had started. In this way, the bot knows exactly when it should end, so the bot always removes the mute role once a member's mute has expired.

- **Display Name Filtering**
  - Configure display names to be filtered. Anytime a user joins or updates their profile, the bot will always be one step ahead.

    ![ezgif-4-4899e194b6](https://github.com/user-attachments/assets/5aa1b2a8-f4ce-4624-b28e-dfd5fc66510a)

    ![ezgif-4-6af9e97560](https://github.com/user-attachments/assets/9d758164-412f-4083-98dd-31d5eee75a17)

  - Regular and global role exclusions apply here. If there is a role group whose profile name you want left unfiltered, select it in either exceptions level. It will then not get filtered whenever you do enable this optional filtering.
  - The automated punishment system also applies here. Whenever someone keeps trying to use an inappropriate profile name in the chat, they will likewise receive a punishment according to your punishment configuration.

    ![ezgif-2-7b7b3da24a](https://github.com/user-attachments/assets/bacd4121-0561-4c86-a9ee-f178fcc461d5)

    ![ezgif-2-1b8035b4ea](https://github.com/user-attachments/assets/96df73f9-8bbb-456e-a592-6085ea7aec64)

- **Comprehensive Logging**
  - Everything is transparent between you and your users in the DMs and the logs. Both you in your logs and your users in their DMs can see a breakdown of the violated blacklists and associated terms, together with the full message with text both obscured and censored.
 
    ![ezgif-5-7297a8fc84](https://github.com/user-attachments/assets/3abf2fa9-e4d0-4fdf-907b-e378c6231bf4)

    ![ezgif-5-3fc2c1418e](https://github.com/user-attachments/assets/00c34036-5fee-4899-9585-d9ef225c6114)

  - Users are immediately notified via DM when they are muted by the bot. They are advised of the duration of their mute in relative time, and the exact date and time can also be seen easily by hovering over the time field.

    ![ezgif-7-203aa7266e](https://github.com/user-attachments/assets/5d40014c-62a4-49c1-a243-ab718c7c3fbf)

  - When applying a punishment lift, the acting staff member is noted along with an optional reason. This action and its reason are then recorded both in your configured log channel and the server audit logs. See the time when the lift took place in relative time units from the present, and also hover to see the exact date and time.
 
    ![ezgif-7-bbae15d9d7](https://github.com/user-attachments/assets/b4fa64f8-198b-4999-afb0-0af9d2c44072)

  - Gather a detailed history of violations from the log channel. Observe when punishments are applied and whenever they are lifted either automatically by the bot or manually by a staff member via the lift punishment command.

    ![ezgif-7-a6ce9a1d10](https://github.com/user-attachments/assets/8c85401c-ff0c-4c2f-8d3c-e626f9e2f0ec)

- **DM Message Customization**
  - Customize the DM you send to users whenever the bot notifies them of a censor event. DMs are also automatically titled with your server's name in the DM header like so: `<SERVER_NAME> Discord Server Content Filter Notification`

    ![ezgif-5-7f12ec3d26](https://github.com/user-attachments/assets/bd897b9f-7593-4a73-8cf3-a192b16d6d97)


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
- `/view_configuration` - View the current bot configuration
- `/set_moderator_role` - Set the moderator role
- `/set_term_approver_role` - Set term approver role
- `/set_log_channel` - Set logging channel
- `/set_dm_notification` - Configure DM notifications
- `/set_punishment` - Configure punishment settings
- `/set_replacement_string` - Configure replacement string
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
- `/add_global_category_exception` - Add global category exceptions
- `/remove_global_category_exception` - Remove global category exceptions
- `/add_global_channel_exception` - Add global channel exceptions
- `/remove_global_channel_exception` - Remove global channel exceptions
- `/add_global_role_exception` - Add global role exceptions
- `/remove_global_role_exception` - Remove global role exceptions
- `/list_global_exceptions` - View all global exceptions
- `/add_category_exception` - Add category exceptions
- `/add_channel_exception` - Add channel exceptions
- `/add_role_exception` - Add role exceptions
- `/remove_category_exception` - Remove category exceptions
- `/remove_channel_exception` - Remove channel exceptions
- `/remove_role_exception` - Remove role exceptions
- `/list_exceptions` - View all exceptions

### Moderation Tools
- `/scan_last_messages` - Scan recent messages
- `/lift_punishment` - Remove punishments
- `/view_term_request_history` - View and manage term requests

### User
- `/request_term_removal` - Request removal of a term from blacklists
- Context menu - `Edit Censored Message` - Edit a censored message
- Context menu - `Delete Censored Message` - Delete a censored message
  
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
	"punishment_role": 123456789012345678,
	"punishment_duration": {
		"days": 0,
		"seconds": 3600,
		"microseconds": 0
	},
	"dm_notifications": "Your content was modified because of inappropriate content or a false positive. Note that you can always edit and delete your censored messages from the context menu under *Apps→Edit Censored Message* and *Apps→Delete Censored Message*. If you believe this censor to be in error, please report the erroneous term(s) with the slash command `/request_term_removal`. We greatly appreciate users who report false positives that should be whitelisted.\n\n Note that if you repeatedly try to circumvent a censor including false positives, after {max_violations} attempt(s) in {time_window}, you will be automatically timed out for the period of {punishment_duration}. Outside of the system's automated punishment, moderators will never manually punish a user for a false positive. Thank you for your understanding.",
	"replacement_string": "***"
}
```

## Contributing
To help make this bot even better, follow these five simple steps to contribute.
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

If you found this bot at all helpful, in lieu of development contribution, [please consider donating to the Humanitarian Services of The Church of Jesus Christ of Latter-day Saints.](https://philanthropies.churchofjesuschrist.org/humanitarian-services)

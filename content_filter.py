"""
Discord Content Filter Bot
-------------------------
A comprehensive content moderation bot supporting blacklists, whitelists,
automated punishments, and extensive filtering capabilities.

Author: Hifihedgehog
Version: 1.0.0
License: MIT
"""

import aiofiles
import aiosqlite
import asyncio
import discord
import discord.utils
import emoji
import json
import os
import regex
import unicodedata
from asyncio import Queue
from datetime import datetime, timedelta, timezone
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv
from typing import List, Optional, Tuple, Union

# Load environment variables from .env file
load_dotenv()

# Core Constants
MAX_MESSAGE_LENGTH = 2000
CONFIG_DIR = "server_configs"
DATABASE_PATH = os.path.join(CONFIG_DIR, "censored_messages.db")
CHARACTER_MAP_PATH = "full_character_map.json"

# Markdown Processing
MARKDOWN_MARKERS = ['```', '***', '**', '*', '__', '___', '~~', '`', '||']
MARKDOWN_MARKERS.sort(key=lambda x: -len(x))

# URL Regex Pattern
URL_REGEX = r'\b(?:https?://[^\s]+|(?:discord\.gg/|discord\.com/invite/)[^\s]+)\b'

# Global Caches
character_map = {}
pattern_cache = {}
server_config_cache = {}
webhook_cache = {}

# Global Task Queues
message_deletion_queue = Queue()
reaction_removal_queue = Queue()

# Bot Setup with Required Intents
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)

# Permission Check Decorators
def is_admin():
    """Decorator to check if user has administrator permissions."""
    async def predicate(interaction: discord.Interaction) -> bool:
        guild = interaction.guild
        if not guild:
            return False
        member = interaction.user
        return member.guild_permissions.administrator
    return app_commands.check(predicate)

def is_moderator():
    """Decorator to check if user has moderator role or administrator permissions."""
    async def predicate(interaction: discord.Interaction) -> bool:
        guild = interaction.guild
        if not guild:
            return False
        
        member = interaction.user
        if not isinstance(member, discord.Member):
            return False
            
        if member.guild_permissions.administrator:
            return True
            
        server_config = await load_server_config(guild.id)
        guild_moderator_role_id = server_config.get("moderator_role_id")        
        
        return guild_moderator_role_id and any(
            role.id == guild_moderator_role_id for role in member.roles
        )

    return app_commands.check(predicate)

def is_term_approver():
    async def predicate(interaction: discord.Interaction):
        if interaction.user.guild_permissions.administrator:
            return True
        return await has_term_approver_role(interaction.user)
    return app_commands.check(predicate)

async def has_term_approver_role(member: discord.Member) -> bool:
    """Check if the member has the term approver role."""
    server_config = await load_server_config(member.guild.id)
    term_approver_role_id = server_config.get("term_approver_role_id")
    if term_approver_role_id:
        term_approver_role = member.guild.get_role(term_approver_role_id)
        if term_approver_role in member.roles:
            return True
    return False

# Error Handler for Permission Checks
@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    """Global error handler for application commands."""
    if isinstance(error, app_commands.CheckFailure):
        await interaction.response.send_message(
            "You do not have permission to use this command.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            "An unexpected error occurred. Please contact an administrator.",
            ephemeral=True
        )

# Database Functions
async def initialize_database():
    """Initialize SQLite database with required tables and indexes."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    async with aiosqlite.connect(DATABASE_PATH) as db:
        print(f"SQLite Version: {aiosqlite.sqlite_version}")
        
        async with db.execute("PRAGMA journal_mode = WAL2;") as cursor:
            result = await cursor.fetchone()
            if result and result[0].upper() == "WAL2":
                print("Journal mode successfully set to WAL2.")
        await db.execute("PRAGMA synchronous = normal")
        await db.execute("PRAGMA temp_store = memory")
        await db.execute("PRAGMA mmap_size = 1000000000;")
            
        await db.execute("""
            CREATE TABLE IF NOT EXISTS censored_messages (
                guild_id INTEGER,
                message_id INTEGER,
                author_id INTEGER,
                webhook_id INTEGER,
                webhook_token TEXT,
                PRIMARY KEY (guild_id, message_id)
            )
        """)
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS user_violations (
                guild_id INTEGER,
                user_id INTEGER,
                timestamp TEXT,
                PRIMARY KEY (guild_id, user_id, timestamp)
            )
        """)
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS punishments (
                guild_id INTEGER,
                user_id INTEGER,
                role_id INTEGER,
                expiration_time TEXT,
                PRIMARY KEY (guild_id, user_id, role_id)
            )
        """)
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS term_removal_requests (
                guild_id INTEGER,
                term TEXT,
                reporter_id INTEGER,
                status TEXT,
                reason TEXT,
                timestamp TEXT,
                message_id INTEGER,
                blacklists_modified TEXT,
                PRIMARY KEY (guild_id, term)
            )
        """)
        
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_guild_id 
            ON censored_messages (guild_id)
        """)
        
        await db.commit()

async def save_censored_message(guild_id, message_id, author_id, webhook_id, webhook_token):
    """Save information about a censored message to the database."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO censored_messages 
            VALUES (?, ?, ?, ?, ?)
        """, (guild_id, message_id, author_id, webhook_id, webhook_token))
        await db.commit()

async def get_censored_message_info(guild_id, message_id):
    """Retrieve information about a censored message."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT author_id, webhook_id, webhook_token 
            FROM censored_messages
            WHERE guild_id = ? AND message_id = ?
        """, (guild_id, message_id)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def add_user_violation(guild_id, user_id):
    """Record a content violation for a user."""
    current_time = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO user_violations VALUES (?, ?, ?)
        """, (guild_id, user_id, current_time))
        await db.commit()

async def get_recent_violations(guild_id, user_id, time_window):
    """Get recent violations for a user within specified time window."""
    cutoff_time = (datetime.now(timezone.utc) - time_window).isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("""
            SELECT timestamp FROM user_violations
            WHERE guild_id = ? AND user_id = ? AND timestamp > ?
        """, (guild_id, user_id, cutoff_time)) as cursor:
            return [row[0] for row in await cursor.fetchall()]

async def clear_user_violations(guild_id, user_id):
    """Clear all violations for a user."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            DELETE FROM user_violations
            WHERE guild_id = ? AND user_id = ?
        """, (guild_id, user_id))
        await db.commit()

async def add_punishment(guild_id, user_id, role_id, expiration_time):
    """Add or update punishment in the database."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO punishments (guild_id, user_id, role_id, expiration_time)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(guild_id, user_id, role_id) DO UPDATE SET
                expiration_time=excluded.expiration_time
        """, (guild_id, user_id, role_id, expiration_time.isoformat()))
        await db.commit()

async def remove_punishment(guild_id, user_id, role_id):
    """Remove a punishment from the database."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            DELETE FROM punishments
            WHERE guild_id = ? AND user_id = ? AND role_id = ?
        """, (guild_id, user_id, role_id))
        await db.commit()

async def get_expired_punishments():
    """Get all punishments that have expired."""
    now_iso = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("""
            SELECT guild_id, user_id, role_id FROM punishments
            WHERE expiration_time <= ?
        """, (now_iso,)) as cursor:
            return await cursor.fetchall()

# Server Configuration Functions
async def load_server_config(guild_id: int) -> dict:
    """Load server configuration from cache or file."""
    if guild_id in server_config_cache:
        return server_config_cache[guild_id]
        
    default_dm_message = (
        "Your content was modified because of inappropriate content or a false positive. Note that you can always edit and delete your censored messages from the context menu under *Apps→Edit Censored Message* and *Apps→Delete Censored Message*. If you believe this censor to be in error, please report the erroneous term(s) with the slash command `/request_term_removal`. We greatly appreciate users who report false positives that should be whitelisted.\n\n"
        "Note that if you repeatedly try to circumvent a censor including false positives, after {max_violations} attempt(s) in {time_window}, you will be automatically muted for the period of {punishment_duration}. Outside of the system's automated punishment, moderators will never manually punish a user for a false positive. Thank you for your understanding."
    )
    default_replacement_string = "***"

    config_path = os.path.join(CONFIG_DIR, f"{guild_id}.json")
    if os.path.exists(config_path):
        try:
            async with aiofiles.open(config_path, "r") as f:
                config = json.loads(await f.read())
                config["punishments"]["time_window"] = await dict_to_timedelta(config["punishments"]["time_window"])
                config["punishments"]["punishment_duration"] = await dict_to_timedelta(config["punishments"]["punishment_duration"])

                config.setdefault("global_exceptions", {"categories": [], "channels": [], "roles": []})
                config.setdefault("exceptions", {"categories": {}, "channels": {}, "roles": {}})

                for key in ["categories", "channels", "roles"]:
                    config["global_exceptions"][key] = [int(value) for value in config["global_exceptions"].get(key, [])]
                    config["exceptions"][key] = {int(k): v for k, v in config["exceptions"].get(key, {}).items()}

                config.setdefault("moderator_role_id", None)
                config.setdefault("term_approver_role_id", None)
                config.setdefault("dm_notifications", default_dm_message)
                config.setdefault("replacement_string", default_replacement_string)
                
                server_config_cache[guild_id] = config
                return config
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"Error loading config for guild {guild_id}: {e}. Resetting to default.")

    default_config = {
        "blacklists": {},
        "whitelists": {},
        "exceptions": {"categories": {}, "channels": {}, "roles": {}},
        "global_exceptions": {"categories": [], "channels": [], "roles": []},
        "punishments": {
            "max_violations": 3,
            "time_window": timedelta(minutes=5),
            "punishment_role": None,
            "punishment_duration": timedelta(hours=1),
        },
        "display_name_filter_enabled": False,
        "log_channel_id": None,
        "dm_notifications": default_dm_message,
        "moderator_role_id": None,
        "term_approver_role_id": None,
        "replacement_string": default_replacement_string,
    }
    server_config_cache[guild_id] = default_config
    return default_config

async def save_server_config(guild_id: int, config: dict):
    """Save server configuration to cache and file."""
    server_config_cache[guild_id] = config
    config_to_save = config.copy()
    
    config_to_save["punishments"]["time_window"] = await timedelta_to_dict(
        config["punishments"]["time_window"]
    )
    config_to_save["punishments"]["punishment_duration"] = await timedelta_to_dict(
        config["punishments"]["punishment_duration"]
    )
    
    config_to_save["blacklists"] = dict(sorted(config_to_save["blacklists"].items()))
    config_to_save["whitelists"] = dict(sorted(config_to_save["whitelists"].items()))
    for key in ["categories", "channels", "roles"]:
        config_to_save["global_exceptions"][key] = sorted(map(int, config_to_save["global_exceptions"].get(key, [])))
        config_to_save["exceptions"][key] = {int(k): v for k, v in sorted(config_to_save["exceptions"].get(key, {}).items())}

    os.makedirs(CONFIG_DIR, exist_ok=True)
    config_path = os.path.join(CONFIG_DIR, f"{guild_id}.json")
    
    async with aiofiles.open(config_path, "w") as f:
        await f.write(json.dumps(config_to_save, indent=4))
        
    config["punishments"]["time_window"] = await dict_to_timedelta(config_to_save["punishments"]["time_window"])
    config["punishments"]["punishment_duration"] = await dict_to_timedelta(config_to_save["punishments"]["punishment_duration"])

# Utility Functions
async def timedelta_to_dict(td):
    """Convert timedelta to serializable dictionary."""
    return {
        "days": td.days,
        "seconds": td.seconds,
        "microseconds": td.microseconds
    }

async def dict_to_timedelta(td_dict):
    """Convert dictionary back to timedelta."""
    return timedelta(
        days=td_dict["days"],
        seconds=td_dict["seconds"],
        microseconds=td_dict["microseconds"]
    )
    
async def format_timedelta(td: timedelta) -> str:
    """Format a timedelta object into a human-readable string."""
    total_seconds = int(td.total_seconds())
    periods = [
        ('day', 86400),  # 60 * 60 * 24
        ('hour', 3600),  # 60 * 60
        ('minute', 60),
        ('second', 1),
    ]
    strings = []
    for period_name, period_seconds in periods:
        if total_seconds >= period_seconds:
            period_value, total_seconds = divmod(total_seconds, period_seconds)
            if period_value > 0:
                strings.append(f"{period_value} {period_name}{'s' if period_value > 1 else ''}")
    return ', '.join(strings)
    
async def load_character_map():
    """Load the character map from the JSON file."""
    try:
        async with aiofiles.open(CHARACTER_MAP_PATH, "r") as f:
            loaded_map = json.loads(await f.read())
            character_map.update(loaded_map)
        print("Character map loaded.")
    except Exception as e:
        print(f"Error loading character map: {e}")

async def setup_webhook(channel):
    """Set up or retrieve webhook for message reposting."""
    parent_channel = channel.parent if isinstance(channel, discord.Thread) else channel

    if parent_channel.id in webhook_cache:
        return webhook_cache[parent_channel.id]
    
    existing_webhooks = await parent_channel.webhooks()
    bot_webhooks = [wh for wh in existing_webhooks if wh.name.startswith("Content Filter Bot")]

    if not bot_webhooks:
        new_webhook = await parent_channel.create_webhook(name="Content Filter Bot")
        bot_webhooks.append(new_webhook)

    webhook_cache[parent_channel.id] = bot_webhooks[0]
    return bot_webhooks[0]
    
def escape_markdown(text: str) -> str:
    markdown_chars = ['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|', '>', '~']
    escape_dict = {ord(char): f"\\{char}" for char in markdown_chars}
    return text.translate(escape_dict)

# Content Pattern Processing
async def is_emoji_or_sequence(s):
    """Check if string is emoji or emoji sequence."""
    if not isinstance(s, str) or not s:
        return False

    custom_emoji_pattern = regex.compile(r'^<a?:\w+:\d+>$')
    if custom_emoji_pattern.match(s):
        return True

    emojis_found = emoji.emoji_list(s)
    if not emojis_found:
        return False

    emoji_spans = [(e['match_start'], e['match_end']) for e in emojis_found]
    emoji_spans.sort(key=lambda x: x[0])
    
    merged_spans = []
    for span in emoji_spans:
        if not merged_spans:
            merged_spans.append(span)
        else:
            last_span = merged_spans[-1]
            if span[0] <= last_span[1]:
                merged_spans[-1] = (last_span[0], max(last_span[1], span[1]))
            else:
                merged_spans.append(span)

    current_pos = 0
    for start, end in merged_spans:
        if start > current_pos:
            return False
        current_pos = end

    return current_pos == len(s)

async def normalize_text(text: str) -> Tuple[str, List[int]]:
    """Normalize text while preserving emojis and special characters."""
    normalized_text = []
    index_map = []

    for idx, char in enumerate(text):
        if await is_emoji_or_sequence(char):
            normalized_text.append(char)
            index_map.append(idx)
        else:
            normalized_char = unicodedata.normalize('NFKD', char)
            normalized_char = ''.join(c for c in normalized_char if not unicodedata.combining(c))
            mapped_characters = ''.join(character_map.get(c, c) for c in normalized_char)
            for norm_char in mapped_characters:
                normalized_text.append(norm_char)
                index_map.append(idx)

    return ''.join(normalized_text), index_map

async def merge_ranges(ranges):
    """Merge overlapping or contiguous ranges."""
    if not ranges:
        return []
    sorted_ranges = sorted(ranges, key=lambda x: x[0])
    merged = [sorted_ranges[0]]
    
    for current in sorted_ranges[1:]:
        last = merged[-1]
        if current[0] <= last[1]:
            merged[-1] = (last[0], max(last[1], current[1]))
        else:
            merged.append(current)
    return merged

async def get_whitelist_pattern(term: str) -> regex.Pattern:
    """Get compiled pattern for whitelist term with additional checks."""
    cache_key = f"wl:{term}"
    if cache_key not in pattern_cache:
        normalized_term, _ = await normalize_text(term)
        word_boundary_start = r'(?<![A-Za-z0-9])'
        word_boundary_end = r'(?![A-Za-z0-9])'

        if term.startswith("re:"):
            pattern = word_boundary_start + term[3:] + word_boundary_end
        elif await is_emoji_or_sequence(term):
            pattern = regex.escape(term)
        else:

            def create_subpatterns(base_term: str):
                return [
                    word_boundary_start + regex.escape(base_term) + word_boundary_end
                ]
            subpatterns = (
                create_subpatterns(term)
                + create_subpatterns(normalized_term)
            )
            pattern = f"(?:{'|'.join(subpatterns)})"
        pattern_cache[cache_key] = regex.compile(pattern, regex.IGNORECASE)
    return pattern_cache[cache_key]

async def get_blacklist_pattern(term: str) -> regex.Pattern:
    """Get compiled pattern for blacklist term with obfuscation and additional checks."""
    cache_key = f"bl:{term}"
    if cache_key not in pattern_cache:
        normalized_term, _ = await normalize_text(term)
        reversed_term = term[::-1]
        normalized_reversed_term = normalized_term[::-1]      
        word_boundary_start = r'(?<![A-Za-z0-9])'
        word_boundary_end = r'(?![A-Za-z0-9])'
        if term.startswith("url:"):
            pattern = term[4:]
        elif term.startswith("re:"):
            pattern = word_boundary_start + term[3:] + word_boundary_end
        elif await is_emoji_or_sequence(term):
            pattern = regex.escape(term)
        else:

            def create_subpatterns(base_term: str):
                word_pattern = word_boundary_start + regex.escape(base_term) + word_boundary_end
                obfuscated_pattern = word_boundary_start + r'[^\w]*'.join(regex.escape(char) for char in base_term) + word_boundary_end
                md_markers_class = ''.join(map(regex.escape, MARKDOWN_MARKERS))
                markdown_intermediate = ''.join(
                    f'{regex.escape(char)}(?:[{md_markers_class}]*)'
                    for char in base_term[:-1]
                )
                markdown_last_char = regex.escape(base_term[-1])
                markdown_pattern = word_boundary_start + markdown_intermediate + markdown_last_char + word_boundary_end
                return [word_pattern, obfuscated_pattern, markdown_pattern]
            subpatterns = (
                create_subpatterns(term)
                + create_subpatterns(normalized_term)
                + create_subpatterns(reversed_term)
                + create_subpatterns(normalized_reversed_term)
            )
            pattern = f"(?:{'|'.join(subpatterns)})"
        pattern_cache[cache_key] = regex.compile(pattern, regex.IGNORECASE)
    return pattern_cache[cache_key]

async def is_globally_exempt(channel: Optional[Union[discord.Thread, discord.abc.GuildChannel]],
                           author: Union[discord.User, discord.Member],
                           server_config: dict) -> bool:
    """Check if message is globally exempt from filtering."""
    global_exceptions = server_config.get("global_exceptions", {})
    
    if channel:
        if channel.id in global_exceptions.get("channels", []):
            return True

        parent_channel = channel.parent if isinstance(channel, discord.Thread) else channel
        if parent_channel and parent_channel.id in global_exceptions.get("channels", []):
            return True

        category = parent_channel.category if parent_channel else None
        if category and category.id in global_exceptions.get("categories", []):
            return True

    if isinstance(author, discord.Member):
        user_role_ids = {role.id for role in author.roles}
        if user_role_ids.intersection(global_exceptions.get("roles", [])):
            return True

    return False

async def check_exceptions(channel: Optional[Union[discord.Thread, discord.abc.GuildChannel]],
                        author: Union[discord.User, discord.Member],
                        server_config: dict,
                        blacklist_name: str) -> bool:
    """Check if content is exempt from filtering based on the new exceptions structure."""
    if await is_globally_exempt(channel, author, server_config):
        return True

    exceptions = server_config.get("exceptions", {})
    channel_exceptions = exceptions.get("channels", {})
    category_exceptions = exceptions.get("categories", {})
    role_exceptions = exceptions.get("roles", {})
    role_ids = [role.id for role in getattr(author, "roles", [])] if isinstance(author, discord.Member) else []

    if channel:
        if channel.id in channel_exceptions and blacklist_name in channel_exceptions[channel.id]:
            return True

        parent_channel = channel.parent if isinstance(channel, discord.Thread) else channel
        if parent_channel:
            if parent_channel.id in channel_exceptions and blacklist_name in channel_exceptions[parent_channel.id]:
                return True

            if parent_channel.category and parent_channel.category.id in category_exceptions:
                if blacklist_name in category_exceptions[parent_channel.category.id]:
                    return True

    for role_id in role_ids:
        if role_id in role_exceptions and blacklist_name in role_exceptions[role_id]:
            return True

    return False

# Content Filtering Functions
async def censor_content(content: str, channel: Optional[Union[discord.Thread, discord.abc.GuildChannel]], 
                         author: Union[discord.User, discord.Member], server_config: dict) -> str:
    """Apply censorship to content based on blacklists and whitelists."""
    if await is_globally_exempt(channel, author, server_config):
        return content

    blacklists = server_config.get("blacklists", {})
    whitelists = server_config.get("whitelists", {})
    replacement_string = server_config.get("replacement_string", "***")
    replacement_string = escape_markdown(replacement_string)
    normalized_content, index_map = await normalize_text(content)
    exempt_ranges_original = []
    exempt_ranges_normalized = []

    all_whitelist_terms = [term for terms in whitelists.values() for term in terms]

    for term in all_whitelist_terms:
        pattern = await get_whitelist_pattern(term)
        for match in pattern.finditer(content):
            exempt_ranges_original.append((match.start(), match.end()))

    for term in all_whitelist_terms:
        pattern = await get_whitelist_pattern(term)
        for match in pattern.finditer(normalized_content):
            orig_start = index_map[match.start()]
            orig_end = index_map[match.end() - 1] + 1
            exempt_ranges_normalized.append((orig_start, orig_end))

    url_matches = list(regex.finditer(URL_REGEX, content))
    match_ranges_original = []
    match_ranges_normalized = []

    for url_match in url_matches:
        url_text = url_match.group()
        url_start, url_end = url_match.start(), url_match.end()

        is_blacklisted = False
        for blacklist_name, terms in blacklists.items():
            if await check_exceptions(channel, author, server_config, blacklist_name):
                continue

            url_terms = [term for term in terms if term.startswith("url:")]

            for term in url_terms:
                pattern = await get_blacklist_pattern(term)
                if pattern.search(url_text):
                    is_blacklisted = True
                    break
            if is_blacklisted:
                break

        if is_blacklisted:
            match_ranges_original.append((url_start, url_end))
        else:
            exempt_ranges_original.append((url_start, url_end))

    merged_exempt_ranges = await merge_ranges(exempt_ranges_original + exempt_ranges_normalized)

    for blacklist_name, terms in blacklists.items():
        if await check_exceptions(channel, author, server_config, blacklist_name):
            continue

        general_terms = [term for term in terms if not term.startswith("url:")]

        for term in general_terms:
            pattern = await get_blacklist_pattern(term)
            for match in pattern.finditer(content):
                start, end = match.start(), match.end()
                if not any(ex_start <= start < ex_end or ex_start < end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    match_ranges_original.append((start, end))

            for match in pattern.finditer(normalized_content):
                start_norm, end_norm = match.start(), match.end()
                orig_start = index_map[start_norm]
                orig_end = index_map[end_norm - 1] + 1
                if not any(ex_start <= orig_start < ex_end or ex_start < orig_end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    match_ranges_normalized.append((orig_start, orig_end))

    merged_match_ranges = await merge_ranges(match_ranges_original + match_ranges_normalized)

    censored_message_content = ""
    last_index = 0
    for start, end in merged_match_ranges:
        censored_message_content += content[last_index:start]
        censored_message_content += replacement_string
        last_index = end
    censored_message_content += content[last_index:]

    return censored_message_content


async def apply_spoilers(content: str, channel: Optional[Union[discord.Thread, discord.abc.GuildChannel]], 
                         author: Union[discord.User, discord.Member], server_config: dict) -> str:
    """Apply spoiler tags to blacklisted content."""
    if await is_globally_exempt(channel, author, server_config):
        return content

    blacklists = server_config.get("blacklists", {})
    whitelists = server_config.get("whitelists", {})
    normalized_content, index_map = await normalize_text(content)
    exempt_ranges_original = []
    exempt_ranges_normalized = []

    all_whitelist_terms = [term for terms in whitelists.values() for term in terms]

    for term in all_whitelist_terms:
        pattern = await get_whitelist_pattern(term)
        for match in pattern.finditer(content):
            exempt_ranges_original.append((match.start(), match.end()))

    for term in all_whitelist_terms:
        pattern = await get_whitelist_pattern(term)
        for match in pattern.finditer(normalized_content):
            orig_start = index_map[match.start()]
            orig_end = index_map[match.end() - 1] + 1
            exempt_ranges_normalized.append((orig_start, orig_end))

    url_matches = list(regex.finditer(URL_REGEX, content))
    match_ranges_original = []
    match_ranges_normalized = []

    for url_match in url_matches:
        url_text = url_match.group()
        url_start, url_end = url_match.start(), url_match.end()

        is_blacklisted = False
        for blacklist_name, terms in blacklists.items():
            if await check_exceptions(channel, author, server_config, blacklist_name):
                continue

            url_terms = [term for term in terms if term.startswith("url:")]

            for term in url_terms:
                pattern = await get_blacklist_pattern(term)
                if pattern.search(url_text):
                    is_blacklisted = True
                    break
            if is_blacklisted:
                break

        if is_blacklisted:
            match_ranges_original.append((url_start, url_end))
        else:
            exempt_ranges_original.append((url_start, url_end))

    merged_exempt_ranges = await merge_ranges(exempt_ranges_original + exempt_ranges_normalized)

    for blacklist_name, terms in blacklists.items():
        if await check_exceptions(channel, author, server_config, blacklist_name):
            continue

        general_terms = [term for term in terms if not term.startswith("url:")]

        for term in general_terms:
            pattern = await get_blacklist_pattern(term)
            for match in pattern.finditer(content):
                start, end = match.start(), match.end()
                if not any(ex_start <= start < ex_end or ex_start < end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    match_ranges_original.append((start, end))

            for match in pattern.finditer(normalized_content):
                start_norm, end_norm = match.start(), match.end()
                orig_start = index_map[start_norm]
                orig_end = index_map[end_norm - 1] + 1
                if not any(ex_start <= orig_start < ex_end or ex_start < orig_end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    match_ranges_normalized.append((orig_start, orig_end))

    merged_match_ranges = await merge_ranges(match_ranges_original + match_ranges_normalized)

    censored_message_content = ""
    last_index = 0
    for start, end in merged_match_ranges:
        censored_message_content += content[last_index:start]
        censored_message_content += f'||{content[start:end]}||'
        last_index = end
    censored_message_content += content[last_index:]

    return censored_message_content

async def get_blocked_terms(content: str, channel: Optional[Union[discord.Thread, discord.abc.GuildChannel]], 
                            author: Union[discord.User, discord.Member], server_config: dict, 
                            blacklist: Optional[str] = None) -> set:
    """Get list of blocked terms applied to target content."""
    matched_terms = set()

    if await is_globally_exempt(channel, author, server_config):
        return matched_terms

    whitelists = server_config.get("whitelists", {})
    blacklists = server_config.get("blacklists", {})
    normalized_content, index_map = await normalize_text(content)
    exempt_ranges_original = []
    exempt_ranges_normalized = []

    all_whitelist_terms = [term for terms in whitelists.values() for term in terms]

    for term in all_whitelist_terms:
        pattern = await get_whitelist_pattern(term)
        for match in pattern.finditer(content):
            exempt_ranges_original.append((match.start(), match.end()))

    for term in all_whitelist_terms:
        pattern = await get_whitelist_pattern(term)
        for match in pattern.finditer(normalized_content):
            orig_start = index_map[match.start()]
            orig_end = index_map[match.end() - 1] + 1
            exempt_ranges_normalized.append((orig_start, orig_end))

    url_matches = list(regex.finditer(URL_REGEX, content, regex.IGNORECASE))

    if blacklist:
        if await check_exceptions(channel, author, server_config, blacklist):
            return matched_terms
        target_blacklist = blacklists.get(blacklist, [])

        url_terms = [term for term in target_blacklist if term.startswith("url:")]
        general_terms = [term for term in target_blacklist if not term.startswith("url:")]

        for url_match in url_matches:
            url_text = url_match.group()
            url_start, url_end = url_match.start(), url_match.end()

            is_blacklisted = False
            for term in url_terms:
                pattern = await get_blacklist_pattern(term)
                if pattern.search(url_text):
                    matched_terms.add(term)
                    is_blacklisted = True
                    break
            if not is_blacklisted:
                exempt_ranges_original.append((url_start, url_end))

        merged_exempt_ranges = await merge_ranges(exempt_ranges_original + exempt_ranges_normalized)

        for term in general_terms:
            pattern = await get_blacklist_pattern(term)
            for match in pattern.finditer(content):
                start, end = match.start(), match.end()
                if not any(ex_start <= start < ex_end or ex_start < end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    matched_terms.add(term)
            for match in pattern.finditer(normalized_content):
                start_norm, end_norm = match.start(), match.end()
                orig_start = index_map[start_norm]
                orig_end = index_map[end_norm - 1] + 1
                if not any(ex_start <= orig_start < ex_end or ex_start < orig_end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    matched_terms.add(term)
    else:
        url_terms = []
        general_terms = []

        for blacklist_name, terms in blacklists.items():
            if await check_exceptions(channel, author, server_config, blacklist_name):
                continue
            url_terms.extend([term for term in terms if term.startswith("url:")])
            general_terms.extend([term for term in terms if not term.startswith("url:")])

        for url_match in url_matches:
            url_text = url_match.group()
            url_start, url_end = url_match.start(), url_match.end()

            is_blacklisted = False
            for term in url_terms:
                pattern = await get_blacklist_pattern(term)
                if pattern.search(url_text):
                    matched_terms.add(term)
                    is_blacklisted = True
                    break
            if not is_blacklisted:
                exempt_ranges_original.append((url_start, url_end))

        merged_exempt_ranges = await merge_ranges(exempt_ranges_original + exempt_ranges_normalized)

        for term in general_terms:
            pattern = await get_blacklist_pattern(term)
            for match in pattern.finditer(content):
                start, end = match.start(), match.end()
                if not any(ex_start <= start < ex_end or ex_start < end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    matched_terms.add(term)
            for match in pattern.finditer(normalized_content):
                start_norm, end_norm = match.start(), match.end()
                orig_start = index_map[start_norm]
                orig_end = index_map[end_norm - 1] + 1
                if not any(ex_start <= orig_start < ex_end or ex_start < orig_end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    matched_terms.add(term)

    return matched_terms

# Message Handling Functions
async def split_message_preserving_markdown(message: str, max_length: int = MAX_MESSAGE_LENGTH) -> List[str]:
    """Split long messages while preserving Markdown formatting."""
    chunks = []
    current_chunk = ""
    open_markers = []
    in_code = False
    last_safe_split_pos = 0

    i = 0
    message_length = len(message)

    while i < message_length:
        matched_marker = None
        for marker in MARKDOWN_MARKERS:
            if message.startswith(marker, i):
                matched_marker = marker
                break

        if matched_marker:
            if matched_marker in ['```', '`']:
                if in_code and open_markers and open_markers[-1] == matched_marker:
                    open_markers.pop()
                    in_code = False
                else:
                    open_markers.append(matched_marker)
                    in_code = True
            elif not in_code:
                if open_markers and open_markers[-1] == matched_marker:
                    open_markers.pop()
                else:
                    open_markers.append(matched_marker)
            current_chunk += matched_marker
            i += len(matched_marker)
        else:
            current_chunk += message[i]
            i += 1

        if not in_code and not open_markers:
            last_safe_split_pos = len(current_chunk)

        if len(current_chunk) > max_length - 1:
            if last_safe_split_pos > 0:
                chunks.append(current_chunk[:last_safe_split_pos].rstrip())
                current_chunk = current_chunk[last_safe_split_pos:].lstrip()
                last_safe_split_pos = 0
            else:
                split_point = max_length
                for marker in MARKDOWN_MARKERS:
                    marker_len = len(marker)
                    if current_chunk.endswith(marker, split_point - marker_len, split_point):
                        split_point -= marker_len
                        break
                if split_point <= 0:
                    split_point = max_length
                
                split_chunk = current_chunk[:split_point].rstrip()
                if split_chunk.endswith('`'):
                    split_chunk = split_chunk[:-1]
                    current_chunk = '`' + current_chunk[split_point:].lstrip()
                else:
                    current_chunk = current_chunk[split_point:].lstrip()
                chunks.append(split_chunk)
                last_safe_split_pos = 0

    if current_chunk:
        chunks.append(current_chunk)

    return chunks

async def send_long_message(interaction: discord.Interaction, message: str, emphemeral: bool = True):
    """Send long messages split into chunks."""
    message_chunks = await split_message_preserving_markdown(message)
    for chunk in message_chunks:
        await interaction.followup.send(chunk, ephemeral=emphemeral)

async def repost_as_user(message: discord.Message, censored_message: str) -> discord.Message:
    """Repost censored message via webhook."""
    webhook = await setup_webhook(message.channel)
    author = message.author
    
    if isinstance(author, discord.Member):
        username = author.display_name
        avatar_url = author.display_avatar.url if author.display_avatar else None
    else:
        username = author.name
        avatar_url = author.display_avatar.url if author.display_avatar else None

    if len(censored_message) > 2000:
        embed = discord.Embed(description=censored_message)
        send_kwargs = {'embed': embed, 'username': username, 'avatar_url': avatar_url, 'wait': True}
    else:
        send_kwargs = {'content': censored_message[:2000], 'username': username, 'avatar_url': avatar_url, 'wait': True}
    if isinstance(message.channel, discord.Thread):
        send_kwargs['thread'] = message.channel

    try:
        bot_message = await webhook.send(**send_kwargs)
    except discord.HTTPException as e:
        print(f"Failed to send censored message via webhook: {e}")
        return

    await save_censored_message(message.guild.id, bot_message.id, message.author.id, webhook.id, webhook.token)
    return bot_message

# Notification Functions
async def notify_user_message(message, censored_message, reposted_message, server_config):
    """Notify user about message censorship."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(message.content, message.channel, message.author, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(message.content, message.channel, message.author, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(message.content, message.channel, message.author, server_config))

    embeds = []
    
    embed_1 = discord.Embed(title=f"{message.guild.name} Discord Server Content Filter Notification", color=discord.Color.red())
    value = server_config.get("dm_notifications", "Your message was filtered because it contains blacklisted content.")
    punishments = server_config.get("punishments")
    max_violations = punishments.get("max_violations")
    time_window = punishments.get("time_window")
    punishment_duration = punishments.get("punishment_duration")
    time_window_str = await format_timedelta(time_window)
    punishment_duration_str = await format_timedelta(punishment_duration)
    value = value.format(
        max_violations=max_violations,
        time_window=time_window_str,
        punishment_duration=punishment_duration_str
    )
    embed_1.add_field(name="", value=value, inline=False)
    embeds.append(embed_1)
    
    embed_2 = discord.Embed(title="Message Censored", color=discord.Color.red(), timestamp=datetime.now(timezone.utc))
    
    if len(spoilered_content) > 1024:
        embed_2.add_field(name="Your Message With Blocked Terms Hidden (Truncated)", value=spoilered_content[:1024], inline=False)
        embed_3 = discord.Embed(title=f"Your Message With Blocked Terms Hidden (Full)", description=spoilered_content, color=discord.Color.red())
    else:
        embed_2.add_field(name="Your Message With Blocked Terms Hidden", value=spoilered_content or "No content", inline=False)

    if len(censored_message) > 1024:
        embed_2.add_field(name="Censored Message (Truncated)", value=censored_message[:1024],inline=False)
        embed_4 = discord.Embed(title=f"Censored Message (Full)", description=censored_message, color=discord.Color.red())
    else:
        embed_2.add_field(name="Censored Message", value=censored_message or "No content", inline=False)
        
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed_2.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed_2.add_field(name="Blocked Terms", 
                       value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
                       inline=False)

    embed_2.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed_2.add_field(name="Message Link", value=f"[Go to Message]({reposted_message.jump_url})", inline=False)
    embeds.append(embed_2)
    
    try:
        await message.author.send(embeds=embeds)
        if len(spoilered_content) > 1024:
            await message.author.send(embed=embed_3)
        if len(censored_message) > 1024:
            await message.author.send(embed=embed_4)
    except discord.Forbidden:
        pass

async def notify_user_thread_title(thread, censored_title, server_config):
    """Notify user about thread title censorship."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(thread.name, thread, thread.owner, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(thread.name, thread, thread.owner, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(thread.name, thread, thread.owner, server_config))
                    
    embeds = []
    
    embed_1 = discord.Embed(title=f"{thread.guild.name} Discord Server Content Filter Notification", color=discord.Color.orange())
    value = server_config.get("dm_notifications", "Your thread was filtered because it contains blacklisted content.")
    punishments = server_config.get("punishments")
    max_violations = punishments.get("max_violations")
    time_window = punishments.get("time_window")
    punishment_duration = punishments.get("punishment_duration")
    time_window_str = await format_timedelta(time_window)
    punishment_duration_str = await format_timedelta(punishment_duration)
    value = value.format(
        max_violations=max_violations,
        time_window=time_window_str,
        punishment_duration=punishment_duration_str
    )
    embed_1.add_field(name="", value=value, inline=False)
    embeds.append(embed_1)
    
    embed_2 = discord.Embed(title="Thread Title Censored", color=discord.Color.orange(), timestamp=datetime.now(timezone.utc))
    embed_2.add_field(name="Your Thread's Title With Blocked Terms Hidden",
                   value=spoilered_content[:1024] or "No content", inline=False)
    embed_2.add_field(name="Censored Title",
                   value=censored_title[:1024] or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed_2.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed_2.add_field(name="Blocked Terms",
                       value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
                       inline=False)

    embed_2.add_field(name="Channel", value=thread.parent.mention, inline=False)
    embed_2.add_field(name="Message Link", value=f"[Go to Thread]({thread.jump_url})", inline=False)
    embeds.append(embed_2)
    
    try:
        await thread.owner.send(embeds=embeds)
    except discord.Forbidden:
        pass
        
async def notify_user_reaction_removal(user, emoji, message, server_config):
    """Notify user about removed reaction."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(emoji, message.channel, user, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(emoji, message.channel, user, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(emoji, message.channel, user, server_config))
                    
    embeds = []
    
    embed_1 = discord.Embed(title=f"{message.guild.name} Discord Server Content Filter Notification", color=discord.Color.yellow())
    value = server_config.get("dm_notifications", "Your reaction was filtered because it contains blacklisted content.")
    punishments = server_config.get("punishments")
    max_violations = punishments.get("max_violations")
    time_window = punishments.get("time_window")
    punishment_duration = punishments.get("punishment_duration")
    time_window_str = await format_timedelta(time_window)
    punishment_duration_str = await format_timedelta(punishment_duration)
    value = value.format(
        max_violations=max_violations,
        time_window=time_window_str,
        punishment_duration=punishment_duration_str
    )
    embed_1.add_field(name="", value=value, inline=False)
    embeds.append(embed_1)
    
    embed_2 = discord.Embed(title="Reaction Removed", color=discord.Color.yellow(), timestamp=datetime.now(timezone.utc))
    embed_2.add_field(name="Your Removed Reaction", value=spoilered_content, inline=False)
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed_2.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed_2.add_field(name="Blocked Terms", 
                       value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
                       inline=False)
    embed_2.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed_2.add_field(name="Message Link", value=f"[Go to Message]({message.jump_url})", inline=False)
    embeds.append(embed_2)
    
    try:
        await user.send(embeds=embeds)
    except discord.Forbidden:
        pass

async def notify_user_display_name(member, censored_display_name, server_config):
    """Notify user about display name censorship."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(member.display_name, None, member, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(member.display_name, None, member, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))
        
    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(member.display_name, None, member, server_config))

    embeds = []
    
    embed_1 = discord.Embed(title=f"{member.guild.name} Discord Server Content Filter Notification", color=discord.Color.purple())
    value = server_config.get("dm_notifications", "Your display name was filtered because it contains blacklisted content.")
    punishments = server_config.get("punishments")
    max_violations = punishments.get("max_violations")
    time_window = punishments.get("time_window")
    punishment_duration = punishments.get("punishment_duration")
    time_window_str = await format_timedelta(time_window)
    punishment_duration_str = await format_timedelta(punishment_duration)
    value = value.format(
        max_violations=max_violations,
        time_window=time_window_str,
        punishment_duration=punishment_duration_str
    )
    embed_1.add_field(name="", value=value, inline=False)
    embeds.append(embed_1)
    
    embed_2 = discord.Embed(title="Display Name Censored", color=discord.Color.purple(), timestamp=datetime.now(timezone.utc))
    embed_2.add_field(name="Your Display Name With Blocked Terms Hidden",
                   value=spoilered_content or "No content", inline=False)
    embed_2.add_field(name="Censored Display Name",
                   value=censored_display_name or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed_2.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed_2.add_field(name="Blocked Terms",
                       value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
                       inline=False)
    embeds.append(embed_2)
    
    try:
        await member.send(embeds=embeds)
    except discord.Forbidden:
        pass

async def notify_user_scan_deletion(message: discord.Message, censored_message: str, server_config: dict):
    """Notify user about message deletion from channel scan."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(message.content, message.channel, message.author, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(message.content, message.channel, message.author, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))
    
    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(message.content, message.channel, message.author, server_config))
    
    embeds = []
    
    embed_1 = discord.Embed(title=f"{message.guild.name} Discord Server Content Filter Notification", color=discord.Color.red())
    value = server_config.get("dm_notifications", "Your message was removed because it contains blacklisted content.")
    punishments = server_config.get("punishments")
    max_violations = punishments.get("max_violations")
    time_window = punishments.get("time_window")
    punishment_duration = punishments.get("punishment_duration")
    time_window_str = await format_timedelta(time_window)
    punishment_duration_str = await format_timedelta(punishment_duration)
    value = value.format(
        max_violations=max_violations,
        time_window=time_window_str,
        punishment_duration=punishment_duration_str
    )
    embed_1.add_field(name="", value=value, inline=False)
    embeds.append(embed_1)
    
    embed_2 = discord.Embed(title="Message Deleted Via Channel Scan", color=discord.Color.red(), timestamp=datetime.now(timezone.utc))

    if len(spoilered_content) > 1024:
        embed_2.add_field(name="Your Message With Blocked Terms Hidden (Truncated)", value=spoilered_content[:1024], inline=False)
        embed_3 = discord.Embed(title=f"Your Message With Blocked Terms Hidden (Full)", description=spoilered_content, color=discord.Color.red())
    else:
        embed_2.add_field(name="Your Message With Blocked Terms Hidden", value=spoilered_content or "No content", inline=False)

    if len(censored_message) > 1024:
        embed_2.add_field(name="Censored Message (Truncated)", value=censored_message[:1024],inline=False)
        embed_4 = discord.Embed(title=f"Censored Message (Full)", description=censored_message, color=discord.Color.red())
    else:
        embed_2.add_field(name="Censored Message", value=censored_message or "No content", inline=False)
        
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed_2.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed_2.add_field(name="Blocked Terms", 
                       value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
                       inline=False)
                       
    embed_2.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed_2.add_field(name="Message Link", value=f"[Go to Message]({message.jump_url})", inline=False)
    embeds.append(embed_2)
    
    try:
        await message.author.send(embeds=embeds)
        if len(spoilered_content) > 1024:
            await message.author.send(embed=embed_3)
        if len(censored_message) > 1024:
            await message.author.send(embed=embed_4)
    except discord.Forbidden:
        pass

# Logging Functions
async def log_censored_message(message, censored_message, reposted_message, server_config):
    """Log censored messages with detailed information."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(message.content, message.channel, message.author, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(message.content, message.channel, message.author, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(message.content, message.channel, message.author, server_config))

    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        return

    log_channel = message.guild.get_channel_or_thread(log_channel_id)
    if not log_channel:
        return
    
    embed_1 = discord.Embed(title="Message Censored", color=discord.Color.red(), timestamp=datetime.now(timezone.utc))
    embed_1.add_field(name="User", value=message.author.mention, inline=False)
 
    if len(spoilered_content) > 1024:
        embed_1.add_field(name="Original Message (Truncated)", value=spoilered_content[:1024], inline=False)
        embed_2 = discord.Embed(title=f"Original Message (Full)", description=spoilered_content, color=discord.Color.red())
    else:
        embed_1.add_field(name="Original Message", value=spoilered_content or "No content", inline=False)
    if len(censored_message) > 1024:
        embed_1.add_field(name="Censored Message (Truncated)", value=censored_message[:1024],inline=False)
        embed_3 = discord.Embed(title=f"Censored Message (Full)", description=censored_message, color=discord.Color.red())
    else:
        embed_1.add_field(name="Censored Message", value=censored_message or "No content", inline=False)
        
    if triggered_blacklists:
        blacklist_details = "\n".join([
            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
            for name, terms in triggered_blacklists
        ])
        embed_1.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed_1.add_field(
            name="Blocked Terms",
            value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
            inline=False
        )
        
    embed_1.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed_1.add_field(name="Message Link", value=f"[Go to Message]({reposted_message.jump_url})", inline=False)
    
    await log_channel.send(embed=embed_1)
    if len(spoilered_content) > 1024:
        await log_channel.send(embed=embed_2)
    if len(censored_message) > 1024:
        await log_channel.send(embed=embed_3)

async def log_censored_thread_title(thread, censored_title, server_config):
    """Log thread title censorship."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(thread.name, thread, thread.owner, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(thread.name, thread, thread.owner, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(thread.name, thread, thread.owner, server_config))

    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        return

    log_channel = thread.guild.get_channel_or_thread(log_channel_id)
    if not log_channel:
        return

    embed = discord.Embed(title="Thread Title Censored", color=discord.Color.orange(), timestamp=datetime.now(timezone.utc))
    embed.add_field(name="User", value=thread.owner.mention, inline=False)
    embed.add_field(name="Original Title", value=spoilered_content[:1024] or "No content", inline=False)
    embed.add_field(name="Censored Title", value=censored_title[:1024] or "No content", inline=False)

    if triggered_blacklists:
        blacklist_details = "\n".join([
            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
            for name, terms in triggered_blacklists
        ])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed.add_field(
            name="Blocked Terms",
            value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
            inline=False
        )

    embed.add_field(name="Channel", value=thread.parent.mention, inline=False)
    embed.add_field(name="Thread Link", value=f"[Go to Thread]({thread.jump_url})", inline=False)
    await log_channel.send(embed=embed)
    
async def log_removed_reaction(user, emoji, message, server_config):
    """Log removed reactions."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(emoji, message.channel, user, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(emoji, message.channel, user, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(emoji, message.channel, user, server_config))

    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        return

    log_channel = message.guild.get_channel_or_thread(log_channel_id)
    if not log_channel:
        return

    embed = discord.Embed(title="Reaction Removed", color=discord.Color.yellow(),timestamp=datetime.now(timezone.utc))
    embed.add_field(name="User", value=user.mention, inline=False)
    embed.add_field(name="Removed Reaction", value=spoilered_content, inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed.add_field(name="Blocked Terms",
                       value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
                       inline=False)
                       
    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed.add_field(name="Message Link", value=f"[Go to Message]({message.jump_url})", inline=False)
    await log_channel.send(embed=embed)

async def log_censored_display_name(member, censored_display_name, server_config):
    """Log display name censorship."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(member.display_name, None, member, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(member.display_name, None, member, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(member.display_name, None, member, server_config))

    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        return

    log_channel = member.guild.get_channel_or_thread(log_channel_id)
    if not log_channel:
        return

    embed = discord.Embed(title="Display Name Censored", color=discord.Color.purple(), timestamp=datetime.now(timezone.utc))
    embed.add_field(name="User", value=member.mention, inline=False)
    embed.add_field(name="Original Display Name", value=spoilered_content or "No content", inline=False)
    embed.add_field(name="Censored Display Name", value=censored_display_name or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([
            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
            for name, terms in triggered_blacklists
        ])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed.add_field(
            name="Blocked Terms",
            value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
            inline=False
        )

    embed.add_field(name="User Link", value=f"[Go to User](https://discord.com/users/{member.id})", inline=False)
    await log_channel.send(embed=embed)

async def log_scan_deletion(message: discord.Message, censored_message: str, server_config: dict):
    """Log message deletions from channel scans."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(message.content, message.channel, message.author, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(message.content, message.channel, message.author, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(message.content, message.channel, message.author, server_config))

    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        return

    log_channel = message.guild.get_channel_or_thread(log_channel_id)
    if not log_channel:
        return
    
    embed_1 = discord.Embed(title="Message Deleted via Channel Scan", color=discord.Color.red(), timestamp=datetime.now(timezone.utc))
    embed_1.add_field(name="User", value=message.author.mention, inline=False)   
    
    if len(spoilered_content) > 1024:
        embed_1.add_field(name="Original Message (Truncated)", value=spoilered_content[:1024], inline=False)
        embed_2 = discord.Embed(title=f"Original Message (Full)", description=spoilered_content, color=discord.Color.red())
    else:
        embed_1.add_field(name="Original Message", value=spoilered_content or "No content", inline=False)
    if len(censored_message) > 1024:
        embed_1.add_field(name="Censored Message (Truncated)", value=censored_message[:1024],inline=False)
        embed_3 = discord.Embed(title=f"Censored Message (Full)", description=censored_message, color=discord.Color.red())
    else:
        embed_1.add_field(name="Censored Message", value=censored_message or "No content", inline=False)
        
    if triggered_blacklists:
        blacklist_details = "\n".join([
            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
            for name, terms in triggered_blacklists
        ])
        embed_1.add_field(name="Triggered Blacklists", value=blacklist_details[:1024], inline=False)
    else:
        embed_1.add_field(
            name="Blocked Terms",
            value=", ".join(f'`{term}`' for term in blocked_terms)[:1024] if blocked_terms else "No specific terms matched",
            inline=False
        )
        
    embed_1.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed_1.add_field(name="Message Link", value=f"[Go to Message]({message.jump_url})", inline=False)
    
    await log_channel.send(embed=embed_1)
    if len(spoilered_content) > 1024:
        await log_channel.send(embed=embed_2)
    if len(censored_message) > 1024:
        await log_channel.send(embed=embed_3)
    
# Punishment System Functions
async def check_and_apply_punishment(user: discord.Member, guild_id: int, server_config: dict):
    """Check violations and apply punishment if threshold exceeded."""
    current_time = datetime.now(timezone.utc)
    time_window = server_config["punishments"]["time_window"]

    recent_violations = await get_recent_violations(guild_id, user.id, time_window)
    await add_user_violation(guild_id, user.id)
    recent_violations.append(current_time.isoformat())

    if len(recent_violations) >= server_config["punishments"]["max_violations"]:
        role_id = server_config["punishments"]["punishment_role"]
        punishment_duration = server_config["punishments"]["punishment_duration"]

        if role_id:
            role = user.guild.get_role(role_id)
            if role:
                if role in user.roles:
                    return
                try:
                    await user.add_roles(role, reason="Repeated violations of the server's content rules.")
                except discord.Forbidden:
                    return
                except discord.HTTPException as e:
                    return

                expiration_time = current_time + punishment_duration
                try:
                    await add_punishment(guild_id, user.id, role_id, expiration_time)
                except aiosqlite.IntegrityError:
                    return
                
                embeds = []
                embed_punish_1 = discord.Embed(title=f"{user.guild.name} Discord Server Content Filter Notification", description ="You have received a temporary role due to repeated violations of the server's content rules.", color=discord.Color.dark_red())
                embed_punish_2 = discord.Embed(title="Punishment Applied", color=discord.Color.dark_red(), timestamp=current_time)
                embed_punish_2.add_field(name="Punishment", value=f"Temporary role: `{role.name}`", inline=False)
                embed_punish_2.add_field(name="Duration", value=str(punishment_duration), inline=False)
                embed_punish_2.add_field(name="Punishment Expires At", value=f"<t:{int(expiration_time.timestamp())}:R>", inline=False)
                embed_punish_2.add_field(name="Reason", value="Repeated violations of the server's content rules.", inline=False)
                embeds.append(embed_punish_1)
                embeds.append(embed_punish_2)
                
                try:
                    await user.send(embeds=embeds)
                except discord.Forbidden:
                    pass

                log_channel_id = server_config.get("log_channel_id")
                if log_channel_id:
                    log_channel = user.guild.get_channel_or_thread(log_channel_id)
                    if log_channel:
                        embed_log = discord.Embed(title="Punishment Applied", color=discord.Color.dark_red(), timestamp=current_time)
                        embed_log.add_field(name="User", value=user.mention, inline=False)
                        embed_log.add_field(name="Punishment Role", value=f"`{role.name}`", inline=False)
                        embed_log.add_field(name="Duration", value=str(punishment_duration), inline=False)
                        embed_log.add_field(name="Punishment Expires At", value=f"<t:{int(expiration_time.timestamp())}:R>", inline=False)
                        embed_log.add_field(name="Reason", value="Repeated violations of the server's content rules.", inline=False)
                        await log_channel.send(embed=embed_log)

                await clear_user_violations(guild_id, user.id)

# User Management Functions
async def filter_display_name(member):
    """Filter member display names."""
    server_config = await load_server_config(member.guild.id)
    if server_config["display_name_filter_enabled"]:
        censored_display_name = await censor_content(member.display_name, None, member, server_config)
        if censored_display_name != member.display_name:
            try:
                await log_censored_display_name(member, censored_display_name, server_config)
                await notify_user_display_name(member, censored_display_name, server_config)
                await check_and_apply_punishment(member, member.guild.id, server_config)
                await member.edit(nick=censored_display_name.replace("\\",""))
            except discord.Forbidden:
                pass

# Event Handlers
@bot.event
async def on_ready():
    """Handle bot startup."""
    print(f"{bot.user} has connected to Discord!")
    await initialize_database()
    await load_character_map()
    
    asyncio.create_task(punishment_checker())
    print("Punishment checker started.")
    
    asyncio.create_task(prune_deleted_messages())
    print("Deleted message pruner started.")
    
    asyncio.create_task(message_deletion_worker())
    print("Message deletion worker started.")
    
    asyncio.create_task(reaction_removal_worker())
    print("Reaction removal worker started.")
    
    for guild in bot.guilds:
        server_config = await load_server_config(guild.id)
        print(f"Loaded server config file for '{guild.name}' ({guild.id}).")
        
        blacklists = server_config.get("blacklists", {})
        all_blacklist_terms = [term for terms in blacklists.values() for term in terms]       
        for term in all_blacklist_terms:
            pattern = await get_blacklist_pattern(term)      
        whitelists = server_config.get("whitelists", {})
        all_whitelist_terms = [term for terms in whitelists.values() for term in terms]
        for term in all_whitelist_terms:
            await get_whitelist_pattern(term)
        print(f"Loaded server regex cache for '{guild.name}' ({guild.id}).")
    try:
        await bot.tree.sync()
        print("Commands synced globally.")
    except Exception as e:
        print(f"Failed to sync commands: {e}")

@bot.event
async def on_message(message):
    """Handle message creation."""
    if message.author == bot.user or not message.guild:
        return
        
    server_config = await load_server_config(message.guild.id)
    if isinstance(message.channel, (discord.TextChannel, discord.ForumChannel, discord.Thread, discord.VoiceChannel, discord.StageChannel)):
        censored_message_content = await censor_content(message.content, message.channel, message.author, server_config)
        if censored_message_content != message.content:
            await message_deletion_queue.put(message) 
            reposted_message = await repost_as_user(message, censored_message_content)
            await log_censored_message(message, censored_message_content, reposted_message, server_config)
            await notify_user_message(message, censored_message_content, reposted_message, server_config)
            await check_and_apply_punishment(message.author, message.guild.id, server_config)
            return

    await bot.process_commands(message)

@bot.event
async def on_raw_message_edit(payload):
    """Handle message edits."""
    channel = bot.get_channel(payload.channel_id)
    if not isinstance(channel, (discord.TextChannel, discord.ForumChannel, discord.Thread, discord.VoiceChannel, discord.StageChannel)):
        return    
    try:
        message = await channel.fetch_message(payload.message_id)
    except discord.NotFound:
        return     
    if message.author == bot.user or not message.guild:
        return
        
    server_config = await load_server_config(message.guild.id)
    censored_message_content = await censor_content(message.content, channel, message.author, server_config)
    if censored_message_content != message.content:
        await message_deletion_queue.put(message) 
        reposted_message = await repost_as_user(message, censored_message_content)
        await log_censored_message(message, censored_message_content, reposted_message, server_config)
        await notify_user_message(message, censored_message_content, reposted_message, server_config)
        await check_and_apply_punishment(message.author, message.guild.id, server_config)

@bot.event
async def on_thread_create(thread):
    """Handle thread creation."""
    server_config = await load_server_config(thread.guild.id)
    censored_title = await censor_content(thread.name, thread, thread.owner, server_config)
    
    if censored_title != thread.name:
        try:
            if thread.owner:
                await notify_user_thread_title(thread, censored_title, server_config)
            await log_censored_thread_title(thread, censored_title, server_config)
            await thread.edit(name=censored_title.replace("\\",""))
            await check_and_apply_punishment(thread.owner, thread.guild.id, server_config)
        except (discord.Forbidden, discord.HTTPException) as e:
            print(f"Error editing thread title: {e}")

@bot.event
async def on_raw_thread_update(payload):
    """Handle raw thread updates."""
    guild = bot.get_guild(payload.guild_id)
    if not guild:
        return
    try:
        thread = await guild.fetch_channel(payload.thread_id)
    except discord.NotFound:
        print(f"Thread with ID {payload.thread_id} not found.")
        return

    server_config = await load_server_config(thread.guild.id)
    censored_title = await censor_content(thread.name, thread, thread.owner, server_config)
    if censored_title != thread.name:
        try:
            if thread.owner:
                await notify_user_thread_title(thread, censored_title, server_config)
            await log_censored_thread_title(thread, censored_title, server_config)
            await thread.edit(name=censored_title.replace("\\", ""))
            await check_and_apply_punishment(thread.owner, thread.guild.id, server_config)
        except (discord.Forbidden, discord.HTTPException) as e:
            print(f"Error editing thread title: {e}")
    
@bot.event
async def on_raw_reaction_add(payload):
    """Handle reaction addition."""
    if payload.user_id == bot.user.id:
        return
    guild = bot.get_guild(payload.guild_id)
    if not guild:
        return     
    user = guild.get_member(payload.user_id)
    if not user:
        return
    channel = bot.get_channel(payload.channel_id)
    if not channel:
        return
    try:
        message = await channel.fetch_message(payload.message_id)
    except discord.NotFound:
        return
    emoji = payload.emoji
    reaction = discord.Reaction(message=message,data={'count': None, 'me': None, 'emoji': emoji}, emoji=emoji)
    
    server_config = await load_server_config(message.guild.id)
    censored_emoji = await censor_content(str(reaction.emoji), message.channel, user, server_config)
    if censored_emoji != str(reaction.emoji):
        await log_removed_reaction(user, str(reaction.emoji), reaction.message, server_config)
        await notify_user_reaction_removal(user, str(reaction.emoji), reaction.message, server_config)
        await check_and_apply_punishment(user, reaction.message.guild.id, server_config)
        await reaction_removal_queue.put((reaction, user))
        return

@bot.event
async def on_member_join(member):
    """Handle member joins."""
    await filter_display_name(member)

@bot.event
async def on_member_update(before, after):
    """Handle member updates."""
    if after.display_name != before.display_name:
        await filter_display_name(after)

# Background Tasks
async def punishment_checker():
    """Background task to check and remove expired punishments."""
    await bot.wait_until_ready()
    while not bot.is_closed():
        try:
            expired_punishments = await get_expired_punishments()
            for punishment in expired_punishments:
                guild_id, user_id, role_id = punishment
                guild = bot.get_guild(guild_id)
                
                if guild:
                    member = guild.get_member(user_id)
                    role = guild.get_role(role_id)
                    
                    if member and role:
                        try:
                            await member.remove_roles(role, reason="Punishment duration has expired.")
                            try:
                                embeds = []
                                embed_lift_1 = discord.Embed(title=f"{guild.name} Discord Server Content Filter Notification", description ="Your punishment role has been lifted. Please adhere to the server rules to avoid future punishments.", color=discord.Color.green())
                                embed_lift_2 = discord.Embed(title="Punishment Lifted", color=discord.Color.green(), timestamp=datetime.now(timezone.utc))
                                embed_lift_2.add_field(name="Punishment Role", value=f"`{role.name}`", inline=False)
                                embed_lift_2.add_field(name="Punishment Lifted At", value=f"<t:{int(datetime.now(timezone.utc).timestamp())}:R>", inline=False)
                                embed_lift_2.add_field(name="Reason", value="Punishment duration has expired.", inline=False)
                                embeds.append(embed_lift_1)
                                embeds.append(embed_lift_2)
                                await member.send(embeds=embeds)
                            except discord.Forbidden:
                                print(f"Unable to send DM to {member.display_name} ({member.id}).")

                            server_config = await load_server_config(guild_id)
                            log_channel_id = server_config["log_channel_id"]
                            if log_channel_id:
                                log_channel = guild.get_channel_or_thread(log_channel_id)
                                if log_channel:
                                    embed_lift = discord.Embed(title="Punishment Lifted", color=discord.Color.green(), timestamp=datetime.now(timezone.utc))
                                    embed_lift.add_field(name="User", value=member.mention, inline=False)
                                    embed_lift.add_field(name="Punishment Role", value=f"`{role.name}`", inline=False)
                                    embed_lift.add_field(name="Punishment Lifted At", value=f"<t:{int(datetime.now(timezone.utc).timestamp())}:R>", inline=False)
                                    embed_lift.add_field(name="Punishment Lifted By", value=f"{bot.user.mention}", inline=False)
                                    embed_lift.add_field(name="Reason", value="Punishment duration has expired.", inline=False)
                                    await log_channel.send(embed=embed_lift)
                        except discord.Forbidden:
                            print(f"Failed to remove role {role_id} from user {user_id}. Insufficient permissions.")
                        except discord.HTTPException as e:
                            print(f"HTTPException while removing role {role_id} from user {user_id}: {e}")
                        except Exception as e:
                            print(f"Failed to remove role {role_id} from user {user_id}: {e}")
                await remove_punishment(guild_id, user_id, role_id)
        except Exception as e:
            print(f"Error in punishment_checker: {e}")
        await asyncio.sleep(60)

async def prune_deleted_messages():
    """Remove records of deleted messages."""
    await bot.wait_until_ready()
    while not bot.is_closed():
        try:
            async with aiosqlite.connect(DATABASE_PATH) as db:
                async with db.execute("SELECT guild_id, message_id, webhook_id, webhook_token FROM censored_messages") as cursor:
                    async for row in cursor:
                        guild_id, message_id, webhook_id, webhook_token = row
                        try:
                            webhook = await bot.fetch_webhook(webhook_id)
                            await webhook.fetch_message(message_id)
                        except discord.NotFound:
                            await db.execute(
                                "DELETE FROM censored_messages WHERE guild_id = ? AND message_id = ?",
                                (guild_id, message_id)
                            )
                        except discord.HTTPException as e:
                            print(f"HTTPException checking message {message_id}: {e}")
                await db.commit()
        except Exception as e:
            print(f"Error in prune_deleted_messages: {e}")
        await asyncio.sleep(60)
        
async def message_deletion_worker():
    """Worker task to process message deletions."""
    while True:
        message = await message_deletion_queue.get()
        try:
            await message.delete()
            await asyncio.sleep(0.2)
        except discord.Forbidden:
            print(f"Failed to delete message in {message.channel}: Forbidden.")
        except discord.HTTPException as e:
            print(f"HTTPException during deletion: {e}")
        finally:
            message_deletion_queue.task_done()
            
async def reaction_removal_worker():
    """Worker task to process reaction removals."""
    while True:
        reaction, user = await reaction_removal_queue.get()
        try:
            await reaction.remove(user)
            await asyncio.sleep(0.2)
        except discord.Forbidden:
            print(f"Failed to remove reaction {reaction.emoji} in {reaction.message.channel}: Forbidden.")
        except discord.HTTPException as e:
            print(f"HTTPException during removal: {e}")
        finally:
            reaction_removal_queue.task_done()

# Modal Classes
class EditMessageModal(discord.ui.Modal, title="Edit Your Message"):
    def __init__(self, message, guild_id, webhook_id, webhook_token):
        super().__init__()
        default_content = (
            message.embeds[0].description
            if message.embeds and message.embeds[0].description
            else message.content
        )
        self.edited_message = discord.ui.TextInput(
            label="Edited Message Content",
            style=discord.TextStyle.paragraph,
            placeholder="Enter your edited message",
            required=True,
            custom_id="edited_message",
            max_length=4000,
            default=default_content,
        )
        self.add_item(self.edited_message)
        self.message = message
        self.guild_id = guild_id
        self.webhook_id = webhook_id
        self.webhook_token = webhook_token

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        original_content = (
            self.message.embeds[0].description
            if self.message.embeds and self.message.embeds[0].description
            else self.message.content
        )
        if original_content != self.edited_message.value:
            server_config = await load_server_config(self.guild_id)
            censored_message = await censor_content(self.edited_message.value, self.message.channel, interaction.user, server_config)
            try:
                webhook = await interaction.client.fetch_webhook(self.webhook_id)
                if len(censored_message) > 2000:
                    embed = discord.Embed(description=censored_message)
                    if isinstance(self.message.channel, discord.Thread):
                        await webhook.edit_message(self.message.id, content="", embed=embed, thread=self.message.channel)
                    else:
                        await webhook.edit_message(self.message.id, content="", embed=embed)
                else:
                    if isinstance(self.message.channel, discord.Thread):
                        await webhook.edit_message(self.message.id, content=censored_message, embed=None, thread=self.message.channel)
                    else:
                        await webhook.edit_message(self.message.id, content=censored_message, embed=None)

                if self.edited_message.value != censored_message:
                    spoilered_content = await apply_spoilers(self.edited_message.value, self.message.channel, interaction.user, server_config)
                    triggered_blacklists = []
                    for blacklist, terms in server_config.get("blacklists", {}).items():
                        blocked_terms = await get_blocked_terms(self.edited_message.value, self.message.channel, interaction.user, server_config, blacklist)
                        if blocked_terms:
                            triggered_blacklists.append((blacklist, blocked_terms))
                    blocked_terms = (
                        [term for _, terms in triggered_blacklists for term in terms]
                        if triggered_blacklists else
                        await get_blocked_terms(self.edited_message.value, self.message.channel, interaction.user, server_config)
                    )
                    embed = discord.Embed(title="Message Censored: Your Message With Blocked Terms Hidden", description=spoilered_content, color=discord.Color.red())
                    if triggered_blacklists:
                        blacklist_details = "\n".join(
                            [f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                             for name, terms in triggered_blacklists]
                        )
                        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
                    else:
                        embed.add_field(name="Blocked Terms", value=", ".join(f"`{term}`" for term in blocked_terms) if blocked_terms else "No specific terms matched", inline=False)
                    await interaction.followup.send(content="Your edited message was filtered because it contains blacklisted content.", embed=embed, ephemeral=True)
                else:
                    await interaction.followup.send("Your message has been successfully updated.", ephemeral=True)
            except discord.NotFound:
                await interaction.followup.send("Original message not found.", ephemeral=True)
            except discord.Forbidden:
                await interaction.followup.send("Cannot edit the message.", ephemeral=True)
            except discord.HTTPException as e:
                await interaction.followup.send(f"Failed to edit the message: {e}", ephemeral=True)

class TermRemovalApprovalModal(discord.ui.Modal):
    def __init__(self, guild_id, term, reporter_id, action, approver):
        super().__init__(title=f"Reason for {action.capitalize()}")
        self.guild_id = guild_id
        self.term = term
        self.reporter_id = reporter_id
        self.action = action
        self.approver = approver
        self.reason_input = discord.ui.TextInput(
            label='Reason',
            style=discord.TextStyle.paragraph,
            required=True,
            placeholder='Enter the reason here...'
        )
        self.add_item(self.reason_input)

    async def on_submit(self, interaction: discord.Interaction):
        reason = self.reason_input.value.strip()
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("""
                UPDATE term_removal_requests
                SET status = ?, reason = ?
                WHERE guild_id = ? AND term = ?
            """, (self.action, reason, self.guild_id, self.term))
            await db.commit()

        guild = interaction.guild
        reporter = guild.get_member(self.reporter_id)
        if reporter:
            try:
                embed = discord.Embed(
                    title=f"{guild.name} Discord Server Blacklist Request Follow-Up",
                    color=discord.Color.green() if self.action == 'approved' else discord.Color.red(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name='Term', value=f"`{self.term}`", inline=False)
                embed.add_field(name='Status', value=self.action.capitalize(), inline=False)
                embed.add_field(name='Reason', value=reason, inline=False)
                await reporter.send(embed=embed)
            except discord.Forbidden:
                pass

        server_config = await load_server_config(self.guild_id)
        log_channel_id = server_config.get("log_channel_id")
        if log_channel_id:
            log_channel = guild.get_channel_or_thread(log_channel_id)
            if log_channel:
                async with aiosqlite.connect(DATABASE_PATH) as db:
                    async with db.execute("""
                        SELECT message_id FROM term_removal_requests
                        WHERE guild_id = ? AND term = ?
                    """, (self.guild_id, self.term)) as cursor:
                        row = await cursor.fetchone()
                        if row:
                            message_id = row[0]
                            try:
                                message = await log_channel.fetch_message(message_id)
                                embed = message.embeds[0]
                                embed.color = discord.Color.green() if self.action == 'approved' else discord.Color.red()
                                embed.set_field_at(2, name='Status', value=self.action.capitalize(), inline=False)
                                embed.set_field_at(3, name='Reason', value=reason, inline=False)
                                embed.add_field(name='Reviewed By', value=self.approver.mention, inline=False)
                                await message.edit(embed=embed, view=None)
                            except discord.NotFound:
                                pass

        if self.action == 'approved':
            term_removed = False
            blacklists_modified = []
            for blacklist_name, terms in server_config["blacklists"].items():
                if self.term in terms:
                    terms.remove(self.term)
                    blacklists_modified.append(blacklist_name)
                    term_removed = True
            if term_removed:
                await save_server_config(self.guild_id, server_config)
                async with aiosqlite.connect(DATABASE_PATH) as db:
                    await db.execute("""
                        UPDATE term_removal_requests
                        SET blacklists_modified = ?
                        WHERE guild_id = ? AND term = ?
                    """, (json.dumps(blacklists_modified), self.guild_id, self.term))
                    await db.commit()

        await interaction.response.send_message(
            f"Term '{self.term}' has been {self.action}.",
            ephemeral=True
        )

# Selection View Classes

class BlacklistSelectView(discord.ui.View):
    """View for selecting a blacklist to edit."""
    def __init__(self, blacklists):
        super().__init__()
        sorted_blacklist_names = sorted(blacklists.keys(), key=lambda x: x.lower())
        options = [discord.SelectOption(label=bl_name, description=f"Edit the \"{bl_name}\" blacklist", emoji="📝") for bl_name in sorted_blacklist_names[:25]]
        self.add_item(BlacklistSelect(options))

class BlacklistSelect(discord.ui.Select):
    """Dropdown for selecting a blacklist."""
    def __init__(self, options):
        super().__init__(placeholder="Choose a blacklist to edit...", min_values=1, max_values=1, options=options, custom_id="blacklist_select")

    async def callback(self, interaction: discord.Interaction):
        selected_name = self.values[0]
        server_config = await load_server_config(interaction.guild.id)
        blacklists = server_config.get("blacklists", {})
        await show_blacklist_edit_modal(interaction, selected_name, blacklists)

class WhitelistSelectView(discord.ui.View):
    """View for selecting a whitelist to edit."""
    def __init__(self, whitelists):
        super().__init__()
        sorted_whitelist_names = sorted(whitelists.keys(), key=lambda x: x.lower())
        options = [
            discord.SelectOption(
                label=wl_name,
                description=f"Edit the \"{wl_name}\" whitelist",
                emoji="📝"
            )
            for wl_name in sorted_whitelist_names[:25]
        ]
        self.add_item(WhitelistSelect(options))

class WhitelistSelect(discord.ui.Select):
    """Dropdown for selecting a whitelist."""
    def __init__(self, options):
        super().__init__(placeholder="Choose a whitelist to edit...", min_values=1, max_values=1, options=options, custom_id="whitelist_select")

    async def callback(self, interaction: discord.Interaction):
        selected_name = self.values[0]
        server_config = await load_server_config(interaction.guild.id)
        whitelists = server_config.get("whitelists", {})
        await show_whitelist_edit_modal(interaction, selected_name, whitelists)

class TermRemovalApprovalView(discord.ui.View):
    '''Buttons for approving and disapproving term requests.'''
    def __init__(self, guild_id, term, reporter_id):
        super().__init__(timeout=None)
        self.guild_id = guild_id
        self.term = term
        self.reporter_id = reporter_id

    @discord.ui.button(label='Approve', style=discord.ButtonStyle.success)
    async def approve_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not (interaction.user.guild_permissions.administrator or await has_term_approver_role(interaction.user)):
            await interaction.response.send_message(
                "Only administrators or users with the term approver role can approve or disapprove term removal requests.",
                ephemeral=True
            )
            return
        # Show modal to enter reason for approval
        modal = TermRemovalApprovalModal(
            guild_id=self.guild_id,
            term=self.term,
            reporter_id=self.reporter_id,
            action='approved',
            approver=interaction.user
        )
        await interaction.response.send_modal(modal)

    @discord.ui.button(label='Disapprove', style=discord.ButtonStyle.danger)
    async def disapprove_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not (interaction.user.guild_permissions.administrator or await has_term_approver_role(interaction.user)):
            await interaction.response.send_message(
                "Only administrators or users with the term approver role can approve or disapprove term removal requests.",
                ephemeral=True
            )
            return
        # Show modal to enter reason for disapproval
        modal = TermRemovalApprovalModal(
            guild_id=self.guild_id,
            term=self.term,
            reporter_id=self.reporter_id,
            action='disapproved',
            approver=interaction.user
        )
        await interaction.response.send_modal(modal)

class TermRequestHistoryView(discord.ui.View):
    def __init__(self, user, requests):
        super().__init__(timeout=None)
        self.user = user
        self.requests = requests
        self.index = 0
        self.update_buttons()
    
    def update_buttons(self):
        self.first_page.disabled = self.index == 0
        self.previous_page.disabled = self.index == 0
        self.next_page.disabled = self.index >= len(self.requests) - 1
        self.last_page.disabled = self.index >= len(self.requests) - 1
        current_status = self.requests[self.index][2]
        self.revert_approval.disabled = current_status != 'approved'
        self.delete_request.disabled = False

    def current_embed(self):
        term, reporter_id, status, reason, timestamp, blacklists_modified = self.requests[self.index]
        embed = discord.Embed(
            title="Term Removal Request",
            color=discord.Color.green() if status == 'approved' else discord.Color.red() if status == 'disapproved' else discord.Color.blue(),
            timestamp=datetime.fromisoformat(timestamp)
        )
        embed.add_field(name="Term", value=f"`{term}`", inline=False)
        reporter = self.user.guild.get_member(reporter_id)
        embed.add_field(name="Requested By", value=reporter.mention if reporter else f"User ID {reporter_id}", inline=False)
        embed.add_field(name="Status", value=status.capitalize(), inline=False)
        embed.add_field(name="Reason", value=reason, inline=False)
        if blacklists_modified:
            blacklists = json.loads(blacklists_modified)
            embed.add_field(name="Blacklists Modified", value=", ".join(blacklists), inline=False)
        else:
            embed.add_field(name="Blacklists Modified", value="N/A", inline=False)
        embed.set_footer(text=f"Request {self.index + 1} of {len(self.requests)}")
        return embed

    @discord.ui.button(label='<<', style=discord.ButtonStyle.secondary)
    async def first_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.index = 0
        self.update_buttons()
        await interaction.response.edit_message(embed=self.current_embed(), view=self)
    
    @discord.ui.button(label='<', style=discord.ButtonStyle.secondary)
    async def previous_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.index = max(self.index - 1, 0)
        self.update_buttons()
        await interaction.response.edit_message(embed=self.current_embed(), view=self)
    
    @discord.ui.button(label='>', style=discord.ButtonStyle.secondary)
    async def next_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.index = min(self.index + 1, len(self.requests) - 1)
        self.update_buttons()
        await interaction.response.edit_message(embed=self.current_embed(), view=self)
    
    @discord.ui.button(label='>>', style=discord.ButtonStyle.secondary)
    async def last_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.index = len(self.requests) - 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.current_embed(), view=self)

    @discord.ui.button(label='Revert Approval', style=discord.ButtonStyle.danger)
    async def revert_approval(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Revert the approval
        term, reporter_id, status, reason, timestamp, blacklists_modified = self.requests[self.index]
        if status != 'approved':
            await interaction.response.send_message("Only approved terms can be reverted.", ephemeral=True)
            return
        blacklists = json.loads(blacklists_modified)
        # Re-add the term to the blacklists
        guild_id = interaction.guild.id
        server_config = await load_server_config(guild_id)
        for blacklist_name in blacklists:
            if blacklist_name in server_config["blacklists"]:
                server_config["blacklists"][blacklist_name].append(term)
        await save_server_config(guild_id, server_config)
        # Update the request status in the database
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("""
                UPDATE term_removal_requests
                SET status = 'reverted', reason = ?
                WHERE guild_id = ? AND term = ?
            """, (f'Approval reverted by {interaction.user}', guild_id, term))
            await db.commit()
        # Update the request in memory
        self.requests[self.index] = (term, reporter_id, 'reverted', f'Approval reverted by {interaction.user}', timestamp, blacklists_modified)
        self.update_buttons()
        await interaction.response.edit_message(embed=self.current_embed(), view=self)

    @discord.ui.button(label='Delete Request', style=discord.ButtonStyle.danger)
    async def delete_request(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Delete the request
        term, reporter_id, status, reason, timestamp, blacklists_modified = self.requests.pop(self.index)
        guild_id = interaction.guild.id
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("""
                DELETE FROM term_removal_requests
                WHERE guild_id = ? AND term = ?
            """, (guild_id, term))
            await db.commit()
        if self.index >= len(self.requests):
            self.index = len(self.requests) - 1
        if len(self.requests) == 0:
            await interaction.response.edit_message(content="No more term removal requests.", embed=None, view=None)
            return
        self.update_buttons()
        await interaction.response.edit_message(embed=self.current_embed(), view=self)

# Helper Functions
async def show_blacklist_edit_modal(interaction: discord.Interaction, name: str, blacklists: dict):
    """Show modal for editing a blacklist."""
    existing_terms = blacklists.get(name, [])
    default_value = '\n'.join(existing_terms)

    class BlacklistModal(discord.ui.Modal, title=f"Edit Blacklist: {name}"[:45]):
        blacklist_terms = discord.ui.TextInput(
            label="Blacklist Terms (Enter one term per line)",
            style=discord.TextStyle.paragraph,
            required=True,
            default=default_value,
            placeholder=(
                "Examples:\n"
                "- Exact word: badword\n"
                "- Regex: re:\\w*badword\\w*\n"
                "- URL: url:badsite.com"
            )
        )

        async def on_submit(modal_self, interaction: discord.Interaction):
            await interaction.response.defer(ephemeral=True)
            guild_id = interaction.guild.id
            server_config = await load_server_config(guild_id)
            terms = modal_self.blacklist_terms.value.splitlines()
            terms = [term.strip().lower() for term in terms if term.strip()]
            terms = sorted(list(set(terms)))

            server_config["blacklists"][name] = terms
            await save_server_config(guild_id, server_config)

            blacklist_details = (
                f"**{name}** has been updated with the following terms:\n"
                + ", ".join(f"`{term}`" for term in terms)
            ) if terms else f"**{name}** has been cleared of all terms."

            await send_long_message(interaction, blacklist_details)

        async def on_error(self, interaction: discord.Interaction, error: Exception):
            await interaction.response.send_message(
                "An error occurred while processing the modal submission.",
                ephemeral=True
            )

    await interaction.response.send_modal(BlacklistModal())

async def show_whitelist_edit_modal(interaction: discord.Interaction, name: str, whitelists: dict):
    """Show modal for editing a whitelist."""
    existing_terms = whitelists.get(name, [])
    default_value = '\n'.join(existing_terms)

    class WhitelistModal(discord.ui.Modal, title=f"Edit Whitelist: {name}"[:45]):
        whitelist_terms = discord.ui.TextInput(
            label="Whitelist Terms (Enter one term per line)",
            style=discord.TextStyle.paragraph,
            required=True,
            default=default_value,
            placeholder=(
                "Examples:\n"
                "- Exact word: goodword\n"
                "- Regex: re:\\w*goodw\\w* (allows any word containing goodw)"
            )
        )

        async def on_submit(modal_self, interaction: discord.Interaction):
            await interaction.response.defer(ephemeral=True)
            guild_id = interaction.guild.id
            server_config = await load_server_config(guild_id)
            terms = modal_self.whitelist_terms.value.splitlines()
            terms = [term.strip().lower() for term in terms if term.strip()]
            terms = sorted(list(set(terms)))

            server_config["whitelists"][name] = terms
            await save_server_config(guild_id, server_config)

            whitelist_details = (
                f"**{name}** has been updated with the following terms:\n"
                + ", ".join(f"`{term}`" for term in terms)
            ) if terms else f"**{name}** has been cleared of all terms."

            await send_long_message(interaction, whitelist_details)

        async def on_error(self, interaction: discord.Interaction, error: Exception):
            await interaction.response.send_message(
                "An error occurred while processing the modal submission.",
                ephemeral=True
            )

    await interaction.response.send_modal(WhitelistModal())

# Commands - General Settings
@bot.tree.command(name="view_configuration")
@is_admin()
async def view_configuration(interaction: discord.Interaction):
    """View the bot's filtering settings and related configuration."""
    guild_id = interaction.guild.id
    server_config = await load_server_config(guild_id)
    embed_1 = discord.Embed(title=f"{interaction.guild.name} Discord Server Content Filter Configuration", color=discord.Color.blue(), timestamp=datetime.now(timezone.utc))

    log_channel_id = server_config.get("log_channel_id")
    log_channel = interaction.guild.get_channel_or_thread(log_channel_id) if log_channel_id else None
    embed_1.add_field(
        name="Log Channel",
        value=(
            "Channel where logs are sent.\n"
            "**Currently:** {0}\n"
            "Use `/set_log_channel` to configure."
        ).format(log_channel.mention if log_channel else 'Not Set'),
        inline=False
    )
    
    replacement_string = server_config.get("replacement_string", False)
    replacement_string = escape_markdown(replacement_string)
    embed_1.add_field(
        name="Replacement String",
        value=(
            "String used for replacing censored content.\n"
            "**Currently:** `{0}`\n"
            "Use `/set_replacement_string` to configure."
        ).format(replacement_string if replacement_string else 'Not Set'),
        inline=False
    )

    display_name_filter_enabled = server_config.get("display_name_filter_enabled", False)
    embed_1.add_field(
        name="Display Name Filter",
        value=(
            "Filters member display names.\n"
            "**Currently:** {0}\n"
            "Use `/toggle_display_name_filter` to enable or disable."
        ).format('Enabled' if display_name_filter_enabled else 'Disabled'),
        inline=False
    )

    moderator_role_id = server_config.get("moderator_role_id")
    moderator_role = interaction.guild.get_role(moderator_role_id) if moderator_role_id else None
    embed_1.add_field(
        name="Moderator Role",
        value=(
            "Role with moderator permissions.\n"
            "**Currently:** {0}\n"
            "Use `/set_moderator_role` to configure."
        ).format(moderator_role.mention if moderator_role else 'Not Set'),
        inline=False
    )

    term_approver_role_id = server_config.get("term_approver_role_id")
    term_approver_role = interaction.guild.get_role(term_approver_role_id) if term_approver_role_id else None
    embed_1.add_field(
        name="Term Approver Role",
        value=(
            "Role that can approve term removals.\n"
            "**Currently:** {0}\n"
            "Use `/set_term_approver_role` to configure."
        ).format(term_approver_role.mention if term_approver_role else 'Not Set'),
        inline=False
    )

    punishments = server_config.get("punishments", {})
    punishment_role_id = punishments.get("punishment_role")
    punishment_role = interaction.guild.get_role(punishment_role_id) if punishment_role_id else None
    max_violations = punishments.get('max_violations')
    time_window = punishments.get('time_window')
    punishment_duration = punishments.get('punishment_duration')

    time_window_str = await format_timedelta(time_window) if time_window else 'Not Set'
    punishment_duration_str = await format_timedelta(punishment_duration) if punishment_duration else 'Not Set'

    punishment_settings = (
        f"Max Violations: {max_violations}\n"
        f"Time Window: {time_window_str}\n"
        f"Punishment Role: {punishment_role.mention if punishment_role else 'Not Set'}\n"
        f"Punishment Duration: {punishment_duration_str}\n"
        "Use `/set_punishment` to configure."
    )
    embed_1.add_field(
        name="Punishment Settings",
        value=punishment_settings,
        inline=False
    )

    embed_1.add_field(
        name="Blacklist Management",
        value=(
            "Manage blacklists to filter specific terms.\n"
            "Use the following commands to configure:\n"
            "- `/edit_blacklist`: Create/edit blacklists.\n"
            "- `/quick_add_blacklist`: Quick add terms.\n"
            "- `/delete_blacklist`: Remove blacklists.\n"
            "- `/list_blacklists`: View all blacklists."
        ),
        inline=False
    )

    embed_1.add_field(
        name="Whitelist Management",
        value=(
            "Manage whitelists to allow specific terms.\n"
            "Use the following commands to configure:\n"
            "- `/edit_whitelist`: Create/edit whitelists.\n"
            "- `/quick_add_whitelist`: Quick add terms.\n"
            "- `/delete_whitelist`: Remove whitelists.\n"
            "- `/list_whitelists`: View all whitelists."
        ),
        inline=False
    )
    
    embed_2 = discord.Embed(title=f"{interaction.guild.name} Discord Server Content Filter Configuration", color=discord.Color.blue(), timestamp=datetime.now(timezone.utc))

    global_exceptions = server_config.get("global_exceptions", {"categories": [], "channels": [], "roles": []})
    categories_list = []
    for category_id in global_exceptions.get("categories", []):
        category = interaction.guild.get_channel(category_id)
        if category:
            categories_list.append(category.name)
        else:
            categories_list.append(f"ID: {category_id}")

    channels_list = []
    for channel_id in global_exceptions.get("channels", []):
        channel = interaction.guild.get_channel_or_thread(channel_id)
        if channel:
            if isinstance(channel, discord.Thread):
                parent = channel.parent
                if parent:
                    channels_list.append(f"{parent.mention} → {channel.mention}")
                else:
                    channels_list.append(channel.mention)
            else:
                channels_list.append(channel.mention)
        else:
            channels_list.append(f"ID: {channel_id}")

    roles_list = []
    for role_id in global_exceptions.get("roles", []):
        role = interaction.guild.get_role(role_id)
        if role:
            roles_list.append(role.mention)
        else:
            roles_list.append(f"ID: {role_id}")

    global_exceptions_str = "Globally exempted categories, channels, and roles.\n**Currently:**\n"
    if categories_list:
        global_exceptions_str += "**Categories**: " + ", ".join(categories_list) + "\n"
    if channels_list:
        global_exceptions_str += "**Channels**: " + ", ".join(channels_list) + "\n"
    if roles_list:
        global_exceptions_str += "**Roles**: " + ", ".join(roles_list) + "\n"

    if not any(global_exceptions.values()):
        global_exceptions_str = "No global exceptions set."
    else:
        if len(global_exceptions_str) > 1024:
            global_exceptions_str = global_exceptions_str[:1021] + "..."

    embed_2.add_field(name="Global Exceptions", value=global_exceptions_str, inline=False)
    
    embed_2.add_field(name="",
        value=(
            "Use the following commands to configure:\n"
            "- `/add_global_category_exception`: Add category exceptions.\n"
            "- `/remove_global_category_exception`: Remove category exceptions.\n"
            "- `/add_global_channel_exception`: Add channel exceptions.\n"
            "- `/remove_global_channel_exception`: Remove channel exceptions.\n"
            "- `/add_global_role_exception`: Add role exceptions.\n"
            "- `/remove_global_role_exception`: Remove role exceptions.\n"
            "- `/list_global_exceptions`: View all global exceptions."
        ),
        inline=False
    )

    exceptions = server_config.get("exceptions", {"categories": {}, "channels": {}, "roles": {}})
    exceptions_str = "Exceptions per blacklist.\n**Currently:**\n"
    for exception_type in ["categories", "channels", "roles"]:
        exception_dict = exceptions.get(exception_type, {})
        if exception_dict:
            exception_entries = []
            for entity_id, blacklists in exception_dict.items():
                entity_name = "Unknown"
                if exception_type == "categories":
                    entity = interaction.guild.get_channel(int(entity_id))
                    entity_name = entity.name if entity else f"ID: {entity_id}"
                elif exception_type == "channels":
                    entity = interaction.guild.get_channel_or_thread(int(entity_id))
                    if entity:
                        if isinstance(entity, discord.Thread):
                            parent = entity.parent
                            entity_name = f"{parent.mention} → {entity.mention}" if parent else entity.mention
                        else:
                            entity_name = entity.mention
                    else:
                        entity_name = f"ID: {entity_id}"
                elif exception_type == "roles":
                    entity = interaction.guild.get_role(int(entity_id))
                    entity_name = entity.mention if entity else f"ID: {entity_id}"
                blacklists_str = ", ".join(blacklists)
                exception_entries.append(f"{entity_name} (Blacklists: {blacklists_str})")
            if exception_entries:
                exceptions_str += f"**{exception_type.capitalize()}**:\n" + "\n".join(exception_entries) + "\n"

    if not any(exceptions.values()):
        exceptions_str = "No exceptions set."
    else:
        if len(exceptions_str) > 1024:
            exceptions_str = exceptions_str[:1021] + "..."

    embed_2.add_field(name="Exceptions", value=exceptions_str, inline=False)
    
    embed_2.add_field(
        name="",
        value=(
            "Use the following commands to configure:\n"
            "- `/add_category_exception`: Add category exceptions.\n"
            "- `/remove_category_exception`: Remove category exceptions.\n"
            "- `/add_channel_exception`: Add channel exceptions.\n"
            "- `/remove_channel_exception`: Remove channel exceptions.\n"
            "- `/add_role_exception`: Add role exceptions.\n"
            "- `/remove_role_exception`: Remove role exceptions.\n"
            "- `/list_exceptions`: View all exceptions."
        ),
        inline=False
    )

    # Moderation Tools
    embed_2.add_field(
        name="Moderation Tools",
        value=(
            "Tools for moderation tasks.\n"
            "Use the following commands:\n"
            "- `/scan_last_messages`: Scan recent messages.\n"
            "- `/lift_punishment`: Remove punishments.\n"
            "- `/view_term_request_history`: View and manage term requests."
        ),
        inline=False
    )

    # User Commands
    embed_2.add_field(
        name="User Commands",
        value=(
            "Commands available to all users.\n"
            "- `/request_term_removal`: Request removal of a term from blacklists.\n"
            "- Context Menu Commands:\n"
            "  - **Edit Censored Message**: Edit a censored message.\n"
            "  - **Delete Censored Message**: Delete a censored message."
        ),
        inline=False
    )

    await interaction.response.send_message(embed=embed_1, ephemeral=True)
    await interaction.followup.send(embed=embed_2, ephemeral=True)

@bot.tree.command(name="set_moderator_role")
@is_admin()
async def set_moderator_role(interaction: discord.Interaction, role: discord.Role):
    """Set moderator role for the server."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["moderator_role_id"] = role.id
    await save_server_config(interaction.guild.id, server_config)
    await interaction.response.send_message(f"Moderator role set to {role.mention}.", ephemeral=True)

@bot.tree.command(name="set_term_approver_role")
@is_admin()
async def set_term_approver_role(interaction: discord.Interaction, role: discord.Role):
    """Set the term approver role for the server."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["term_approver_role_id"] = role.id
    await save_server_config(interaction.guild.id, server_config)
    await interaction.response.send_message(f"Term approver role set to {role.mention}.", ephemeral=True)

@bot.tree.command(name="set_log_channel")
@is_admin()
async def set_log_channel(interaction: discord.Interaction, channel: Union[discord.Thread, discord.abc.GuildChannel]):
    """Set a log channel for filtered content activity."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["log_channel_id"] = channel.id
    await save_server_config(interaction.guild.id, server_config)
    await interaction.response.send_message(f"Log channel set to {channel.mention}", ephemeral=True)

@bot.tree.command(name="set_replacement_string")
@is_admin()
async def set_replacement_string(interaction: discord.Interaction, replacement_string: str):
    """Set a replacement string for censored content."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["replacement_string"] = replacement_string
    await save_server_config(interaction.guild.id, server_config)
    await interaction.response.send_message(f"Replacement string set to {replacement_string}", ephemeral=True)

@bot.tree.command(name="set_dm_notification")
@is_admin()
async def set_dm_notification(interaction: discord.Interaction):
    """Set custom DM notification message using modal."""
    server_config = await load_server_config(interaction.guild.id)
    message_content = server_config["dm_notifications"]
    
    class SetDMNotificationModal(discord.ui.Modal, title="Set DM Notification"):
        def __init__(self, current_message):
            super().__init__()
            self.notification_message = discord.ui.TextInput(
                label="DM Notification Message",
                style=discord.TextStyle.paragraph,
                required=True,
                default=current_message,
                max_length=2000,
                placeholder="DM for censored content. Available tags: {max_violations}, {time_window}, {punishment_duration}."
            )
            self.add_item(self.notification_message)

        async def on_submit(self, interaction: discord.Interaction):
            server_config = await load_server_config(interaction.guild.id)
            server_config["dm_notifications"] = self.notification_message.value.strip()
            await save_server_config(interaction.guild.id, server_config)
            
            punishments = server_config.get("punishments")
            max_violations = punishments.get("max_violations")
            time_window = punishments.get("time_window")
            punishment_duration = punishments.get("punishment_duration")
            time_window_str = await format_timedelta(time_window)
            punishment_duration_str = await format_timedelta(punishment_duration)

            preview_message = self.notification_message.value.strip().format(
                max_violations=max_violations,
                time_window=time_window_str,
                punishment_duration=punishment_duration_str
            )
            await interaction.response.send_message("DM notification message set. Preview below:", embed=discord.Embed(description=preview_message), ephemeral=True)

    await interaction.response.send_modal(SetDMNotificationModal(message_content))
    
@bot.tree.command(name="toggle_display_name_filter")
@is_admin()
async def toggle_display_name_filter(interaction: discord.Interaction, enabled: bool):
    """Toggle display name filtering."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["display_name_filter_enabled"] = enabled
    await save_server_config(interaction.guild.id, server_config)
    status = "enabled" if enabled else "disabled"
    await interaction.response.send_message(f"Display name filtering {status}.", ephemeral=True)

# Commands - Punishment Management
@bot.tree.command(name="set_punishment")
@is_admin()
async def set_punishment(interaction: discord.Interaction, max_violations: int, 
                        time_window_minutes: int, punishment_role: discord.Role, 
                        duration_hours: int):
    """Configure punishment settings for repeat offenders."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["punishments"].update({
        "max_violations": max_violations,
        "time_window": timedelta(minutes=time_window_minutes),
        "punishment_role": punishment_role.id,
        "punishment_duration": timedelta(hours=duration_hours)
    })
    await save_server_config(interaction.guild.id, server_config)
    await interaction.response.send_message("Punishment settings updated.", ephemeral=True)

# Commands - Blacklist and Whitelist Management
@bot.tree.command(name="quick_add_blacklist")
@app_commands.describe(
    list_name="Name of the blacklist",
    term="Term to add"
)
@is_admin()
async def quick_add_blacklist(interaction: discord.Interaction, list_name: str, term: str):
    """Quickly add a term to existing blacklist."""
    guild_id = interaction.guild.id
    server_config = await load_server_config(guild_id)
    blacklists = server_config.get("blacklists", {})

    if list_name not in blacklists:
        await interaction.response.send_message(f"Blacklist **{list_name}** not found.", ephemeral=True)
        return

    if term in blacklists[list_name]:
        await interaction.response.send_message(f"Term `{term}` already exists.", ephemeral=True)
        return

    blacklists[list_name].append(term)
    blacklists[list_name] = sorted(set(term.lower() for term in blacklists[list_name]))
    await save_server_config(guild_id, server_config)
    await interaction.response.send_message(f"Added `{term}` to **{list_name}**", ephemeral=True)

@bot.tree.command(name="quick_add_whitelist")
@app_commands.describe(
    list_name="Name of the whitelist",
    term="Term to add"
)
@is_admin()
async def quick_add_whitelist(interaction: discord.Interaction, list_name: str, term: str):
    """Quickly add a term to existing whitelist."""
    guild_id = interaction.guild.id
    server_config = await load_server_config(guild_id)
    whitelists = server_config.get("whitelists", {})

    if list_name not in whitelists:
        await interaction.response.send_message(f"Whitelist **{list_name}** not found.", ephemeral=True)
        return

    if term in whitelists[list_name]:
        await interaction.response.send_message(f"Term `{term}` already exists.", ephemeral=True)
        return

    whitelists[list_name].append(term)
    whitelists[list_name] = sorted(set(term.lower() for term in whitelists[list_name]))
    await save_server_config(guild_id, server_config)
    await interaction.response.send_message(f"Added `{term}` to **{list_name}**", ephemeral=True)

@bot.tree.command(name="edit_blacklist")
@is_admin()
@app_commands.describe(name="Name of blacklist (optional)")
async def edit_blacklist(interaction: discord.Interaction, name: Optional[str] = None):
    """Edit a blacklist using a modal."""
    server_config = await load_server_config(interaction.guild.id)
    blacklists = server_config.get("blacklists", {})

    if name:
        await show_blacklist_edit_modal(interaction, name, blacklists)
    else:
        if not blacklists:
            await interaction.response.send_message("No blacklists exist.", ephemeral=True)
            return
        view = BlacklistSelectView(blacklists)
        await interaction.response.send_message("Select blacklist:", view=view, ephemeral=True)

@bot.tree.command(name="edit_whitelist")
@is_admin()
@app_commands.describe(name="Name of whitelist (optional)")
async def edit_whitelist(interaction: discord.Interaction, name: Optional[str] = None):
    """Edit a whitelist using a modal."""
    server_config = await load_server_config(interaction.guild.id)
    whitelists = server_config.get("whitelists", {})

    if name:
        await show_whitelist_edit_modal(interaction, name, whitelists)
    else:
        if not whitelists:
            await interaction.response.send_message("No whitelists exist.", ephemeral=True)
            return
        view = WhitelistSelectView(whitelists)
        await interaction.response.send_message("Select whitelist:", view=view, ephemeral=True)

@bot.tree.command(name="delete_blacklist")
@is_admin()
async def delete_blacklist(interaction: discord.Interaction, name: str):
    """Delete a blacklist."""
    server_config = await load_server_config(interaction.guild.id)
    if name in server_config["blacklists"]:
        del server_config["blacklists"][name]
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Deleted blacklist '{name}'.", ephemeral=True)
    else:
        await interaction.response.send_message(f"Blacklist '{name}' not found.", ephemeral=True)

@bot.tree.command(name="delete_whitelist")
@is_admin()
async def delete_whitelist(interaction: discord.Interaction, name: str):
    """Delete a whitelist."""
    server_config = await load_server_config(interaction.guild.id)
    if name in server_config["whitelists"]:
        del server_config["whitelists"][name]
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Deleted whitelist '{name}'.", ephemeral=True)
    else:
        await interaction.response.send_message(f"Whitelist '{name}' not found.", ephemeral=True)

# Commands - Exception Management
@bot.tree.command(name="add_category_exception")
@is_admin()
async def add_category_exception(interaction: discord.Interaction, category: discord.CategoryChannel, blacklist_name: str):
    """Add category exception to blacklist."""
    server_config = await load_server_config(interaction.guild.id)
    blacklists = server_config.get("blacklists", {})
    
    if blacklist_name not in blacklists:
        await interaction.response.send_message(f"The blacklist '{blacklist_name}' does not exist.", ephemeral=True)
        return

    exceptions = server_config.setdefault("exceptions", {"channels": {}, "categories": {}, "roles": {}})
    category_id = category.id

    if category_id not in exceptions["categories"]:
        exceptions["categories"][category_id] = []
    if blacklist_name not in exceptions["categories"][category_id]:
        exceptions["categories"][category_id].append(blacklist_name)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Added exception for category {category.name} to blacklist '{blacklist_name}'.", ephemeral=True)
    else:
        await interaction.response.send_message(f"Category {category.name} is already excepted from '{blacklist_name}'.", ephemeral=True)

@bot.tree.command(name="add_channel_exception")
@is_admin()
async def add_channel_exception(
    interaction: discord.Interaction,
    channel: Union[discord.TextChannel, discord.ForumChannel, discord.Thread, discord.VoiceChannel, discord.StageChannel],
    blacklist_name: str,
):
    """Add channel exception to blacklist."""
    server_config = await load_server_config(interaction.guild.id)
    blacklists = server_config.get("blacklists", {})

    if blacklist_name not in blacklists:
        await interaction.response.send_message(f"The blacklist '{blacklist_name}' does not exist.", ephemeral=True)
        return

    exceptions = server_config.setdefault("exceptions", {"channels": {}, "categories": {}, "roles": {}})
    channel_id = channel.id

    if channel_id not in exceptions["channels"]:
        exceptions["channels"][channel_id] = []
    if blacklist_name not in exceptions["channels"][channel_id]:
        exceptions["channels"][channel_id].append(blacklist_name)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(
            f"Added exception for {channel.mention} to blacklist '{blacklist_name}'."
        )
    else:
        await interaction.response.send_message(f"{channel.mention} is already excepted from '{blacklist_name}'.", ephemeral=True)

@bot.tree.command(name="add_role_exception")
@is_admin()
async def add_role_exception(interaction: discord.Interaction, role: discord.Role, blacklist_name: str):
    """Add role exception to blacklist."""
    server_config = await load_server_config(interaction.guild.id)
    blacklists = server_config.get("blacklists", {})

    if blacklist_name not in blacklists:
        await interaction.response.send_message(f"The blacklist '{blacklist_name}' does not exist.", ephemeral=True)
        return

    exceptions = server_config.setdefault("exceptions", {"channels": {}, "categories": {}, "roles": {}})
    role_id = role.id

    if role_id not in exceptions["roles"]:
        exceptions["roles"][role_id] = []
    if blacklist_name not in exceptions["roles"][role_id]:
        exceptions["roles"][role_id].append(blacklist_name)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Added exception for role {role.name} to blacklist '{blacklist_name}'.", ephemeral=True)
    else:
        await interaction.response.send_message(f"Role {role.name} is already excepted from '{blacklist_name}'.", ephemeral=True)

@bot.tree.command(name="remove_category_exception")
@is_admin()
async def remove_category_exception(
    interaction: discord.Interaction,
    category: Optional[discord.CategoryChannel],
    category_id: Optional[str],
    blacklist_name: str
):
    """Remove category exception from a specific blacklist."""
    server_config = await load_server_config(interaction.guild.id)

    if category:
        category_id = category.id
        category_name = category.name
    elif category_id:
        category_name = f"ID {category_id}"
        category_id = int(category_id)
    else:
        await interaction.response.send_message("Invalid input. Please provide a category or its ID.", ephemeral=True)
        return

    exceptions = server_config.get("exceptions", {}).get("categories", {})
    if category_id in exceptions and blacklist_name in exceptions[category_id]:
        exceptions[category_id].remove(blacklist_name)
        if not exceptions[category_id]:
            del exceptions[category_id]
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Removed {category_name} exception from '{blacklist_name}'.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{category_name} is not excepted from '{blacklist_name}'.", ephemeral=True)
        
@bot.tree.command(name="remove_channel_exception")
@is_admin()
async def remove_channel_exception(
    interaction: discord.Interaction,
    channel: Optional[Union[discord.TextChannel, discord.ForumChannel, discord.Thread, discord.VoiceChannel, discord.StageChannel]],
    channel_id: Optional[str],
    blacklist_name: str
):
    """Remove channel exception from a specific blacklist."""
    server_config = await load_server_config(interaction.guild.id)

    if channel:
        channel_id = channel.id
        channel_mention = channel.mention
    elif channel_id:
        channel_name = f"ID {channel_id}"
        channel_mention = channel_name
        channel_id = int(channel_id)
    else:
        await interaction.response.send_message("Invalid input. Please provide a channel or its ID.", ephemeral=True)
        return

    exceptions = server_config.get("exceptions", {}).get("channels", {})
    if channel_id in exceptions and blacklist_name in exceptions[channel_id]:
        exceptions[channel_id].remove(blacklist_name)
        if not exceptions[channel_id]:
            del exceptions[channel_id]
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Removed {channel_mention} exception from '{blacklist_name}'.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{channel_mention} is not excepted from '{blacklist_name}'.", ephemeral=True)
        
@bot.tree.command(name="remove_role_exception")
@is_admin()
async def remove_role_exception(
    interaction: discord.Interaction,
    role: Optional[discord.Role],
    role_id: Optional[str],
    blacklist_name: str
):
    """Remove role exception from a specific blacklist."""
    server_config = await load_server_config(interaction.guild.id)

    if role:
        role_id = role.id
        role_mention = role.mention
    elif role_id:
        role_name = f"ID {role_id}"
        role_mention = role_name
    else:
        await interaction.response.send_message("Invalid input. Please provide a role or its ID.", ephemeral=True)
        return

    exceptions = server_config.get("exceptions", {}).get("roles", {})
    if role_id in exceptions and blacklist_name in exceptions[role_id]:
        exceptions[role_id].remove(blacklist_name)
        if not exceptions[role_id]:
            del exceptions[role_id]
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Removed {role_mention} exception from '{blacklist_name}'.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{role_mention} is not excepted from '{blacklist_name}'.", ephemeral=True)

# Commands - Global Exception Management
@bot.tree.command(name="add_global_category_exception")
@is_admin()
async def add_global_category_exception(interaction: discord.Interaction, category: discord.CategoryChannel):
    """Add category to global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    global_exceptions = server_config.get("global_exceptions", {})
    if category.id not in global_exceptions["categories"]:
        global_exceptions["categories"].append(category.id)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Added {category.name} to global exceptions.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{category.name} already globally excepted.", ephemeral=True)

@bot.tree.command(name="add_global_channel_exception")
@is_admin()
async def add_global_channel_exception(interaction: discord.Interaction, 
    channel: Union[discord.TextChannel, discord.ForumChannel, discord.Thread, discord.VoiceChannel, discord.StageChannel]):
    """Add channel to global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    if channel.id not in server_config["global_exceptions"]["channels"]:
        server_config["global_exceptions"]["channels"].append(channel.id)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Added {channel.mention} to global exceptions.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{channel.mention} already globally excepted.", ephemeral=True)

@bot.tree.command(name="add_global_role_exception")
@is_admin()
async def add_global_role_exception(interaction: discord.Interaction, role: discord.Role):
    """Add role to global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    if role.id not in server_config["global_exceptions"]["roles"]:
        server_config["global_exceptions"]["roles"].append(role.id)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Added {role.name} to global exceptions.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{role.name} already globally excepted.", ephemeral=True)

@bot.tree.command(name="remove_global_category_exception")
@is_admin()
async def remove_global_category_exception(interaction: discord.Interaction, category: Optional[discord.CategoryChannel], category_id: Optional[str]):
    """Remove category from global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    if category:
        category_id = category.id
        category_name = category.name
    elif category_id:
        category_id = int(category_id)
        category_name = f"ID {category_id}"
    else:
        await interaction.response.send_message("Invalid input. Please provide a category or its ID.", ephemeral=True)
        return
    if category_id in server_config["global_exceptions"]["categories"]:
        server_config["global_exceptions"]["categories"].remove(category_id)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Removed {category_name} from global exceptions.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{category_name} not globally excepted.", ephemeral=True)

@bot.tree.command(name="remove_global_channel_exception")
@is_admin()
async def remove_global_channel_exception(interaction: discord.Interaction,
    channel: Optional[Union[discord.TextChannel, discord.ForumChannel, discord.Thread, discord.VoiceChannel, discord.StageChannel]],channel_id: Optional[str]):
    """Remove channel from global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    if channel:
        channel_id = channel.id
        channel_name = channel.name
        channel_mention = channel.mention
    elif channel_id:
        channel_id = int(channel_id)
        channel_name = f"ID {channel_id}"
        channel_mention = channel_name
    else:
        await interaction.response.send_message("Invalid input. Please provide a channel or its ID.", ephemeral=True)
        return
    if channel_id in server_config["global_exceptions"]["channels"]:
        server_config["global_exceptions"]["channels"].remove(channel_id)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Removed {channel_mention} from global exceptions.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{channel_mention} not globally excepted.", ephemeral=True)

@bot.tree.command(name="remove_global_role_exception")
@is_admin()
async def remove_global_role_exception(interaction: discord.Interaction, role: Optional[discord.Role], role_id: Optional[str]):
    """Remove role from global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    if role:
        role_id = role.id
        role_name = role.name
    elif role_id:
        role_id = int(role_id)
        role_name = f"ID {role_id}"
    else:
        await interaction.response.send_message("Invalid input. Please provide a role or its ID.", ephemeral=True)
        return
    if role_id in server_config["global_exceptions"]["roles"]:
        server_config["global_exceptions"]["roles"].remove(role_id)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Removed {role_name} from global exceptions.", ephemeral=True)
    else:
        await interaction.response.send_message(f"{role_name} not globally excepted.", ephemeral=True)

# Commands - List and Display
@bot.tree.command(name="list_blacklists")
@is_moderator()
async def list_blacklists(interaction: discord.Interaction):
    """List all blacklists and their terms."""
    await interaction.response.defer(ephemeral=True)
    server_config = await load_server_config(interaction.guild.id)
    if not server_config["blacklists"]:
        await interaction.followup.send("No blacklists found.", ephemeral=True)
        return
    blacklist_summary = "\n".join([
        f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
        for name, terms in server_config["blacklists"].items()
    ])
    await send_long_message(interaction, blacklist_summary)

@bot.tree.command(name="list_whitelists")
@is_moderator()
async def list_whitelists(interaction: discord.Interaction):
    """List all whitelists and their terms."""
    await interaction.response.defer(ephemeral=True)
    server_config = await load_server_config(interaction.guild.id)
    if not server_config["whitelists"]:
        await interaction.followup.send("No whitelists found.", ephemeral=True)
        return
    whitelist_summary = "\n".join([
        f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
        for name, terms in server_config["whitelists"].items()
    ])
    await send_long_message(interaction, whitelist_summary)

@bot.tree.command(name="list_exceptions")
@is_moderator()
async def list_exceptions(interaction: discord.Interaction):
    """List all exceptions for blacklists."""
    server_config = await load_server_config(interaction.guild.id)
    exceptions = server_config.get("exceptions", {})

    categories = [
        f"{interaction.guild.get_channel_or_thread(category_id).mention if interaction.guild.get_channel_or_thread(category_id)
        else f'ID: {category_id}'} - {', '.join(blacklist_names)}"
        for category_id, blacklist_names in exceptions.get("categories", {}).items()
    ]
    channels = [
        f"{interaction.guild.get_channel_or_thread(channel_id).mention if interaction.guild.get_channel_or_thread(channel_id)
        else f'ID: {channel_id}'} - {', '.join(blacklist_names)}"
        for channel_id, blacklist_names in exceptions.get("channels", {}).items()
    ]
    roles = [
        f"{interaction.guild.get_role(role_id).mention if interaction.guild.get_role(role_id)
        else f'ID: {role_id}'} - {', '.join(blacklist_names)}"
        for role_id, blacklist_names in exceptions.get("roles", {}).items()
    ]

    embed = discord.Embed(title="Exceptions", color=discord.Color.green(), timestamp=datetime.now(timezone.utc))
    embed.add_field(name="Categories", value="\n".join(categories) if categories else "None", inline=False)
    embed.add_field(name="Channels", value="\n".join(channels) if channels else "None", inline=False)
    embed.add_field(name="Roles", value="\n".join(roles) if roles else "None", inline=False)

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="list_global_exceptions")
@is_moderator()
async def list_global_exceptions(interaction: discord.Interaction):
    """List all global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    global_exceptions = server_config.get("global_exceptions", {})
    
    categories = [
        interaction.guild.get_channel_or_thread(category_id).mention if isinstance(interaction.guild.get_channel_or_thread(category_id), discord.CategoryChannel)
        else f"ID: {category_id}" 
        for category_id in global_exceptions.get("categories", [])
    ]
    channels = [
        interaction.guild.get_channel_or_thread(channel_id).mention if interaction.guild.get_channel_or_thread(channel_id) 
        else f"ID: {channel_id}" 
        for channel_id in global_exceptions.get("channels", [])
    ]
    roles = [
        interaction.guild.get_role(role_id).mention if interaction.guild.get_role(role_id)
        else f"ID: {role_id}" 
        for role_id in global_exceptions.get("roles", [])
    ]
    
    embed = discord.Embed(title="Global Exceptions", color=discord.Color.blue(), timestamp=datetime.now(timezone.utc))
    embed.add_field(name="Categories", value=", ".join(categories) if categories else "None", inline=False)
    embed.add_field(name="Channels", value=", ".join(channels) if channels else "None", inline=False)
    embed.add_field(name="Roles", value=", ".join(roles) if roles else "None", inline=False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# Commands - Moderation
@bot.tree.command(name="lift_punishment")
@is_moderator()
@app_commands.describe(
    member="The member to lift punishment from",
    reason="The reason for lifting the punishment"
)
async def lift_punishment(interaction: discord.Interaction, member: discord.Member, reason: Optional[str]):
    """Lift punishment from a member."""
    server_config = await load_server_config(interaction.guild.id)
    punishment_role_id = server_config["punishments"]["punishment_role"]
    
    if not punishment_role_id:
        await interaction.response.send_message("No punishment role configured.", ephemeral=True)
        return

    punishment_role = interaction.guild.get_role(punishment_role_id)
    if not punishment_role:
        await interaction.response.send_message("Punishment role not found.", ephemeral=True)
        return

    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("""
            SELECT guild_id, user_id, role_id FROM punishments
            WHERE guild_id = ? AND user_id = ? AND role_id = ?
        """, (interaction.guild.id, member.id, punishment_role_id)) as cursor:
            punishments = await cursor.fetchall()

    if not punishments:
        await interaction.response.send_message(f"{member.mention} has no active punishments.", ephemeral=True)
        return

    try:
        await member.remove_roles(punishment_role, reason=reason if reason is not None else "Punishment manually lifted.")
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.executemany("""
                DELETE FROM punishments
                WHERE guild_id = ? AND user_id = ? AND role_id = ?
            """, punishments)
            await db.commit()

        try:
            embeds = []
            embed_lift_1 = discord.Embed(title=f"{member.guild.name} Discord Server Content Filter Notification", description ="Your punishment role has been lifted by a staff member.", color=discord.Color.green())
            embed_lift_2 = discord.Embed(title="Punishment Lifted",color=discord.Color.green(),timestamp=datetime.now(timezone.utc))
            embed_lift_2.add_field(name="Punishment Role", value=f"`{punishment_role.name}`", inline=False)
            embed_lift_2.add_field(name="Punishment Lifted At", value=f"<t:{int(datetime.now(timezone.utc).timestamp())}:R>", inline=False)
            embed_lift_2.add_field(name="Reason", value=reason if reason is not None else "Punishment manually lifted.", inline=False)
            embeds.append(embed_lift_1)
            embeds.append(embed_lift_2)
            await member.send(embeds=embeds)
        except discord.Forbidden:
            pass

        log_channel_id = server_config.get("log_channel_id")
        if log_channel_id:
            log_channel = interaction.guild.get_channel_or_thread(log_channel_id)
            if log_channel:
                embed = discord.Embed(title="Punishment Lifted", color=discord.Color.green(), timestamp=datetime.now(timezone.utc))
                embed.add_field(name="User", value=member.mention, inline=False)
                embed.add_field(name="Punishment Role", value=f"`{punishment_role.name}`", inline=False)
                embed.add_field(name="Punishment Lifted At", value=f"<t:{int(datetime.now(timezone.utc).timestamp())}:R>", inline=False)
                embed.add_field(name="Punishment Lifted By", value=f"{interaction.user.mention}", inline=False)
                embed.add_field(name="Reason", value=reason if reason is not None else "Punishment manually lifted.", inline=False)
                await log_channel.send(embed=embed)

        await interaction.response.send_message(f"Punishment role removed from {member.mention}.", ephemeral=True)

    except discord.Forbidden:
        await interaction.response.send_message("Insufficient permissions to remove roles.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Error removing punishment: {e}", ephemeral=True)

@bot.tree.command(name="scan_last_messages")
@app_commands.describe(
    limit="The number of recent messages to scan (max 10000)."
)
@is_moderator()
async def scan_last_messages(interaction: discord.Interaction, limit: int):
    """Scan the last specified number of messages in the channel and delete those containing blacklisted content."""
    max_limit = 10000
    if limit < 1 or limit > max_limit:
        await interaction.response.send_message(f"Please provide a number between 1 and {max_limit}.", ephemeral=True)
        return

    server_config = await load_server_config(interaction.guild.id)
    channel = interaction.channel
    deleted_count = 0
    scanned_count = 0

    await interaction.response.defer(ephemeral=True)
    progress_message = await interaction.followup.send(f"Starting scan of {limit} messages. Progress: 0% (0/{limit} messages scanned).", ephemeral=True)

    try:
        async for message in channel.history(limit=limit):
            scanned_count += 1
            progress_percent = int((scanned_count / limit) * 100)
            
            if scanned_count % 10 == 0 or scanned_count == limit:
                await progress_message.edit(content=f"Scanning messages... Progress: {progress_percent}% ({scanned_count}/{limit} messages scanned).")

            if message.author == bot.user or message.author.bot:
                continue

            censored_message = await censor_content(message.content, message.channel, message.author, server_config)
            if message.content != censored_message:
                await message.delete()
                await log_scan_deletion(message, censored_message, server_config)
                await notify_user_scan_deletion(message, censored_message, server_config)
                await check_and_apply_punishment(message.author, message.guild.id, server_config)
                deleted_count += 1

    except discord.Forbidden:
        await interaction.followup.send("I do not have permission to delete messages.", ephemeral=True)
        return
    except discord.HTTPException as e:
        await interaction.followup.send(f"Failed to delete messages: {e}", ephemeral=True)
        return

    await progress_message.edit(
        content=f"Scan complete: {deleted_count} message(s) deleted out of {scanned_count} scanned."
    )

@bot.tree.command(name="view_term_request_history")
@is_term_approver()
async def view_term_request_history(interaction: discord.Interaction):
    """View and manage term removal requests history."""
    guild_id = interaction.guild.id
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("""
            SELECT term, reporter_id, status, reason, timestamp, blacklists_modified
            FROM term_removal_requests
            WHERE guild_id = ?
            ORDER BY timestamp DESC
        """, (guild_id,)) as cursor:
            requests = await cursor.fetchall()
    if not requests:
        await interaction.response.send_message("No term removal requests found.", ephemeral=True)
        return
    # Create the view and send the initial message
    view = TermRequestHistoryView(interaction.user, requests)
    await interaction.response.send_message(embed=view.current_embed(), view=view, ephemeral=True)

# User Commands
@bot.tree.command(name="request_term_removal")
@app_commands.describe(
    term="The term you are requesting to be removed. Must be exactly as shown in your DM."
)
async def request_term_removal(interaction: discord.Interaction, term: str):
    """Request removal of a term from the blacklists."""
    guild_id = interaction.guild.id
    user_id = interaction.user.id
    server_config = await load_server_config(guild_id)
    blacklists = server_config.get("blacklists", {})
    term = term.strip().lower()

    term_in_blacklist = any(term in terms for terms in blacklists.values())
    if not term_in_blacklist:
        await interaction.response.send_message(
            f"The term `{term}` is not currently in any blacklist. Please check the spelling and ensure you supply the `term` (__***not***__ necessarily the blocked word or phrase) exactly as shown in the DM notification.",
            ephemeral=True
        )
        return
        
    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        await interaction.response.send_message("Log channel is not configured. Please contact an administrator.", ephemeral=True)
        return

    log_channel = interaction.guild.get_channel_or_thread(log_channel_id)
    if not log_channel:
        await interaction.response.send_message("Log channel not found. Please contact an administrator.", ephemeral=True)
        return

    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("""
            SELECT status, reason FROM term_removal_requests
            WHERE guild_id = ? AND term = ?
        """, (guild_id, term)) as cursor:
            row = await cursor.fetchone()
            if row:
                status, reason = row
                if status == 'disapproved':
                    await interaction.response.send_message(f"Your request to remove `{term}` has been previously disapproved.\n\n**Reason:** {reason}",ephemeral=True)
                    return
                elif status == 'pending':
                    await interaction.response.send_message(f"A request to remove `{term}` is already pending.", ephemeral=True)
                    return
                elif status == 'approved':
                    await interaction.response.send_message(f"The term `{term}` has already been approved for removal.",ephemeral=True)
                    return

    current_time = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO term_removal_requests (guild_id, term, reporter_id, status, reason, timestamp)
            VALUES (?, ?, ?, 'pending', 'Pending', ?)
        """, (guild_id, term, user_id, current_time))
        await db.commit()

    term_approver_role_id = server_config.get("term_approver_role_id")
    moderator_role_id = server_config.get("moderator_role_id")

    if term_approver_role_id:
        term_approver_role = interaction.guild.get_role(term_approver_role_id)
        role_mention = term_approver_role.mention if term_approver_role else "@here"
    elif moderator_role_id:
        moderator_role = interaction.guild.get_role(moderator_role_id)
        role_mention = moderator_role.mention if moderator_role else "@here"
    else:
        role_mention = "@here"

    embed = discord.Embed(
        title="Term Removal Request",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Requested By", value=interaction.user.mention, inline=False)
    embed.add_field(name="Term", value=f"`{term}`", inline=False)
    embed.add_field(name="Status", value="Pending", inline=False)
    embed.add_field(name="Reason", value="Pending", inline=False)

    view = TermRemovalApprovalView(guild_id, term, user_id)

    message = await log_channel.send(content=f"{role_mention}, a new term removal request has been submitted.", embed=embed, view=view)

    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            UPDATE term_removal_requests
            SET message_id = ?
            WHERE guild_id = ? AND term = ?
        """, (message.id, guild_id, term))
        await db.commit()

    await interaction.response.send_message("Your term removal request has been submitted for review.", ephemeral=True)

# Context Menu Commands
@bot.tree.context_menu(name="Edit Censored Message")
async def edit_censored_message(interaction: discord.Interaction, message: discord.Message):
    """Context menu command for editing censored messages."""
    if not interaction.guild:
        await interaction.response.send_message("Server-only command.", ephemeral=True)
        return

    message_info = await get_censored_message_info(interaction.guild.id, message.id)
    if not message_info:
        await interaction.response.send_message("Cannot edit this message.", ephemeral=True)
        return

    if not (interaction.user.id == message_info["author_id"] or is_moderator()):
        await interaction.response.send_message("Unauthorized to edit.", ephemeral=True)
        return

    modal = EditMessageModal(message, interaction.guild.id, message_info["webhook_id"], message_info["webhook_token"])
    await interaction.response.send_modal(modal)

@bot.tree.context_menu(name="Delete Censored Message")
async def delete_censored_message(interaction: discord.Interaction, message: discord.Message):
    """Context menu command for deleting censored messages."""
    if not interaction.guild:
        await interaction.response.send_message("Server-only command.", ephemeral=True)
        return

    message_info = await get_censored_message_info(interaction.guild.id, message.id)
    if not message_info:
        await interaction.response.send_message("Cannot delete this message.", ephemeral=True)
        return

    if not (interaction.user.id == message_info["author_id"] or is_moderator()):
        await interaction.response.send_message("Unauthorized to delete.", ephemeral=True)
        return

    webhook = await interaction.client.fetch_webhook(message_info["webhook_id"])
    if isinstance(message.channel, discord.Thread):
        await webhook.delete_message(message.id, thread=message.channel)
    else:
        await webhook.delete_message(message.id)
    await interaction.response.send_message("Message deleted.", ephemeral=True)

# Bot Token and Run
bot.run(os.getenv("BOT_TOKEN"))
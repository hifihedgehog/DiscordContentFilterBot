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
import time
import unicodedata
from asyncio import Queue
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from discord import app_commands
from discord.ext import commands
from typing import Dict, List, Optional, Tuple, Union

# Core Constants
MAX_MESSAGE_LENGTH = 2000
CONFIG_DIR = "server_configs"
DATABASE_PATH = os.path.join(CONFIG_DIR, "censored_messages.db")
CHARACTER_MAP_PATH = "full_character_map.json"

# Markdown Processing
MARKDOWN_MARKERS = ['```', '***', '**', '*', '__', '___', '~~', '`', '||']
MARKDOWN_MARKERS.sort(key=lambda x: -len(x))

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
        
        # Enable WAL2 mode and performance enhancements
        async with db.execute("PRAGMA journal_mode = WAL2;") as cursor:
            result = await cursor.fetchone()
            if result and result[0].upper() == "WAL2":
                print("Journal mode successfully set to WAL2.")
        await db.execute("PRAGMA synchronous = normal")
        await db.execute("PRAGMA temp_store = memory")
        await db.execute("PRAGMA mmap_size = 1000000000;")
            
        # Create tables
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
                    config["global_exceptions"].setdefault(key, [])
                    config["exceptions"].setdefault(key, {})

                config.setdefault("moderator_role_id", None)
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
        "dm_notifications": None,
        "moderator_role_id": None,
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

        if term.startswith("re:"):
            pattern = word_boundary_start + term[3:] + word_boundary_end
        elif await is_emoji_or_sequence(term):
            pattern = regex.escape(term)
        else:

            def create_subpatterns(base_term: str):
                word_pattern = word_boundary_start + regex.escape(base_term) + word_boundary_end
                spaced_pattern = word_boundary_start + r'\s+'.join(regex.escape(char) for char in base_term) + word_boundary_end
                obfuscated_pattern = word_boundary_start + r'[^\w\s]*'.join(regex.escape(char) for char in base_term) + word_boundary_end
                md_markers_class = ''.join(map(regex.escape, MARKDOWN_MARKERS))
                markdown_intermediate = ''.join(
                    f'{regex.escape(char)}(?:[{md_markers_class}]*)'
                    for char in base_term[:-1]
                )
                markdown_last_char = regex.escape(base_term[-1])
                markdown_pattern = word_boundary_start + markdown_intermediate + markdown_last_char + word_boundary_end
                return [word_pattern, spaced_pattern, obfuscated_pattern, markdown_pattern]
            subpatterns = (
                create_subpatterns(term)
                + create_subpatterns(normalized_term)
                + create_subpatterns(reversed_term)
                + create_subpatterns(normalized_reversed_term)
            )
            pattern = f"(?:{'|'.join(subpatterns)})"
        pattern_cache[cache_key] = regex.compile(pattern, regex.IGNORECASE)
    return pattern_cache[cache_key]

async def is_globally_exempt(channel: Optional[discord.abc.GuildChannel],
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

async def check_exceptions(channel: Optional[discord.abc.GuildChannel],
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
async def censor_message(content: str, channel: Optional[discord.abc.GuildChannel], 
                         author: Union[discord.User, discord.Member], server_config: dict) -> str:
    """
    Apply censorship to message content based on blacklists and whitelists.
    Both the original content and its normalized version are checked independently.
    """
    if await is_globally_exempt(channel, author, server_config):
        return content

    blacklists = server_config.get("blacklists", {})
    whitelists = server_config.get("whitelists", {})
    replacement_string = "\*\*\*"
    url_pattern = r're:\bhttps?://[^\s]+\b'

    normalized_content, index_map = await normalize_text(content)

    exempt_ranges_original = []
    exempt_ranges_normalized = []

    all_whitelist_terms = [term for terms in whitelists.values() for term in terms]
    all_whitelist_terms.append(url_pattern)

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

    merged_exempt_ranges = await merge_ranges(exempt_ranges_original + exempt_ranges_normalized)

    match_ranges_original = []
    match_ranges_normalized = []

    for blacklist_name, terms in blacklists.items():
        if await check_exceptions(channel, author, server_config, blacklist_name):
            continue

        for term in terms:
            pattern = await get_blacklist_pattern(term)
            for match in pattern.finditer(content):
                start, end = match.start(), match.end()
                if not any(ex_start <= start < ex_end or ex_start < end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    match_ranges_original.append((start, end))

        for term in terms:
            pattern = await get_blacklist_pattern(term)
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


async def apply_spoilers(content: str, channel: Optional[discord.abc.GuildChannel], 
                         author: Union[discord.User, discord.Member], server_config: dict) -> str:
    """Apply spoiler tags to blacklisted content."""
    if await is_globally_exempt(channel, author, server_config):
        return content

    blacklists = server_config.get("blacklists", {})
    whitelists = server_config.get("whitelists", {})
    url_pattern = r're:\bhttps?://[^\s]+\b'

    normalized_content, index_map = await normalize_text(content)
    exempt_ranges_original = []
    exempt_ranges_normalized = []

    all_whitelist_terms = [term for terms in whitelists.values() for term in terms]
    all_whitelist_terms.append(url_pattern)

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

    merged_exempt_ranges = await merge_ranges(exempt_ranges_original + exempt_ranges_normalized)

    match_ranges_original = []
    match_ranges_normalized = []

    for blacklist_name, terms in blacklists.items():
        if await check_exceptions(channel, author, server_config, blacklist_name):
            continue

        for term in terms:
            pattern = await get_blacklist_pattern(term)
            for match in pattern.finditer(content):
                start, end = match.start(), match.end()
                if not any(ex_start <= start < ex_end or ex_start < end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    match_ranges_original.append((start, end))

        for term in terms:
            pattern = await get_blacklist_pattern(term)
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

async def get_blocked_terms(content: str, channel: Optional[discord.abc.GuildChannel], 
                            author: Union[discord.User, discord.Member], server_config: dict, 
                            blacklist: Optional[str] = None) -> set:
    """Get list of blocked terms that match content."""
    matched_terms = set()

    if await is_globally_exempt(channel, author, server_config):
        return matched_terms

    whitelists = server_config.get("whitelists", {})
    url_pattern = r're:\bhttps?://[^\s]+\b'

    normalized_content, index_map = await normalize_text(content)
    exempt_ranges_original = []
    exempt_ranges_normalized = []
    
    all_whitelist_terms = [term for terms in whitelists.values() for term in terms]
    all_whitelist_terms.append(url_pattern)

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

    merged_exempt_ranges = await merge_ranges(exempt_ranges_original + exempt_ranges_normalized)
    

    blacklists = server_config.get("blacklists", {})
    if blacklist:
        if await check_exceptions(channel, author, server_config, blacklist):
            return matched_terms
        target_blacklist = blacklists.get(blacklist, [])
        for term in target_blacklist:
            pattern = await get_blacklist_pattern(term)
            for match in pattern.finditer(content):
                start, end = match.start(), match.end()
                if not any(ex_start <= start < ex_end or ex_start < end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    matched_terms.add(term)
        for term in target_blacklist:
            pattern = await get_blacklist_pattern(term)
            for match in pattern.finditer(normalized_content):
                start_norm, end_norm = match.start(), match.end()
                orig_start = index_map[start_norm]
                orig_end = index_map[end_norm - 1] + 1
                if not any(ex_start <= orig_start < ex_end or ex_start < orig_end <= ex_end
                           for ex_start, ex_end in merged_exempt_ranges):
                    matched_terms.add(term)
    else:
        for blacklist_name, terms in blacklists.items():
            if await check_exceptions(channel, author, server_config, blacklist_name):
                continue
            for term in terms:
                pattern = await get_blacklist_pattern(term)
                for match in pattern.finditer(content):
                    start, end = match.start(), match.end()
                    if not any(ex_start <= start < ex_end or ex_start < end <= ex_end
                               for ex_start, ex_end in merged_exempt_ranges):
                        matched_terms.add(term)
            for term in terms:
                pattern = await get_blacklist_pattern(term)
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
    """Split long messages while preserving markdown formatting."""
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

async def send_long_message(interaction: discord.Interaction, message: str):
    """Send long messages split into chunks."""
    message_chunks = await split_message_preserving_markdown(message)
    for chunk in message_chunks:
        await interaction.followup.send(chunk, ephemeral=False)

async def repost_as_user(message: discord.Message, censored_message: str) -> discord.Message:
    """Repost censored message via webhook."""
    webhook = await setup_webhook(message.channel)
    author = message.author
    
    if isinstance(author, discord.Member):
        username = author.display_name
        avatar_url = author.avatar.url if author.avatar else None
    else:
        username = author.name
        avatar_url = author.avatar.url if author.avatar else None

    send_kwargs = {
        'content': censored_message[:2000],
        'username': username,
        'avatar_url': avatar_url,
        'wait': True,
    }
    if isinstance(message.channel, discord.Thread):
        send_kwargs['thread'] = message.channel

    try:
        bot_message = await webhook.send(**send_kwargs)
    except discord.HTTPException as e:
        print(f"Failed to send censored message via webhook: {e}")
        return

    await save_censored_message(
        message.guild.id,
        bot_message.id,
        message.author.id,
        webhook.id,
        webhook.token
    )
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

    if not triggered_blacklists:
        blocked_terms = await get_blocked_terms(message.content, message.channel, message.author, server_config)
    else:
        blocked_terms = [term for _, terms in triggered_blacklists for term in terms]

    content = server_config.get("dm_notifications", "Your message was filtered because it contains blacklisted content.")
    embed = discord.Embed(title="Message Censored", color=discord.Color.red(), timestamp=datetime.now(timezone.utc))
    
    embed.add_field(name="Your Message with Blocked Terms Hidden", value=spoilered_content[:1024] or "No content", inline=False)
    embed.add_field(name="Censored Message", value=censored_message[:1024] or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(name="Blocked Terms", 
                       value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
                       inline=False)

    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed.add_field(name="Message Link", value=f"[Go to Message]({reposted_message.jump_url})", inline=False)
    
    try:
        await message.author.send(content=content, embed=embed)
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
                    
    content = server_config.get("dm_notifications", "Your reaction was filtered because it contains blacklisted content.")
    
    embed = discord.Embed(
        title="Reaction Removed",
        color=discord.Color.orange(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Your Removed Reaction", value=spoilered_content, inline=False)
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(name="Blocked Terms", 
                       value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
                       inline=False)
    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed.add_field(name="Message Link", value=f"[Go to Message]({message.jump_url})", inline=False)
    
    try:
        await user.send(content=content, embed=embed)
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

    if not triggered_blacklists:
        blocked_terms = await get_blocked_terms(thread.name, thread, thread.owner, server_config)
    else:
        blocked_terms = [term for _, terms in triggered_blacklists for term in terms]

    content = server_config.get("dm_notifications", "Your thread was filtered because it contains blacklisted content.")
    
    embed = discord.Embed(
        title="Thread Title Censored",
        color=discord.Color.orange(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Your Thread's Title with Blocked Terms Hidden",
                   value=spoilered_content[:1024] or "No content", inline=False)
    embed.add_field(name="Censored Title",
                   value=censored_title[:1024] or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(name="Blocked Terms",
                       value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
                       inline=False)

    embed.add_field(name="Channel", value=thread.parent.mention, inline=False)
    embed.add_field(name="Message Link", value=f"[Go to Thread]({thread.jump_url})", inline=False)
    
    try:
        await thread.owner.send(content=content, embed=embed)
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
    
    content = server_config.get("dm_notifications", "Your message was removed because it contains blacklisted content.")
    
    embed = discord.Embed(
        title="Message Deleted",
        color=discord.Color.dark_red(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Your Message with Blocked Terms Hidden", value=spoilered_content[:1024] or "No content", inline=False)
    embed.add_field(name="Censored Message", value=censored_message[:1024] or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(name="Blocked Terms", 
                       value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
                       inline=False)

    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed.add_field(name="Message Link", value=f"[Go to Message]({message.jump_url})", inline=False)
    
    try:
        await message.author.send(content=content, embed=embed)
    except discord.Forbidden:
        print(f"Unable to send DM to {user.display_name} ({user.id}). They might have DMs disabled.")

async def notify_user_display_name(member, censored_display_name, server_config):
    """Notify user about display name censorship."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(member.display_name, None, member, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(member.display_name, None, member, server_config, blacklist)
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    if not triggered_blacklists:
        blocked_terms = await get_blocked_terms(member.display_name, None, member, server_config)
    else:
        blocked_terms = [term for _, terms in triggered_blacklists for term in terms]

    content = server_config.get("dm_notifications", "Your display name was filtered because it contains blacklisted content.")
    
    embed = discord.Embed(
        title="Display Name Censored",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Your Display Name with Blocked Terms Hidden",
                   value=spoilered_content or "No content", inline=False)
    embed.add_field(name="Censored Display Name",
                   value=censored_display_name or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(name="Blocked Terms",
                       value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
                       inline=False)
    
    try:
        await member.send(content=content, embed=embed)
    except discord.Forbidden:
        pass

# Logging Functions
async def log_censored_message(message, censored_message, reposted_message, server_config):
    """Log censored messages with detailed information."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(message.content, message.channel, message.author, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(
            message.content,
            message.channel,
            message.author,
            server_config,
            blacklist
        )
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(message.content, message.channel, message.author, server_config))

    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        return

    log_channel = message.guild.get_channel(log_channel_id)
    if not log_channel:
        return

    embed = discord.Embed(
        title="Message Censored",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="User", value=message.author.mention, inline=False)
    embed.add_field(name="Original Message", value=spoilered_content[:1024] or "No content", inline=False)
    embed.add_field(name="Censored Message", value=censored_message[:1024] or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([
            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
            for name, terms in triggered_blacklists
        ])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(
            name="Blocked Terms",
            value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
            inline=False
        )

    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed.add_field(name="Message Link", value=f"[Go to Message]({reposted_message.jump_url})", inline=False)
    await log_channel.send(embed=embed)

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

    log_channel = thread.guild.get_channel(log_channel_id)
    if not log_channel:
        return

    embed = discord.Embed(
        title="Thread Title Censored",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="User", value=thread.owner.mention, inline=False)
    embed.add_field(name="Original Title", value=spoilered_content[:1024] or "No content", inline=False)
    embed.add_field(name="Censored Title", value=censored_title[:1024] or "No content", inline=False)

    if triggered_blacklists:
        blacklist_details = "\n".join([
            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
            for name, terms in triggered_blacklists
        ])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(
            name="Blocked Terms",
            value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
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

    log_channel = message.guild.get_channel(log_channel_id)
    if not log_channel:
        return

    embed = discord.Embed(
        title="Reaction Removed",
        color=discord.Color.orange(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="User", value=user.mention, inline=False)
    embed.add_field(name="Removed Reaction", value=spoilered_content, inline=False)
    if triggered_blacklists:
        blacklist_details = "\n".join([f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                                     for name, terms in triggered_blacklists])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(name="Blocked Terms",
                       value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
                       inline=False)
    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed.add_field(name="Message Link", value=f"[Go to Message]({message.jump_url})", inline=False)
    await log_channel.send(embed=embed)

async def log_censored_display_name(member, censored_display_name, server_config):
    """Log display name censorship."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(member.display_name, None, member, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(
            member.display_name,
            None,
            member,
            server_config,
            blacklist
        )
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(member.display_name, None, member, server_config))

    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        return

    log_channel = member.guild.get_channel(log_channel_id)
    if not log_channel:
        return

    embed = discord.Embed(
        title="Display Name Censored",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="User", value=member.mention, inline=False)
    embed.add_field(name="Original Display Name", value=spoilered_content or "No content", inline=False)
    embed.add_field(name="Censored Display Name", value=censored_display_name or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([
            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
            for name, terms in triggered_blacklists
        ])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(
            name="Blocked Terms",
            value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
            inline=False
        )

    embed.add_field(name="User Link", value=f"[Go to User](https://discord.com/users/{member.id})", inline=False)
    await log_channel.send(embed=embed)

async def log_scan_deletion(message: discord.Message, censored_message: str, server_config: dict):
    """Log message deletions from channel scans."""
    triggered_blacklists = []
    spoilered_content = await apply_spoilers(message.content, message.channel, message.author, server_config)
    
    for blacklist, terms in server_config.get("blacklists", {}).items():
        blocked_terms = await get_blocked_terms(
            message.content,
            message.channel,
            message.author,
            server_config,
            blacklist
        )
        if blocked_terms:
            triggered_blacklists.append((blacklist, blocked_terms))

    blocked_terms = ([term for _, terms in triggered_blacklists for term in terms] if triggered_blacklists 
                    else await get_blocked_terms(message.content, message.channel, message.author, server_config))

    log_channel_id = server_config.get("log_channel_id")
    if not log_channel_id:
        return

    log_channel = message.guild.get_channel(log_channel_id)
    if not log_channel:
        return

    embed = discord.Embed(
        title="Message Deleted via Channel Scan",
        color=discord.Color.dark_red(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="User", value=message.author.mention, inline=False)
    embed.add_field(name="Original Message", value=spoilered_content[:1024] or "No content", inline=False)
    embed.add_field(name="Censored Content", value=censored_message[:1024] or "No content", inline=False)
    
    if triggered_blacklists:
        blacklist_details = "\n".join([
            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
            for name, terms in triggered_blacklists
        ])
        embed.add_field(name="Triggered Blacklists", value=blacklist_details, inline=False)
    else:
        embed.add_field(
            name="Blocked Terms",
            value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
            inline=False
        )

    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed.add_field(name="Message Link", value=f"[Go to Message]({message.jump_url})", inline=False)
    await log_channel.send(embed=embed)

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
                    print(f"User {user} already has punishment role '{role.name}'. Skipping punishment.")
                    return

                try:
                    await user.add_roles(role, reason="Exceeded violation threshold.")
                except discord.Forbidden:
                    print(f"Failed to add role '{role.name}' to {user.display_name}. Insufficient permissions.")
                    return
                except discord.HTTPException as e:
                    print(f"HTTPException while adding role '{role.name}' to {user.display_name}: {e}")
                    return

                expiration_time = current_time + punishment_duration
                try:
                    await add_punishment(guild_id, user.id, role_id, expiration_time)
                except aiosqlite.IntegrityError:
                    print(f"Punishment already exists for user {user} in guild {guild_id}.")
                    return

                embed = discord.Embed(
                    title="Punishment Applied",
                    color=discord.Color.dark_red(),
                    timestamp=current_time
                )
                embed.add_field(name="Reason", value="Repeated violations of the server's content rules.", inline=False)
                embed.add_field(name="Punishment", value=f"Temporary role: `{role.name}`", inline=False)
                embed.add_field(name="Duration", value=str(punishment_duration), inline=False)
                embed.add_field(name="Punishment Expires At", value=f"<t:{int(expiration_time.timestamp())}:R>", inline=False)

                try:
                    await user.send(
                        content="You have received a temporary role due to repeated violations of the server's content rules.",
                        embed=embed
                    )
                except discord.Forbidden:
                    print(f"Unable to send DM to {user.display_name} ({user.id}).")

                log_channel_id = server_config.get("log_channel_id")
                if log_channel_id:
                    log_channel = user.guild.get_channel(log_channel_id)
                    if log_channel:
                        embed_log = discord.Embed(
                            title="Punishment Applied",
                            color=discord.Color.dark_red(),
                            timestamp=current_time
                        )
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
        censored_display_name = await censor_message(member.display_name, None, member, server_config)
        if censored_display_name != member.display_name:
            try:
                await log_censored_display_name(member, censored_display_name, server_config)
                await notify_user_display_name(member, censored_display_name, server_config)
                await check_and_apply_punishment(member, member.guild.id, server_config)
                await member.edit(nick=censored_display_name)
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
        url_pattern = r're:\bhttps?://[^\s]+\b'
        all_whitelist_terms.append(url_pattern)
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
    if isinstance(message.channel, (discord.TextChannel, discord.ForumChannel, 
                                  discord.Thread, discord.VoiceChannel, discord.StageChannel)):
        censored_message_content = await censor_message(
            message.content, message.channel, message.author, server_config
        )
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
    if not isinstance(channel, (discord.TextChannel, discord.ForumChannel, 
                              discord.Thread, discord.VoiceChannel, discord.StageChannel)):
        return
        
    try:
        message = await channel.fetch_message(payload.message_id)
    except discord.NotFound:
        return
        
    if message.author == bot.user or not message.guild:
        return
        
    server_config = await load_server_config(message.guild.id)
    censored_message_content = await censor_message(
        message.content, channel, message.author, server_config
    )
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
    censored_title = await censor_message(thread.name, thread, thread.owner, server_config)
    
    if censored_title != thread.name:
        try:
            if thread.owner:
                await notify_user_thread_title(thread, censored_title, server_config)
            await log_censored_thread_title(thread, censored_title, server_config)
            await thread.edit(name=censored_title.replace("\*\*\*","***"))
            await check_and_apply_punishment(thread.owner, thread.guild.id, server_config)
        except (discord.Forbidden, discord.HTTPException) as e:
            print(f"Error editing thread title: {e}")

@bot.event
async def on_thread_update(before, after):
    """Handle thread updates."""
    server_config = await load_server_config(after.guild.id)
    censored_title = await censor_message(after.name, after, after.owner, server_config)
    
    if censored_title != after.name:
        try:
            if after.owner:
                await notify_user_thread_title(after, censored_title, server_config)
            await log_censored_thread_title(after, censored_title, server_config)
            await after.edit(name=censored_title.replace("\*\*\*","***"))
            await check_and_apply_punishment(after.owner, after.guild.id, server_config)
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
    reaction = discord.Reaction(
        message=message,
        data={'count': None, 'me': None, 'emoji': emoji},
        emoji=emoji
    )
    
    server_config = await load_server_config(message.guild.id)
    censored_emoji = await censor_message(
        str(reaction.emoji), message.channel, user, server_config
    )
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
# Replace the existing punishment_checker function with this enhanced version
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
                            await member.remove_roles(role, reason="Punishment duration expired.")
                            try:
                                await member.send(
                                    content=f"Your punishment role `{role.name}` has been lifted. "
                                           "Please adhere to the server rules to avoid future punishments."
                                )
                            except discord.Forbidden:
                                print(f"Unable to send DM to {member.display_name} ({member.id}).")

                            server_config = await load_server_config(guild_id)
                            log_channel_id = server_config["log_channel_id"]
                            if log_channel_id:
                                log_channel = guild.get_channel(log_channel_id)
                                if log_channel:
                                    embed_lift = discord.Embed(
                                        title="Punishment Lifted",
                                        color=discord.Color.green(),
                                        timestamp=datetime.now(timezone.utc)
                                    )
                                    embed_lift.add_field(name="User", value=member.mention, inline=False)
                                    embed_lift.add_field(name="Punishment Role", value=f"`{role.name}`", inline=False)
                                    embed_lift.add_field(name="Punishment Lifted At", value=f"<t:{int(datetime.now(timezone.utc).timestamp())}:R>", inline=False)
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
        self.edited_message = discord.ui.TextInput(
            label="Edited Message Content",
            style=discord.TextStyle.paragraph,
            placeholder="Enter your edited message",
            required=True,
            custom_id="edited_message",
            max_length=2000,
            default=message.content
        )
        self.add_item(self.edited_message)
        self.message = message
        self.guild_id = guild_id
        self.webhook_id = webhook_id
        self.webhook_token = webhook_token

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        if self.message.content != self.edited_message.value:
            server_config = await load_server_config(self.guild_id)
            censored_message = await censor_message(self.edited_message.value, self.message.channel, interaction.user, server_config)
            try:
                webhook = await interaction.client.fetch_webhook(self.webhook_id)
                if isinstance(self.message.channel, discord.Thread):
                    await webhook.edit_message(
                        self.message.id,
                        content=censored_message,
                        thread=self.message.channel
                    )
                else:
                    await webhook.edit_message(
                        self.message.id,
                        content=censored_message
                    )
                if self.edited_message.value != censored_message:
                    spoilered_content = await apply_spoilers(self.edited_message.value, self.message.channel, interaction.user, server_config)
                    triggered_blacklists = []
                    for blacklist, terms in server_config.get("blacklists", {}).items():
                        blocked_terms = await get_blocked_terms(
                            self.edited_message.value,
                            self.message.channel,
                            interaction.user,
                            server_config,
                            blacklist
                        )
                        if blocked_terms:
                            triggered_blacklists.append((blacklist, blocked_terms))

                    if not triggered_blacklists:
                        blocked_terms = await get_blocked_terms(
                            self.edited_message.value,
                            self.message.channel,
                            interaction.user,
                            server_config,
                        )
                    else:
                        blocked_terms = [term for _, terms in triggered_blacklists for term in terms]
                    embed = discord.Embed(
                        title="Message Censored",
                        color=discord.Color.dark_red(),
                        timestamp=datetime.now(timezone.utc)
                    )
                    embed.add_field(
                        name="Your Message with Blocked Terms Hidden",
                        value=spoilered_content[:1024] or "No content",
                        inline=False
                    )
                    if triggered_blacklists:
                        blacklist_details = "\n".join([
                            f"**{name}**: {', '.join(f'`{term}`' for term in terms)}"
                            for name, terms in triggered_blacklists
                        ])
                        embed.add_field(
                            name="Triggered Blacklists",
                            value=blacklist_details,
                            inline=False
                        )
                    else:
                        embed.add_field(
                            name="Blocked Terms",
                            value=", ".join(f'`{term}`' for term in blocked_terms) if blocked_terms else "No specific terms matched",
                            inline=False
                        )
                    await interaction.followup.send(
                        content="Your edited message was filtered because it contains blacklisted content.",
                        embed=embed,
                        ephemeral=True
                    )
                else:
                    await interaction.followup.send(
                        "Your message has been successfully updated.",
                        ephemeral=True
                    )
            except discord.NotFound:
                await interaction.followup.send(
                    "Original message not found.",
                    ephemeral=True
                )
            except discord.Forbidden:
                await interaction.followup.send(
                    "Cannot edit the message.",
                    ephemeral=True
                )
            except discord.HTTPException as e:
                await interaction.followup.send(
                    f"Failed to edit the message: {e}",
                    ephemeral=True
                )

# Selection View Classes
class BlacklistSelectView(discord.ui.View):
    """View for selecting a blacklist to edit."""
    def __init__(self, blacklists):
        super().__init__()
        sorted_blacklist_names = sorted(blacklists.keys(), key=lambda x: x.lower())
        options = [
            discord.SelectOption(
                label=bl_name,
                description=f"Edit the `{bl_name}` blacklist",
                emoji="📝"
            )
            for bl_name in sorted_blacklist_names[:25]
        ]
        self.add_item(BlacklistSelect(options))

class BlacklistSelect(discord.ui.Select):
    """Dropdown for selecting a blacklist."""
    def __init__(self, options):
        super().__init__(
            placeholder="Choose a blacklist to edit...",
            min_values=1,
            max_values=1,
            options=options,
            custom_id="blacklist_select"
        )

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
                description=f"Edit the `{wl_name}` whitelist",
                emoji="📝"
            )
            for wl_name in sorted_whitelist_names[:25]
        ]
        self.add_item(WhitelistSelect(options))

class WhitelistSelect(discord.ui.Select):
    """Dropdown for selecting a whitelist."""
    def __init__(self, options):
        super().__init__(
            placeholder="Choose a whitelist to edit...",
            min_values=1,
            max_values=1,
            options=options,
            custom_id="whitelist_select"
        )

    async def callback(self, interaction: discord.Interaction):
        selected_name = self.values[0]
        server_config = await load_server_config(interaction.guild.id)
        whitelists = server_config.get("whitelists", {})
        await show_whitelist_edit_modal(interaction, selected_name, whitelists)

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
                "- Regex: re:\\b\\w*badw\\w*\\b (blocks any word containing badw)"
            )
        )

        async def on_submit(modal_self, interaction: discord.Interaction):
            await interaction.response.defer(ephemeral=False)
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
                "- Regex: re:\\b\\w*goodw\\w*\\b (allows any word containing goodw)"
            )
        )

        async def on_submit(modal_self, interaction: discord.Interaction):
            await interaction.response.defer(ephemeral=False)
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
@bot.tree.command(name="set_moderator_role")
@is_admin()
async def set_moderator_role(interaction: discord.Interaction, role: discord.Role):
    """Set moderator role for the server."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["moderator_role_id"] = role.id
    await save_server_config(interaction.guild.id, server_config)
    await interaction.response.send_message(f"Moderator role set to {role.mention}.", ephemeral=True)

@bot.tree.command(name="set_log_channel")
@is_admin()
async def set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    """Set a log channel for filtered content activity."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["log_channel_id"] = channel.id
    await save_server_config(interaction.guild.id, server_config)
    await interaction.response.send_message(f"Log channel set to {channel.mention}")

@bot.tree.command(name="set_dm_notification")
@is_admin()
async def set_dm_notification(interaction: discord.Interaction):
    """Set custom DM notification message using modal."""
    server_config = await load_server_config(interaction.guild.id)
    message_content = server_config["dm_notifications"]
    
    class SetDMNotificationModal(discord.ui.Modal, title="Set DM Notification"):
        def __init__(self):
            super().__init__()
            self.notification_message = discord.ui.TextInput(
                label="DM Notification Message",
                style=discord.TextStyle.paragraph,
                required=True,
                custom_id="notification_message",
                default=message_content,
                max_length=2000,
                placeholder="Enter notification message for censored content."
            )
            self.add_item(self.notification_message)

        async def on_submit(self, interaction: discord.Interaction):
            await interaction.response.defer(ephemeral=True)
            server_config["dm_notifications"] = self.notification_message.value.strip()
            await save_server_config(interaction.guild.id, server_config)
            await interaction.followup.send(
                "DM notification message set. Preview below:", 
                embed=discord.Embed(description=self.notification_message.value),
                ephemeral=True
            )

    await interaction.response.send_modal(SetDMNotificationModal())
    
@bot.tree.command(name="toggle_display_name_filter")
@is_admin()
async def toggle_display_name_filter(interaction: discord.Interaction, enabled: bool):
    """Toggle display name filtering."""
    server_config = await load_server_config(interaction.guild.id)
    server_config["display_name_filter_enabled"] = enabled
    await save_server_config(interaction.guild.id, server_config)
    status = "enabled" if enabled else "disabled"
    await interaction.response.send_message(f"Display name filtering {status}.")

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
    await interaction.response.send_message("Punishment settings updated.")

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
        await interaction.response.send_message(f"Deleted blacklist '{name}'.")
    else:
        await interaction.response.send_message(f"Blacklist '{name}' not found.")

@bot.tree.command(name="delete_whitelist")
@is_admin()
async def delete_whitelist(interaction: discord.Interaction, name: str):
    """Delete a whitelist."""
    server_config = await load_server_config(interaction.guild.id)
    if name in server_config["whitelists"]:
        del server_config["whitelists"][name]
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Deleted whitelist '{name}'.")
    else:
        await interaction.response.send_message(f"Whitelist '{name}' not found.")

# Commands - Exception Management
@bot.tree.command(name="add_category_exception")
@is_admin()
async def add_category_exception(interaction: discord.Interaction, category: discord.CategoryChannel, blacklist_name: str):
    """Add category exception to blacklist."""
    server_config = await load_server_config(interaction.guild.id)
    blacklists = server_config.get("blacklists", {})
    
    if blacklist_name not in blacklists:
        await interaction.response.send_message(
            f"The blacklist '{blacklist_name}' does not exist.", ephemeral=True
        )
        return

    exceptions = server_config.setdefault("exceptions", {"channels": {}, "categories": {}, "roles": {}})
    category_id = category.id

    if category_id not in exceptions["categories"]:
        exceptions["categories"][category_id] = []
    if blacklist_name not in exceptions["categories"][category_id]:
        exceptions["categories"][category_id].append(blacklist_name)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(
            f"Added exception for category {category.name} to blacklist '{blacklist_name}'."
        )
    else:
        await interaction.response.send_message(
            f"Category {category.name} is already excepted from '{blacklist_name}'.", ephemeral=True
        )

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

    # Check if the blacklist exists
    if blacklist_name not in blacklists:
        await interaction.response.send_message(
            f"The blacklist '{blacklist_name}' does not exist.", ephemeral=True
        )
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
        await interaction.response.send_message(
            f"{channel.mention} is already excepted from '{blacklist_name}'.", ephemeral=True
        )

@bot.tree.command(name="add_role_exception")
@is_admin()
async def add_role_exception(interaction: discord.Interaction, role: discord.Role, blacklist_name: str):
    """Add role exception to blacklist."""
    server_config = await load_server_config(interaction.guild.id)
    blacklists = server_config.get("blacklists", {})

    # Check if the blacklist exists
    if blacklist_name not in blacklists:
        await interaction.response.send_message(
            f"The blacklist '{blacklist_name}' does not exist.", ephemeral=True
        )
        return

    exceptions = server_config.setdefault("exceptions", {"channels": {}, "categories": {}, "roles": {}})
    role_id = role.id

    if role_id not in exceptions["roles"]:
        exceptions["roles"][role_id] = []
    if blacklist_name not in exceptions["roles"][role_id]:
        exceptions["roles"][role_id].append(blacklist_name)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(
            f"Added exception for role {role.name} to blacklist '{blacklist_name}'."
        )
    else:
        await interaction.response.send_message(
            f"Role {role.name} is already excepted from '{blacklist_name}'.", ephemeral=True
        )

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
        category_id = str(category.id)
        category_name = category.name
    elif category_id:
        category_name = f"ID {category_id}"
    else:
        await interaction.response.send_message("Invalid input. Please provide a category or its ID.", ephemeral=True)
        return

    exceptions = server_config.get("exceptions", {}).get("categories", {})
    if category_id in exceptions and blacklist_name in exceptions[category_id]:
        exceptions[category_id].remove(blacklist_name)
        if not exceptions[category_id]:
            del exceptions[category_id]
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Removed {category_name} exception from '{blacklist_name}'.")
    else:
        await interaction.response.send_message(f"{category_name} is not excepted from '{blacklist_name}'.")
        
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
        channel_id = str(channel.id)
        channel_name = channel.name
        channel_mention = channel.mention
    elif channel_id:
        channel_name = f"ID {channel_id}"
        channel_mention = channel_name
    else:
        await interaction.response.send_message("Invalid input. Please provide a channel or its ID.", ephemeral=True)
        return

    exceptions = server_config.get("exceptions", {}).get("channels", {})
    if channel_id in exceptions and blacklist_name in exceptions[channel_id]:
        exceptions[channel_id].remove(blacklist_name)
        if not exceptions[channel_id]:
            del exceptions[channel_id]
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Removed {channel_mention} exception from '{blacklist_name}'.")
    else:
        await interaction.response.send_message(f"{channel_mention} is not excepted from '{blacklist_name}'.")
        
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
        role_id = str(role.id)
        role_name = role.name
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
        await interaction.response.send_message(f"Removed {role_mention} exception from '{blacklist_name}'.")
    else:
        await interaction.response.send_message(f"{role_mention} is not excepted from '{blacklist_name}'.")

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
        await interaction.response.send_message(f"Added {category.name} to global exceptions.")
    else:
        await interaction.response.send_message(f"{category.name} already globally excepted.")

@bot.tree.command(name="add_global_channel_exception")
@is_admin()
async def add_global_channel_exception(interaction: discord.Interaction, 
    channel: Union[discord.TextChannel, discord.ForumChannel, discord.Thread, discord.VoiceChannel, discord.StageChannel]):
    """Add channel to global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    if channel.id not in server_config["global_exceptions"]["channels"]:
        server_config["global_exceptions"]["channels"].append(channel.id)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Added {channel.mention} to global exceptions.")
    else:
        await interaction.response.send_message(f"{channel.mention} already globally excepted.")

# After add_global_channel_exception command
@bot.tree.command(name="add_global_role_exception")
@is_admin()
async def add_global_role_exception(interaction: discord.Interaction, role: discord.Role):
    """Add role to global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    if role.id not in server_config["global_exceptions"]["roles"]:
        server_config["global_exceptions"]["roles"].append(role.id)
        await save_server_config(interaction.guild.id, server_config)
        await interaction.response.send_message(f"Added {role.name} to global exceptions.")
    else:
        await interaction.response.send_message(f"{role.name} already globally excepted.")

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
        await interaction.response.send_message(f"Removed {category_name} from global exceptions.")
    else:
        await interaction.response.send_message(f"{category_name} not globally excepted.")

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
        await interaction.response.send_message(f"Removed {channel_mention} from global exceptions.")
    else:
        await interaction.response.send_message(f"{channel_mention} not globally excepted.")

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
        await interaction.response.send_message(f"Removed {role_name} from global exceptions.")
    else:
        await interaction.response.send_message(f"{role_name} not globally excepted.")

# Commands - List and Display
@bot.tree.command(name="list_blacklists")
@is_moderator()
async def list_blacklists(interaction: discord.Interaction):
    """List all blacklists and their terms."""
    await interaction.response.defer(ephemeral=False)
    server_config = await load_server_config(interaction.guild.id)
    if not server_config["blacklists"]:
        await interaction.followup.send("No blacklists found.")
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
    await interaction.response.defer(ephemeral=False)
    server_config = await load_server_config(interaction.guild.id)
    if not server_config["whitelists"]:
        await interaction.followup.send("No whitelists found.")
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
        f"{interaction.guild.get_channel(category_id).mention if interaction.guild.get_channel(category_id)
        else f'ID: {category_id}'} - {', '.join(blacklist_names)}"
        for category_id, blacklist_names in exceptions.get("categories", {}).items()
    ]
    channels = [
        f"{interaction.guild.get_channel(channel_id).mention if interaction.guild.get_channel(channel_id)
        else f'ID: {channel_id}'} - {', '.join(blacklist_names)}"
        for channel_id, blacklist_names in exceptions.get("channels", {}).items()
    ]
    roles = [
        f"{interaction.guild.get_role(role_id).mention if interaction.guild.get_role(role_id)
        else f'ID: {role_id}'} - {', '.join(blacklist_names)}"
        for role_id, blacklist_names in exceptions.get("roles", {}).items()
    ]

    embed = discord.Embed(
        title="Exceptions",
        color=discord.Color.green(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Categories", value="\n".join(categories) if categories else "None", inline=False)
    embed.add_field(name="Channels", value="\n".join(channels) if channels else "None", inline=False)
    embed.add_field(name="Roles", value="\n".join(roles) if roles else "None", inline=False)

    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="list_global_exceptions")
@is_moderator()
async def list_global_exceptions(interaction: discord.Interaction):
    """List all global exceptions."""
    server_config = await load_server_config(interaction.guild.id)
    global_exceptions = server_config.get("global_exceptions", {})
    
    categories = [
        interaction.guild.get_channel(category_id).mention if isinstance(interaction.guild.get_channel(category_id), discord.CategoryChannel)
        else f"ID: {category_id}" 
        for category_id in global_exceptions.get("categories", [])
    ]
    channels = [
        interaction.guild.get_channel(channel_id).mention if interaction.guild.get_channel(channel_id) 
        else f"ID: {channel_id}" 
        for channel_id in global_exceptions.get("channels", [])
    ]
    roles = [
        interaction.guild.get_role(role_id).mention if interaction.guild.get_role(role_id)
        else f"ID: {role_id}" 
        for role_id in global_exceptions.get("roles", [])
    ]
    
    embed = discord.Embed(
        title="Global Exceptions",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Categories", value=", ".join(categories) if categories else "None", inline=False)
    embed.add_field(name="Channels", value=", ".join(channels) if channels else "None", inline=False)
    embed.add_field(name="Roles", value=", ".join(roles) if roles else "None", inline=False)
    
    await interaction.response.send_message(embed=embed)

# Commands - Moderation
@bot.tree.command(name="lift_punishment")
@is_moderator()
@app_commands.describe(member="The member to lift punishment from")
async def lift_punishment(interaction: discord.Interaction, member: discord.Member):
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

    # Validate punishment exists
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("""
            SELECT guild_id, user_id, role_id FROM punishments
            WHERE guild_id = ? AND user_id = ? AND role_id = ?
        """, (interaction.guild.id, member.id, punishment_role_id)) as cursor:
            punishments = await cursor.fetchall()

    if not punishments:
        await interaction.response.send_message(
            f"{member.mention} has no active punishments.", 
            ephemeral=True
        )
        return

    try:
        await member.remove_roles(punishment_role, reason="Punishment manually lifted.")
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.executemany("""
                DELETE FROM punishments
                WHERE guild_id = ? AND user_id = ? AND role_id = ?
            """, punishments)
            await db.commit()

        # Notify user
        try:
            await member.send(
                f"Your punishment role `{punishment_role.name}` has been lifted by a staff member."
            )
        except discord.Forbidden:
            pass

        # Log action
        log_channel_id = server_config.get("log_channel_id")
        if log_channel_id:
            log_channel = interaction.guild.get_channel(log_channel_id)
            if log_channel:
                embed = discord.Embed(
                    title="Punishment Lifted",
                    color=discord.Color.green(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="User", value=member.mention, inline=False)
                embed.add_field(name="Punishment Role", value=f"`{punishment_role.name}`", inline=False)
                embed.add_field(name="Action", value="Punishment manually lifted.", inline=False)
                await log_channel.send(embed=embed)

        await interaction.response.send_message(
            f"Punishment role removed from {member.mention}.",
            ephemeral=True
        )

    except discord.Forbidden:
        await interaction.response.send_message(
            "Insufficient permissions to remove roles.",
            ephemeral=True
        )
    except Exception as e:
        await interaction.response.send_message(
            f"Error removing punishment: {e}",
            ephemeral=True
        )

@bot.tree.command(name="scan_last_messages")
@app_commands.describe(
    limit="The number of recent messages to scan (max 10000)."
)
@is_moderator()
async def scan_last_messages(interaction: discord.Interaction, limit: int):
    """Scan the last specified number of messages in the channel and delete those containing blacklisted content."""
    MAX_LIMIT = 10000
    if limit < 1 or limit > MAX_LIMIT:
        await interaction.response.send_message(
            f"Please provide a number between 1 and {MAX_LIMIT}.",
            ephemeral=True
        )
        return

    server_config = await load_server_config(interaction.guild.id)
    channel = interaction.channel
    deleted_count = 0
    scanned_count = 0

    await interaction.response.defer(ephemeral=True)
    progress_message = await interaction.followup.send(
        f"Starting scan of {limit} messages. Progress: 0% (0/{limit} messages scanned).", 
        ephemeral=True
    )

    try:
        async for message in channel.history(limit=limit):
            scanned_count += 1
            progress_percent = int((scanned_count / limit) * 100)
            
            if scanned_count % 10 == 0 or scanned_count == limit:
                await progress_message.edit(
                    content=f"Scanning messages... Progress: {progress_percent}% ({scanned_count}/{limit} messages scanned)."
                )

            if message.author == bot.user or message.author.bot:
                continue

            censored_message = await censor_message(message.content, message.channel, message.author, server_config)
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

    modal = EditMessageModal(message, interaction.guild.id, 
                           message_info["webhook_id"], message_info["webhook_token"])
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
bot.run("YOUR_BOT_TOKEN_HERE")
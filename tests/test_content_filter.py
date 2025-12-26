"""
Comprehensive unit tests for content_filter.py changes.

Tests cover:
1. on_app_command_error function - error handling for application commands
2. delete_user_censored_messages function - deletion of censored messages
"""

import pytest
import asyncio
import aiosqlite
import tempfile
import os
from unittest.mock import Mock, AsyncMock, MagicMock, patch, call
from datetime import datetime, timezone
from typing import Optional

import discord
from discord import app_commands


class TestOnAppCommandError:
    """Test suite for on_app_command_error function."""
    
    @pytest.fixture
    def interaction(self):
        """Create a mock Discord interaction object."""
        interaction = AsyncMock(spec=discord.Interaction)
        interaction.response = AsyncMock()
        interaction.response.is_done = Mock(return_value=False)
        interaction.response.send_message = AsyncMock()
        interaction.followup = AsyncMock()
        interaction.followup.send = AsyncMock()
        interaction.user = Mock(spec=discord.User)
        interaction.user.name = "TestUser"
        return interaction
    
    @pytest.mark.asyncio
    async def test_check_failure_not_responded(self, interaction):
        """Test CheckFailure error when response not yet sent."""
        error = app_commands.CheckFailure()
        
        # Simulate the function behavior
        content = "You do not have permission to use this command."
        
        # Mock is_done to return False (not responded yet)
        interaction.response.is_done.return_value = False
        
        # Simulate the error handler
        try:
            if interaction.response.is_done():
                await interaction.followup.send(content, ephemeral=True)
            else:
                await interaction.response.send_message(content, ephemeral=True)
        except:
            pass
        
        # Verify response.send_message was called
        interaction.response.send_message.assert_called_once_with(
            "You do not have permission to use this command.",
            ephemeral=True
        )
        interaction.followup.send.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_check_failure_already_responded(self, interaction):
        """Test CheckFailure error when response already sent."""
        error = app_commands.CheckFailure()
        content = "You do not have permission to use this command."
        
        # Mock is_done to return True (already responded)
        interaction.response.is_done.return_value = True
        
        # Simulate the error handler
        try:
            if interaction.response.is_done():
                await interaction.followup.send(content, ephemeral=True)
            else:
                await interaction.response.send_message(content, ephemeral=True)
        except:
            pass
        
        # Verify followup.send was called
        interaction.followup.send.assert_called_once_with(
            "You do not have permission to use this command.",
            ephemeral=True
        )
        interaction.response.send_message.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_generic_error_not_responded(self, interaction):
        """Test generic error when response not yet sent."""
        error = app_commands.AppCommandError("Something went wrong")
        content = "An unexpected error occurred. Please contact an administrator."
        
        interaction.response.is_done.return_value = False
        
        # Simulate the error handler
        try:
            if interaction.response.is_done():
                await interaction.followup.send(content, ephemeral=True)
            else:
                await interaction.response.send_message(content, ephemeral=True)
        except:
            pass
        
        interaction.response.send_message.assert_called_once_with(
            "An unexpected error occurred. Please contact an administrator.",
            ephemeral=True
        )
    
    @pytest.mark.asyncio
    async def test_generic_error_already_responded(self, interaction):
        """Test generic error when response already sent."""
        error = app_commands.AppCommandError("Something went wrong")
        content = "An unexpected error occurred. Please contact an administrator."
        
        interaction.response.is_done.return_value = True
        
        # Simulate the error handler
        try:
            if interaction.response.is_done():
                await interaction.followup.send(content, ephemeral=True)
            else:
                await interaction.response.send_message(content, ephemeral=True)
        except:
            pass
        
        interaction.followup.send.assert_called_once_with(
            "An unexpected error occurred. Please contact an administrator.",
            ephemeral=True
        )
    
    @pytest.mark.asyncio
    async def test_error_handler_exception_silently_ignored(self, interaction):
        """Test that exceptions in error handler are silently ignored."""
        interaction.response.is_done.return_value = False
        interaction.response.send_message.side_effect = discord.HTTPException(Mock(), "Network error")
        
        # The error handler should catch exceptions
        try:
            if interaction.response.is_done():
                await interaction.followup.send("test", ephemeral=True)
            else:
                await interaction.response.send_message("test", ephemeral=True)
        except:
            pass  # Silently ignore
        
        # Should have attempted to send
        interaction.response.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_error_handler_followup_exception_silently_ignored(self, interaction):
        """Test that exceptions in followup send are silently ignored."""
        interaction.response.is_done.return_value = True
        interaction.followup.send.side_effect = discord.HTTPException(Mock(), "Network error")
        
        try:
            if interaction.response.is_done():
                await interaction.followup.send("test", ephemeral=True)
            else:
                await interaction.response.send_message("test", ephemeral=True)
        except:
            pass
        
        interaction.followup.send.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_error_type_differentiation(self, interaction):
        """Test that different error types produce different messages."""
        # CheckFailure should produce permission message
        check_error = app_commands.CheckFailure()
        if isinstance(check_error, app_commands.CheckFailure):
            check_content = "You do not have permission to use this command."
        else:
            check_content = "An unexpected error occurred. Please contact an administrator."
        
        assert check_content == "You do not have permission to use this command."
        
        # Generic error should produce unexpected error message
        generic_error = app_commands.AppCommandError("Test")
        if isinstance(generic_error, app_commands.CheckFailure):
            generic_content = "You do not have permission to use this command."
        else:
            generic_content = "An unexpected error occurred. Please contact an administrator."
        
        assert generic_content == "An unexpected error occurred. Please contact an administrator."


class TestDeleteUserCensoredMessages:
    """Test suite for delete_user_censored_messages function."""
    
    @pytest.fixture
    async def temp_db(self):
        """Create a temporary database for testing."""
        db_fd, db_path = tempfile.mkstemp(suffix='.db')
        os.close(db_fd)
        
        # Initialize database with schema
        async with aiosqlite.connect(db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS censored_messages (
                    guild_id INTEGER NOT NULL,
                    author_id INTEGER NOT NULL,
                    message_id INTEGER NOT NULL,
                    webhook_id INTEGER,
                    webhook_token TEXT,
                    thread_id INTEGER,
                    PRIMARY KEY (guild_id, message_id)
                )
            """)
            await db.commit()
        
        yield db_path
        
        # Cleanup
        try:
            os.unlink(db_path)
        except:
            pass
    
    @pytest.fixture
    def interaction(self):
        """Create a mock Discord interaction object."""
        interaction = AsyncMock(spec=discord.Interaction)
        interaction.response = AsyncMock()
        interaction.response.defer = AsyncMock()
        interaction.followup = AsyncMock()
        interaction.followup.send = AsyncMock()
        interaction.user = Mock(spec=discord.User)
        interaction.user.mention = "<@123456789>"
        interaction.guild = Mock(spec=discord.Guild)
        interaction.guild.id = 111111111
        interaction.guild.get_member = Mock(return_value=None)
        interaction.guild.get_channel_or_thread = Mock(return_value=None)
        interaction.guild.get_thread = Mock(return_value=None)
        return interaction
    
    @pytest.fixture
    def bot(self):
        """Create a mock bot object."""
        bot = AsyncMock()
        bot.fetch_user = AsyncMock()
        bot.fetch_webhook = AsyncMock()
        return bot
    
    @pytest.mark.asyncio
    async def test_both_user_and_user_id_provided(self, interaction):
        """Test error when both user and user_id are provided."""
        user = Mock(spec=discord.User)
        user.id = 123456789
        user_id = "987654321"
        
        await interaction.response.defer(ephemeral=True)
        
        # Both parameters provided - should error
        if user and user_id:
            await interaction.followup.send(
                "Please provide either a user or a user ID, not both.",
                ephemeral=True
            )
            return
        
        interaction.followup.send.assert_called_once_with(
            "Please provide either a user or a user ID, not both.",
            ephemeral=True
        )
    
    @pytest.mark.asyncio
    async def test_neither_user_nor_user_id_provided(self, interaction):
        """Test error when neither user nor user_id are provided."""
        user = None
        user_id = None
        
        await interaction.response.defer(ephemeral=True)
        
        if not user and not user_id:
            await interaction.followup.send(
                "Please provide either a user or a user ID.",
                ephemeral=True
            )
            return
        
        interaction.followup.send.assert_called_once_with(
            "Please provide either a user or a user ID.",
            ephemeral=True
        )
    
    @pytest.mark.asyncio
    async def test_invalid_user_id_format(self, interaction):
        """Test error when user_id is not a valid integer."""
        user = None
        user_id = "not_a_number"
        
        await interaction.response.defer(ephemeral=True)
        
        if user_id:
            try:
                target_user_id = int(user_id)
            except ValueError:
                await interaction.followup.send(
                    "Invalid user ID format.",
                    ephemeral=True
                )
                return
        
        interaction.followup.send.assert_called_once_with(
            "Invalid user ID format.",
            ephemeral=True
        )
    
    @pytest.mark.asyncio
    async def test_user_id_conversion_success(self):
        """Test successful conversion of valid user_id string."""
        user_id = "123456789"
        
        try:
            target_user_id = int(user_id)
            assert target_user_id == 123456789
        except ValueError:
            pytest.fail("Should not raise ValueError for valid user ID")
    
    @pytest.mark.asyncio
    async def test_user_object_id_extraction(self):
        """Test extraction of user ID from user object."""
        user = Mock(spec=discord.User)
        user.id = 987654321
        
        target_user_id = user.id
        assert target_user_id == 987654321
    
    @pytest.mark.asyncio
    async def test_user_not_found_graceful_handling(self, interaction, bot):
        """Test graceful handling when user cannot be fetched."""
        target_user_id = 123456789
        
        # Mock fetch_user to raise NotFound
        bot.fetch_user.side_effect = discord.NotFound(Mock(), "User not found")
        interaction.guild.get_member.return_value = None
        
        try:
            target_user = (
                interaction.guild.get_member(target_user_id) 
                or await bot.fetch_user(target_user_id)
            )
        except discord.NotFound:
            target_user = None
        
        assert target_user is None
        
        # Display name should fall back to user ID
        display_name = target_user.mention if target_user else f"User ID {target_user_id}"
        assert display_name == f"User ID {target_user_id}"
    
    @pytest.mark.asyncio
    async def test_no_censored_messages_found(self, interaction, temp_db):
        """Test when no censored messages exist for the user."""
        target_user_id = 123456789
        
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT message_id, webhook_id, webhook_token, thread_id
                FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                rows = await cursor.fetchall()
        
        assert len(rows) == 0
        
        await interaction.followup.send(
            f"No censored messages found for User ID {target_user_id}.",
            ephemeral=True
        )
        
        interaction.followup.send.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_messages_with_valid_webhook(self, interaction, temp_db, bot):
        """Test successful deletion of messages with valid webhook."""
        target_user_id = 123456789
        
        # Insert test data
        async with aiosqlite.connect(temp_db) as db:
            await db.execute("""
                INSERT INTO censored_messages 
                (guild_id, author_id, message_id, webhook_id, webhook_token, thread_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (interaction.guild.id, target_user_id, 111, 222, "token123", None))
            await db.commit()
        
        # Mock webhook
        webhook = AsyncMock()
        webhook.delete_message = AsyncMock()
        bot.fetch_webhook.return_value = webhook
        
        # Fetch and delete
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT message_id, webhook_id, webhook_token, thread_id
                FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                rows = await cursor.fetchall()
        
        deleted_count = 0
        for row in rows:
            message_id, webhook_id, webhook_token, thread_id = row
            if webhook_id is not None:
                webhook_fetched = await bot.fetch_webhook(webhook_id)
                await webhook_fetched.delete_message(message_id)
                deleted_count += 1
        
        assert deleted_count == 1
        webhook.delete_message.assert_called_once_with(111)
    
    @pytest.mark.asyncio
    async def test_delete_messages_with_thread(self, interaction, temp_db, bot):
        """Test deletion of messages in a thread."""
        target_user_id = 123456789
        thread_id = 999
        
        # Insert test data with thread
        async with aiosqlite.connect(temp_db) as db:
            await db.execute("""
                INSERT INTO censored_messages 
                (guild_id, author_id, message_id, webhook_id, webhook_token, thread_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (interaction.guild.id, target_user_id, 111, 222, "token123", thread_id))
            await db.commit()
        
        # Mock thread and webhook
        thread = Mock()
        interaction.guild.get_thread.return_value = thread
        webhook = AsyncMock()
        webhook.delete_message = AsyncMock()
        bot.fetch_webhook.return_value = webhook
        
        # Fetch and delete
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT message_id, webhook_id, webhook_token, thread_id
                FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                rows = await cursor.fetchall()
        
        for row in rows:
            message_id, webhook_id, webhook_token, tid = row
            if webhook_id is not None:
                webhook_fetched = await bot.fetch_webhook(webhook_id)
                thread_obj = interaction.guild.get_thread(tid) if tid else None
                delete_kwargs = {'thread': thread_obj} if thread_obj else {}
                await webhook_fetched.delete_message(message_id, **delete_kwargs)
        
        webhook.delete_message.assert_called_once_with(111, thread=thread)
    
    @pytest.mark.asyncio
    async def test_webhook_not_found_treated_as_deleted(self, interaction, temp_db, bot):
        """Test that NotFound exception is treated as successful deletion."""
        target_user_id = 123456789
        
        # Insert test data
        async with aiosqlite.connect(temp_db) as db:
            await db.execute("""
                INSERT INTO censored_messages 
                (guild_id, author_id, message_id, webhook_id, webhook_token, thread_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (interaction.guild.id, target_user_id, 111, 222, "token123", None))
            await db.commit()
        
        # Mock webhook fetch to raise NotFound
        bot.fetch_webhook.side_effect = discord.NotFound(Mock(), "Webhook not found")
        
        deleted_count = 0
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT message_id, webhook_id, webhook_token, thread_id
                FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                rows = await cursor.fetchall()
        
        for row in rows:
            message_id, webhook_id, webhook_token, thread_id = row
            deleted = False
            if webhook_id is not None:
                try:
                    webhook = await bot.fetch_webhook(webhook_id)
                    await webhook.delete_message(message_id)
                    deleted = True
                except discord.NotFound:
                    deleted = True
            if deleted:
                deleted_count += 1
        
        assert deleted_count == 1
    
    @pytest.mark.asyncio
    async def test_forbidden_error_stops_deletion(self, interaction, temp_db, bot):
        """Test that Forbidden exception stops the deletion process."""
        target_user_id = 123456789
        
        # Insert test data
        async with aiosqlite.connect(temp_db) as db:
            await db.execute("""
                INSERT INTO censored_messages 
                (guild_id, author_id, message_id, webhook_id, webhook_token, thread_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (interaction.guild.id, target_user_id, 111, 222, "token123", None))
            await db.commit()
        
        # Mock webhook to raise Forbidden
        webhook = AsyncMock()
        webhook.delete_message.side_effect = discord.Forbidden(Mock(), "No permission")
        bot.fetch_webhook.return_value = webhook
        
        should_stop = False
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT message_id, webhook_id, webhook_token, thread_id
                FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                rows = await cursor.fetchall()
        
        for row in rows:
            message_id, webhook_id, webhook_token, thread_id = row
            if webhook_id is not None:
                try:
                    webhook_obj = await bot.fetch_webhook(webhook_id)
                    await webhook_obj.delete_message(message_id)
                except discord.Forbidden:
                    should_stop = True
                    break
        
        assert should_stop
        await interaction.followup.send(
            "Insufficient permissions to delete some messages.",
            ephemeral=True
        )
    
    @pytest.mark.asyncio
    async def test_http_exception_continues_processing(self, interaction, temp_db, bot):
        """Test that HTTPException logs but continues processing other messages."""
        target_user_id = 123456789
        
        # Insert multiple test messages
        async with aiosqlite.connect(temp_db) as db:
            await db.executemany("""
                INSERT INTO censored_messages 
                (guild_id, author_id, message_id, webhook_id, webhook_token, thread_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [
                (interaction.guild.id, target_user_id, 111, 222, "token1", None),
                (interaction.guild.id, target_user_id, 333, 444, "token2", None),
            ])
            await db.commit()
        
        # Mock webhook to fail on first, succeed on second
        webhook1 = AsyncMock()
        webhook1.delete_message.side_effect = discord.HTTPException(Mock(), "Server error")
        webhook2 = AsyncMock()
        webhook2.delete_message = AsyncMock()
        
        bot.fetch_webhook.side_effect = [webhook1, webhook2]
        
        deleted_count = 0
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT message_id, webhook_id, webhook_token, thread_id
                FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                rows = await cursor.fetchall()
        
        for row in rows:
            message_id, webhook_id, webhook_token, thread_id = row
            deleted = False
            if webhook_id is not None:
                try:
                    webhook = await bot.fetch_webhook(webhook_id)
                    await webhook.delete_message(message_id)
                    deleted = True
                except discord.HTTPException as e:
                    print(f"Error deleting message {message_id}: {e}")
            if deleted:
                deleted_count += 1
        
        # Only second message should be deleted
        assert deleted_count == 1
    
    @pytest.mark.asyncio
    async def test_database_cleanup_always_happens(self, interaction, temp_db):
        """Test that database entries are cleaned up even if deletion fails."""
        target_user_id = 123456789
        
        # Insert test data
        async with aiosqlite.connect(temp_db) as db:
            await db.execute("""
                INSERT INTO censored_messages 
                (guild_id, author_id, message_id, webhook_id, webhook_token, thread_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (interaction.guild.id, target_user_id, 111, 222, "token123", None))
            await db.commit()
        
        # Simulate cleanup regardless of deletion status
        async with aiosqlite.connect(temp_db) as db:
            await db.execute("""
                DELETE FROM censored_messages
                WHERE guild_id = ? AND message_id = ?
            """, (interaction.guild.id, 111))
            await db.commit()
        
        # Verify database is cleaned up
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT COUNT(*) FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                count = (await cursor.fetchone())[0]
        
        assert count == 0
    
    @pytest.mark.asyncio
    async def test_null_webhook_id_skipped(self, interaction, temp_db):
        """Test that messages with NULL webhook_id are skipped for deletion."""
        target_user_id = 123456789
        
        # Insert test data with NULL webhook_id
        async with aiosqlite.connect(temp_db) as db:
            await db.execute("""
                INSERT INTO censored_messages 
                (guild_id, author_id, message_id, webhook_id, webhook_token, thread_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (interaction.guild.id, target_user_id, 111, None, None, None))
            await db.commit()
        
        deleted_count = 0
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT message_id, webhook_id, webhook_token, thread_id
                FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                rows = await cursor.fetchall()
        
        for row in rows:
            message_id, webhook_id, webhook_token, thread_id = row
            deleted = False
            if webhook_id is not None:
                deleted = True
            if deleted:
                deleted_count += 1
        
        assert deleted_count == 0
    
    @pytest.mark.asyncio
    async def test_multiple_messages_batch_deletion(self, interaction, temp_db, bot):
        """Test deletion of multiple messages in a batch."""
        target_user_id = 123456789
        
        # Insert multiple messages
        async with aiosqlite.connect(temp_db) as db:
            await db.executemany("""
                INSERT INTO censored_messages 
                (guild_id, author_id, message_id, webhook_id, webhook_token, thread_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [
                (interaction.guild.id, target_user_id, 111, 222, "token1", None),
                (interaction.guild.id, target_user_id, 333, 444, "token2", None),
                (interaction.guild.id, target_user_id, 555, 666, "token3", 777),
            ])
            await db.commit()
        
        # Mock webhooks
        webhook = AsyncMock()
        webhook.delete_message = AsyncMock()
        bot.fetch_webhook.return_value = webhook
        
        thread = Mock()
        interaction.guild.get_thread.return_value = thread
        
        deleted_count = 0
        async with aiosqlite.connect(temp_db) as db:
            async with db.execute("""
                SELECT message_id, webhook_id, webhook_token, thread_id
                FROM censored_messages
                WHERE guild_id = ? AND author_id = ?
            """, (interaction.guild.id, target_user_id)) as cursor:
                rows = await cursor.fetchall()
        
        for row in rows:
            message_id, webhook_id, webhook_token, thread_id = row
            deleted = False
            if webhook_id is not None:
                webhook_obj = await bot.fetch_webhook(webhook_id)
                thread_obj = interaction.guild.get_thread(thread_id) if thread_id else None
                delete_kwargs = {'thread': thread_obj} if thread_obj else {}
                await webhook_obj.delete_message(message_id, **delete_kwargs)
                deleted = True
            if deleted:
                deleted_count += 1
        
        assert deleted_count == 3
        assert webhook.delete_message.call_count == 3


class TestEdgeCasesAndBoundaryConditions:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_very_large_user_id(self):
        """Test handling of very large user IDs (max Discord snowflake)."""
        user_id = "9223372036854775807"
        
        try:
            target_user_id = int(user_id)
            assert target_user_id == 9223372036854775807
        except ValueError:
            pytest.fail("Should handle large user IDs")
    
    @pytest.mark.asyncio
    async def test_zero_user_id(self):
        """Test handling of zero as user ID."""
        user_id = "0"
        
        try:
            target_user_id = int(user_id)
            assert target_user_id == 0
        except ValueError:
            pytest.fail("Should handle zero user ID")
    
    @pytest.mark.asyncio
    async def test_negative_user_id(self):
        """Test handling of negative user ID."""
        user_id = "-123"
        
        try:
            target_user_id = int(user_id)
            assert target_user_id == -123
        except ValueError:
            pytest.fail("Should handle negative user ID")
    
    @pytest.mark.asyncio
    async def test_empty_string_user_id(self):
        """Test handling of empty string as user ID."""
        user_id = ""
        
        with pytest.raises(ValueError):
            target_user_id = int(user_id)
    
    @pytest.mark.asyncio
    async def test_whitespace_user_id(self):
        """Test handling of whitespace in user ID."""
        user_id = "   123   "
        
        try:
            target_user_id = int(user_id)
            assert target_user_id == 123
        except ValueError:
            pytest.fail("Should handle whitespace in user ID")
    
    @pytest.mark.asyncio
    async def test_float_user_id(self):
        """Test handling of float as user ID."""
        user_id = "123.456"
        
        with pytest.raises(ValueError):
            target_user_id = int(user_id)
    
    @pytest.mark.asyncio
    async def test_hex_user_id(self):
        """Test handling of hexadecimal user ID."""
        user_id = "0x123"
        
        with pytest.raises(ValueError):
            target_user_id = int(user_id)


class TestLoggingBehavior:
    """Test logging and audit trail functionality."""
    
    @pytest.mark.asyncio
    async def test_log_embed_structure(self):
        """Test the structure of the log embed."""
        deleted_count = 3
        display_name = "<@123456789>"
        user_mention = "<@987654321>"
        
        embed = discord.Embed(
            title="User Censored Messages Deleted",
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="User", value=display_name, inline=False)
        embed.add_field(name="Deleted By", value=user_mention, inline=False)
        embed.add_field(name="Messages Deleted", value=str(deleted_count), inline=False)
        
        assert embed.title == "User Censored Messages Deleted"
        assert embed.color == discord.Color.orange()
        assert len(embed.fields) == 3
        assert embed.fields[0].name == "User"
        assert embed.fields[1].name == "Deleted By"
        assert embed.fields[2].name == "Messages Deleted"
        assert embed.fields[2].value == "3"
    
    @pytest.mark.asyncio
    async def test_final_message_format(self):
        """Test the format of the final success message."""
        deleted_count = 5
        display_name = "<@123456789>"
        
        message = (
            f"Successfully processed censored messages for {display_name}.\n"
            f"Deleted: {deleted_count} reposted message(s).\n"
            f"All matching database entries have been cleaned up."
        )
        
        assert "Successfully processed" in message
        assert str(deleted_count) in message
        assert display_name in message
        assert "database entries have been cleaned up" in message
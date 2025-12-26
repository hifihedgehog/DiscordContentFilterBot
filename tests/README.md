# Test Suite for Discord Content Filter Bot

This directory contains comprehensive unit tests for the Discord Content Filter Bot, specifically focusing on changes to the `content_filter.py` file between the current branch and main.

## Changes Tested

The test suite validates improvements made in the current branch:

### `on_app_command_error` (lines 126-142)
**Improvements:**
1. Single content string assignment based on error type
2. Check if `interaction.response.is_done()` before sending
3. Use `followup.send()` if already responded, else `response.send_message()`
4. Wrapped in try-except to silently handle send failures
5. Traceback printing for non-CheckFailure errors

### `delete_user_censored_messages` (lines 3492-3605)
**Improvements:**
1. Input validation preventing both user and user_id being provided
2. Safe user_id to int conversion with ValueError handling
3. Graceful handling of deleted/unknown users via try-except NotFound
4. NULL webhook_id check before attempting deletion
5. Thread object only fetched if thread_id is not None
6. delete_kwargs only includes thread if successfully fetched
7. NotFound treated as successful deletion
8. Database cleanup always happens regardless of deletion result
9. Enhanced final message with detailed information

## Test Coverage

### TestOnAppCommandError (8 tests)
Tests for the global error handler covering:
- **CheckFailure errors**: Tests both responded and non-responded states
- **Generic errors**: Tests proper error message selection
- **Exception handling**: Verifies silent exception catching
- **Response state**: Ensures proper use of `interaction.response` vs `interaction.followup`
- **Error type differentiation**: Validates correct message per error type

### TestDeleteUserCensoredMessages (18 tests)
Comprehensive tests for message deletion function:

**Input Validation:**
- Both user and user_id provided (should error)
- Neither provided (should error)
- Invalid user_id format (non-numeric)
- Valid user_id conversion
- User object ID extraction

**User Lookup:**
- Graceful NotFound handling
- Fallback display names
- Member vs User object handling

**Database Operations:**
- Fetching censored messages
- Empty result sets
- Database cleanup
- Batch processing

**Webhook Operations:**
- Successful deletion with valid webhook
- Message deletion with thread context
- NotFound treated as success
- Forbidden stops process
- HTTPException continues to next
- NULL webhook_id skipped

**Thread Handling:**
- Thread fetching when thread_id present
- Skipping when thread_id is None
- Conditional kwargs building

### TestEdgeCasesAndBoundaryConditions (7 tests)
Edge cases including:
- Very large user IDs (max Discord snowflake: 9223372036854775807)
- Zero user ID
- Negative user IDs
- Empty string (raises ValueError)
- Whitespace handling (auto-stripped)
- Float format (raises ValueError)
- Hexadecimal format (raises ValueError)

### TestLoggingBehavior (2 tests)
Audit logging tests:
- Log embed structure validation
- Final success message format

## Running Tests

### Install Dependencies
```bash
pip install -r tests/requirements-test.txt
```

### Run All Tests (35 total)
```bash
pytest
```

### Run Specific Test Class
```bash
pytest tests/test_content_filter.py::TestOnAppCommandError -v
pytest tests/test_content_filter.py::TestDeleteUserCensoredMessages -v
pytest tests/test_content_filter.py::TestEdgeCasesAndBoundaryConditions -v
pytest tests/test_content_filter.py::TestLoggingBehavior -v
```

### Run with Coverage Report
```bash
pytest --cov=. --cov-report=html --cov-report=term
```

### Run Specific Test
```bash
pytest tests/test_content_filter.py::TestDeleteUserCensoredMessages::test_invalid_user_id_format -v
```

### Run with Verbose Output
```bash
pytest -vv
```

### Run Only Failed Tests
```bash
pytest --lf
```

## Test Structure

All tests follow the AAA (Arrange-Act-Assert) pattern:
- **Arrange**: Set up mocks, fixtures, and test data
- **Act**: Execute the function/code under test
- **Assert**: Verify expected behavior

## Mocking Strategy

- **Discord objects**: `unittest.mock.AsyncMock` and `Mock`
- **Async operations**: `AsyncMock` for async/await support
- **Database**: Temporary SQLite files for isolation
- **External APIs**: Mocked to avoid network calls
- **Fixtures**: Reusable mock objects via pytest fixtures

## Key Testing Principles

1. **Isolation**: Each test is completely independent
2. **Descriptive Names**: Test names clearly describe scenarios
3. **Comprehensive Coverage**: Happy paths, edge cases, and errors
4. **Async Support**: Proper `pytest-asyncio` usage
5. **Resource Cleanup**: Fixtures clean up temp resources
6. **Mock Verification**: Verify correct method calls
7. **Edge Case Testing**: Extensive boundary conditions
8. **Error Path Testing**: All error conditions covered

## CI/CD Ready

These tests are designed for CI/CD integration:
- Fast execution (in-memory mocking)
- No external dependencies
- Clean setup/teardown
- Clear pass/fail indicators
- Standard pytest compatibility

## Example Test Output
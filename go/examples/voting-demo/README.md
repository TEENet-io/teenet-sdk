# Voting Demo - App-Comm-Consensus SDK

A simple web application demonstrating Mode 1 passive voting with the app-comm-consensus SDK.

## Overview

This application showcases how multiple independent app instances can participate in distributed voting for message signing. Each instance represents a single voter, and when the voting threshold is reached, participants can obtain the final signature through SDK polling.

## Architecture

- **Deployment Model**: Multi-instance (each instance = one voter)
- **Voting Mode**: Mode 1 - Passive Voting
- **Tech Stack**: Go + Gin + Vanilla JavaScript

### How It Works

```
Instance 1 (voter1_app_id:8081)
    ↓ Vote submitted (1/2)
    ↓
Consensus Server (collects votes)
    ↑
Instance 2 (voter2_app_id:8082)
    ↑ Vote submitted (2/2 - threshold met!)
    ↓
Both instances can query/fetch the final signature
```

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Running app-comm-consensus server
- Multiple APP_IDs for testing (configured on consensus server)

### Installation

```bash
cd app-comm-consensus/sdk/example/voting-demo
go mod tidy
```

### Running Multiple Instances

#### Instance 1 (Port 8081)
```bash
APP_ID="f5a8f44238cd6112b9f02f7f63a12533" \
PORT="8081" \
CONSENSUS_URL="http://localhost:8089" \
go run .
```

#### Instance 2 (Port 8082)
```bash
APP_ID="3d8eabdab6bb5a4df0472e52afc46985" \
PORT="8082" \
CONSENSUS_URL="http://localhost:8089" \
go run .
```

#### Instance 3 (Port 8083) - Optional
```bash
APP_ID="6c09bbe17bc38a86b22d348f89f4e0b8" \
PORT="8083" \
CONSENSUS_URL="http://localhost:8089" \
go run .
```

### Testing the Voting Flow

1. **Open Instance 1**: Navigate to `http://localhost:8081`
   - Enter message: "Hello, TEENet!"
   - Click "提交我的投票" (Submit My Vote)
   - Status: "已投票 1/2" (Voted 1/2)
   - Message: "等待其他投票者..." (Waiting for other voters...)

2. **Open Instance 2**: Navigate to `http://localhost:8082`
   - Enter the **same message**: "Hello, TEENet!"
   - Click "提交我的投票"
   - Status: "已投票 2/2" (Voted 2/2)

3. **Result**: Both browser tabs will display the signature!
   - Instance 1: Shows signature (after polling returns signed)
   - Instance 2: Shows signature (immediate response)

## Environment Variables

### Required
- `APP_ID`: Unique identifier for this app instance
- `CONSENSUS_URL`: URL of the consensus server

### Optional
- `PORT`: HTTP server port (default: 8080)

## Building

### Build Binary
```bash
go build -o voting-demo .
```

### Run Binary
```bash
APP_ID="f5a8f44238cd6112b9f02f7f63a12533" PORT="8081" ./voting-demo
```

## API Endpoints

### GET /api/config
Get current instance configuration

**Response:**
```json
{
  "app_id": "f5a8f44238cd6112b9f02f7f63a12533",
  "consensus_url": "http://localhost:8089"
}
```

### POST /api/vote
Submit vote for message signing

**Request:**
```json
{
  "message": "Hello, TEENet!"
}
```

**Response:**
```json
{
  "success": true,
  "app_id": "f5a8f44238cd6112b9f02f7f63a12533",
  "message": "Vote submitted successfully",
  "voting_info": {
    "needs_voting": true,
    "current_votes": 1,
    "required_votes": 2,
    "status": "pending",
    "hash": "0x1234..."
  },
  "signature": "a7b3..." // Only present when threshold is met
}
```

### GET /api/health
Health check

**Response:**
```json
{
  "status": "healthy",
  "service": "Voting Demo App",
  "app_id": "f5a8f44238cd6112b9f02f7f63a12533"
}
```

### POST /api/apikey/get
Retrieve an API key by name (requires API key to be bound to application)

**Request:**
```json
{
  "name": "test"
}
```

**Response:**
```json
{
  "success": true,
  "name": "test",
  "api_key": "sk_abc123..."
}
```

**Error Response:**
```json
{
  "success": false,
  "name": "test",
  "error": "No API keys are accessible for this application"
}
```

### POST /api/apikey/sign
Sign a message using an API secret (requires API secret to be bound to application)

**Request:**
```json
{
  "name": "test",
  "message": "Hello, TEENet!"
}
```

**Response:**
```json
{
  "success": true,
  "name": "test",
  "message": "Hello, TEENet!",
  "signature": "a7b3c4d5...",
  "algorithm": "HMAC-SHA256",
  "message_length": 15
}
```

**Error Response:**
```json
{
  "success": false,
  "name": "test",
  "message": "Hello, TEENet!",
  "error": "No API keys are accessible for this application"
}
```

## Project Structure

```
voting-demo/
├── main.go                 # Backend server (Gin)
├── types.go                # Request/response types
├── frontend/
│   ├── index.html         # Web UI
│   ├── app.js             # Frontend logic
│   └── styles.css         # Styling
├── go.mod                 # Go dependencies
└── README.md              # This file
```

## Features

- ✅ **Single Vote Button**: Each instance has one button representing itself
- ✅ **Real-time Status**: Display app status and voting progress
- ✅ **Polling-Based Completion**: SDK waits/polls until signature is finalized
- ✅ **API Key Operations**: Retrieve API keys and sign with API secrets
- ✅ **Responsive UI**: Clean, mobile-friendly interface
- ✅ **Error Handling**: Clear error messages and validation
- ✅ **Copy Signature**: One-click signature copying

## Testing Scenarios

### Scenario 1: Basic 2-of-3 Voting
1. Start 3 instances
2. Vote on instance 1 → See "1/2 votes"
3. Vote on instance 2 → Both show signature
4. Vote on instance 3 → Immediately shows signature

### Scenario 2: Different Messages
1. Vote on instance 1 with "Message A"
2. Vote on instance 2 with "Message B"
3. Result: No signature (different message hashes)

### Scenario 3: Timeout Test
1. Start 2 instances
2. Vote on instance 1
3. Wait for timeout → Shows timeout error

### Scenario 4: API Key Access Control
1. Create two API keys in user management system: "test" and "test2"
2. Bind only "test" to your application
3. Try to retrieve "test" → Success (API key is returned)
4. Try to retrieve "test2" → Failure (access denied - not bound)
5. Try to sign with "test" → Success (signature is returned)
6. Try to sign with "test2" → Failure (access denied - not bound)

## Troubleshooting

### Issue: "APP_ID environment variable is required"
**Solution**: Set the `APP_ID` environment variable before starting

### Issue: "Connection refused" or timeout
**Solution**:
- Ensure consensus server is running
- Check `CONSENSUS_URL` is correct
- Verify network connectivity

### Issue: Vote submitted but no signature
**Solution**:
- Check voting threshold (need enough votes)
- Ensure all voters use the **same message**
- Check consensus server logs

### Issue: Different messages on different instances
**Solution**:
- Message content must be **exactly the same**
- Copy-paste to ensure consistency
- Message hash is used for matching votes

### Issue: "No API keys are accessible for this application"
**Solution**:
- Verify API key exists in user management system
- Check that API key is bound to your application in the application settings
- Ensure API key name matches exactly (case-sensitive)
- For GetAPIKey: verify API key has an API key stored (not just secret)
- For SignWithAPISecret: verify API key has an API secret stored (not just key)

## Development

### Adding Features
1. Modify `types.go` for new request/response types
2. Add handler in `main.go`
3. Update frontend in `frontend/` directory

### Debugging
- Check browser console for JavaScript errors
- Check server logs for backend errors
- Use `/api/health` to verify server status

## Integration with App-Comm-Consensus

This demo uses the app-comm-consensus SDK's `Sign()` method, which:
1. Submits vote request to consensus server
2. Polls voting status while pending
3. Returns signature when threshold met (or timeout/failed)

The consensus server:
- Collects votes from multiple app instances
- Tracks voting progress
- Triggers signing when threshold reached

## License

Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.

## Support

For issues or questions:
- Check the SDK documentation
- Review consensus server logs
- Ensure all instances use compatible APP_IDs

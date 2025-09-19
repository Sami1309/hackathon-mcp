# PatchPilot Security Management System

A Flask web application for vulnerability management and penetration testing using NodeZero MCP, Apify, Claude AI, and Redis Cloud.

## Overview

PatchPilot implements a Find-Fix-Verify (FFV) security cycle that:

1. **Find**: Scrapes web vulnerabilities using Apify
2. **Fix**: Uses Claude AI to correlate vulnerabilities with support tickets
3. **Verify**: Launches penetration tests via NodeZero MCP integration

## Architecture

- **Frontend**: Bootstrap 5 with vanilla JavaScript
- **Backend**: Flask with Python 3.13
- **AI Integration**: Claude Messages API with MCP support
- **Web Scraping**: Apify MCP server
- **Penetration Testing**: NodeZero MCP server
- **Vector Database**: Redis Cloud for ticket similarity search

## Setup

### Prerequisites

- Python 3.13+
- NodeZero API account
- Apify API account
- Claude API account
- Redis Cloud instance

### Installation

1. Clone the repository
2. Create virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install flask anthropic redis python-dotenv requests
   ```

4. Create `.env.local` file:
   ```
   APIFY_API_KEY=your_apify_key
   ANTHROPIC_API_KEY=your_claude_key
   NODEZERO_API_KEY=your_nodezero_key
   REDIS_HOST=your_redis_host
   REDIS_PORT=your_redis_port
   REDIS_PASSWORD=your_redis_password
   ```

### Running

Start the application:
```bash
source venv/bin/activate
python app.py
```

Access at `http://localhost:5001`

## Features

### Vulnerability Intelligence
- Web scraping for security vulnerabilities
- Support ticket vector database
- AI-powered correlation and prioritization

### Dashboard
- System overview with metrics
- Recent activity monitoring
- Quick navigation

### Penetration Testing
- AI-generated test scenarios
- Real-time progress tracking
- Log viewing and reporting

### Reports
- Vulnerability assessments
- Penetration test results
- Executive summaries

## Usage

1. **Scrape Vulnerabilities**: Use the first tab to collect security data from web sources
2. **Create Vector Database**: Build searchable database of support tickets
3. **AI Analysis**: Let Claude correlate vulnerabilities with tickets and prioritize targets
4. **Launch Pentests**: Start penetration tests on priority targets
5. **Monitor Progress**: Track test execution and view logs
6. **Generate Reports**: Export findings and recommendations

## Configuration

### Redis Connection
The application connects to Redis Cloud without SSL due to connection issues. See `REDIS_FIX.md` for troubleshooting.

### MCP Servers
- NodeZero MCP: Handles penetration testing operations
- Apify MCP: Manages web scraping tasks

## Development

The application uses Flask's debug mode for development. File changes trigger automatic reloads.

Key files:
- `app.py`: Main Flask application
- `templates/`: HTML templates
- `static/`: CSS and JavaScript files
- `.env.local`: Environment variables
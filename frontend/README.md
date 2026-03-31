# Honeypot Dashboard - Frontend

A modern React dashboard for monitoring honeypot security events in real-time.

## Features

- **Real-time Statistics**: Monitor total connections, unique attackers, captured credentials, and more
- **Protocol Analysis**: View connection counts by honeypot protocol
- **Threat Intelligence**: Top attacker IPs visualization
- **Activity Timeline**: 24-hour activity trends
- **Detailed Logs**: Recent connections and captured credentials tables
- **Dark Theme**: Professional dark UI optimized for security operations centers

## Project Structure

```
frontend/
├── public/
│   └── index.html          # Main HTML file
├── src/
│   ├── components/
│   │   ├── Dashboard.js      # Main dashboard component
│   │   ├── StatsSection.js   # Statistics cards
│   │   ├── ChartsSection.js  # Charts and visualizations
│   │   ├── ConnectionsTable.js # Connections table
│   │   └── CredentialsTable.js # Credentials table
│   ├── App.js              # Main app component
│   ├── App.css             # Styles
│   ├── index.js            # React entry point
│   └── index.css           # Global styles
├── .env                    # Environment variables
├── package.json            # Dependencies
└── README.md              # This file
```

## Installation

### Prerequisites
- Node.js 14+ and npm

### Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Make sure the Flask backend is running on `http://localhost:5000`

## Development

Start the development server:

```bash
npm start
```

The dashboard will open at `http://localhost:3000`

The app will automatically connect to the Flask backend API and display real-time data.

## Build for Production

Build the optimized production bundle:

```bash
npm run build
```

This creates a `build/` folder with static files that can be served by the Flask backend.

## API Endpoints

The dashboard expects these endpoints from the Flask backend:

- `GET /api/stats` - Summary statistics
- `GET /api/protocol-stats` - Connections by protocol
- `GET /api/top-ips` - Top attacker IPs
- `GET /api/timeline` - Activity timeline (24 hours)
- `GET /api/connections` - Recent connections (paginated)
- `GET /api/credentials` - Captured credentials (paginated)

## Configuration

Environment variables in `.env`:

- `REACT_APP_API_URL` - Base URL for the backend API (default: `http://localhost:5000/api`)

## Technologies Used

- **React 18** - UI framework
- **CSS3** - Styling with modern gradients and animations
- **Fetch API** - Data fetching
- **dev21** - Custom components library (optional)

## License

MIT

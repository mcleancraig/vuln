const express = require('express');
const mariadb = require('mariadb');
const session = require('express-session');
const { ConfidentialClientApplication } = require('@azure/msal-node');

const app = express();
const port = 3000;

// MSAL configuration
const msalConfig = {
    auth: {
        clientId: process.env.CLIENT_ID || 'YOUR_CLIENT_ID',
        clientSecret: process.env.CLIENT_SECRET || 'YOUR_CLIENT_SECRET',
        authority: `https://login.microsoftonline.com/${process.env.TENANT_ID || 'YOUR_TENANT_ID'}`
    },
    system: {
        loggerOptions: {
            loggerCallback(loglevel, message, containsPii) {
                console.log(message);
            },
            piiLoggingEnabled: false,
            logLevel: 'Info',
        }
    }
};

// Create MSAL instance
const cca = new ConfidentialClientApplication(msalConfig);

// Database connection pool
const pool = mariadb.createPool({
    host: process.env.DB_HOST || 'vip.lan.candi-home.com',
    user: process.env.DB_USER || 'vuln',
    password: process.env.DB_PASSWORD || 'vuln',
    database: process.env.DB_NAME || 'vulntest'
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secure-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true in production with HTTPS
}));

// Authentication middleware
function ensureAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/auth/login');
}

// Routes
app.get('/', ensureAuthenticated, (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Lookup</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .user-info { background-color: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .search-button { background-color: #0078d4; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
                .search-button:hover { background-color: #106ebe; }
                .logout-link { float: right; color: #0078d4; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="user-info">
                <a href="/auth/logout" class="logout-link">Logout</a>
                <h2>Welcome, ${req.session.user.name || 'User'}</h2>
                <p><strong>Email:</strong> ${req.session.user.username}</p>
            </div>
            
            <h2>Find Vulnerabilities</h2>
            <p>Click the button below to search for vulnerabilities associated with your account:</p>
            <form action="/search" method="post">
                <button type="submit" class="search-button">Search My Vulnerabilities</button>
            </form>
        </body>
        </html>
    `);
});

// Login route
app.get('/auth/login', (req, res) => {
    // Generate authentication URL
    const authCodeUrlParameters = {
        scopes: ['openid', 'profile', 'email'],
        redirectUri: 'https://vuln.candi-home.com/auth/callback',
    };

    cca.getAuthCodeUrl(authCodeUrlParameters).then((response) => {
        res.redirect(response);
    }).catch((error) => {
        console.error('Error generating auth URL:', error);
        res.status(500).send('Error initiating authentication');
    });
});

// Callback route
app.get('/auth/callback', (req, res) => {
    const tokenRequest = {
        code: req.query.code,
        scopes: ['openid', 'profile', 'email'],
        redirectUri: 'https://vuln.candi-home.com/auth/callback',
    };

    cca.acquireTokenByCode(tokenRequest).then((response) => {
        // Store user info in session
        req.session.user = {
            username: response.account.username,
            name: response.account.name,
            homeAccountId: response.account.homeAccountId
        };
        res.redirect('/');
    }).catch((error) => {
        console.error('Token acquisition error:', error);
        res.status(500).send('Authentication failed');
    });
});

// Logout route
app.get('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction error:', err);
        }
        res.redirect('/');
    });
});

// Search route
app.post('/search', ensureAuthenticated, async (req, res) => {
    const email = req.session.user.username;
    
    if (!email) {
        res.send('<h2>Error: Could not retrieve email from your account</h2><a href="/">Go back</a>');
        return;
    }

    const username = email.split('@')[0];
    let conn;
    try {
        conn = await pool.getConnection();
        
        // Find the hostname from the 'users' table
        const userRows = await conn.query("SELECT host FROM users WHERE user = ?", [username]);
        
        if (userRows.length === 0) {
            res.send(`<h2>No hostname found for the email: ${email}</h2><a href="/">Go back</a>`);
            return;
        }
        
        const hostname = userRows[0].host;
        
        // Find vulnerabilities using partial matching
        const vulnerabilities = await conn.query("SELECT * FROM vulnerabilities WHERE hostname LIKE ?", [`%${hostname}%`]);
        
        let html = `<h2>Vulnerabilities for hostnames containing "${hostname}"</h2>`;
        html += `<p><strong>Searched for user:</strong> ${email}</p>`;
        html += '<a href="/" style="margin-bottom: 20px; display: inline-block;">← Back to Search</a>';
        
        if (vulnerabilities.length > 0) {
            // Store results in session for CSV download
            req.session.lastResults = vulnerabilities;
            req.session.lastHostname = hostname;
            
            html += '<div style="margin-bottom: 20px;">';
            html += '<a href="/download-csv" style="background-color: #28a745; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; margin-right: 10px;">📥 Download CSV</a>';
            html += '</div>';
            html += '<table border="1" style="width:100%; border-collapse: collapse;"><tr>';
            
            // Create table headers
            for (const column in vulnerabilities[0]) {
                html += `<th style="padding: 8px; border: 1px solid #ddd; background-color: #f2f2f2;">${column}</th>`;
            }
            html += '</tr>';
            
            // Add table rows
            vulnerabilities.forEach(row => {
                html += '<tr>';
                for (const column in row) {
                    html += `<td style="padding: 8px; border: 1px solid #ddd;">${row[column]}</td>`;
                }
                html += '</tr>';
            });
            html += '</table>';
        } else {
            html += `<p>No vulnerabilities found for hostnames containing: <strong>${hostname}</strong></p>`;
        }
        
        res.send(html);
    } catch (err) {
        console.error(err);
        res.status(500).send("An error occurred while communicating with the database.");
    } finally {
        if (conn) conn.release();
    }
});

// CSV download route
app.get('/download-csv', ensureAuthenticated, (req, res) => {
    const results = req.session.lastResults;
    const hostname = req.session.lastHostname;
    
    if (!results || results.length === 0) {
        res.send('<h2>No results to download</h2><a href="/">Go back</a>');
        return;
    }
    
    // Generate CSV content
    const headers = Object.keys(results[0]);
    let csvContent = headers.join(',') + '\n';
    
    results.forEach(row => {
        const values = headers.map(header => {
            const value = row[header];
            // Escape quotes and wrap in quotes if contains comma, quote, or newline
            if (value === null || value === undefined) {
                return '';
            }
            const stringValue = String(value);
            if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
                return '"' + stringValue.replace(/"/g, '""') + '"';
            }
            return stringValue;
        });
        csvContent += values.join(',') + '\n';
    });
    
    // Set headers for file download
    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
    const filename = `vulnerabilities_${hostname}_${timestamp}.csv`;
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

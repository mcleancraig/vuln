const express = require('express');
const mariadb = require('mariadb');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const crypto = require('crypto');
const { ConfidentialClientApplication } = require('@azure/msal-node');
const { execSync } = require('child_process');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Get git version information
let gitVersion = process.env.GIT_VERSION || process.env.GIT_COMMIT?.substring(0, 7) || 'unknown';

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for simplicity
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // Limit auth attempts
    message: 'Too many authentication attempts, please try again later.',
});

// Input validation functions
function validateEmail(email) {
    return validator.isEmail(email) && email.length <= 255;
}

function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) {
        return '';
    }
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Validate environment variables
const requiredEnvVars = ['TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET', 'SESSION_SECRET'];
for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

// MSAL configuration
const msalConfig = {
    auth: {
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}`
    },
    system: {
        loggerOptions: {
            loggerCallback(loglevel, message, containsPii) {
                if (!containsPii) {
                    console.log(message);
                }
            },
            piiLoggingEnabled: false,
            logLevel: 'Error', // Reduce logging in production
        }
    }
};

// Create MSAL instance
const cca = new ConfidentialClientApplication(msalConfig);

// Database connection pool with better error handling
const pool = mariadb.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    acquireTimeout: 60000,
    timeout: 60000,
    reconnect: true
});

// Test database connection
async function testDbConnection() {
    try {
        const conn = await pool.getConnection();
        await conn.query('SELECT 1');
        conn.release();
        console.log('Database connection successful');
    } catch (err) {
        console.error('Database connection failed:', err.message);
        process.exit(1);
    }
}
testDbConnection();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
    name: 'sessionId' // Don't use default session name
}));

// Routes
function ensureAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/auth/login');
}

// CSRF protection middleware (simple implementation)
function csrfProtection(req, res, next) {
    if (req.method === 'POST') {
        const token = req.body.csrf_token;
        const sessionToken = req.session.csrf_token;
        
        if (!token || !sessionToken || token !== sessionToken) {
            return res.status(403).send('CSRF token mismatch');
        }
    }
    next();
}

// Generate version footer HTML
function getVersionFooter() {
    return `
        <footer style="margin-top: 40px; padding: 20px 0; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px;">
            <p>Version: ${escapeHtml(gitVersion)}</p>
        </footer>
    `;
}

// Generate CSRF token
function generateCsrfToken(req) {
    if (!req.session.csrf_token) {
        req.session.csrf_token = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrf_token;
}
app.get('/', ensureAuthenticated, (req, res) => {
    const csrfToken = generateCsrfToken(req);
    const userName = escapeHtml(req.session.user.name || 'User');
    const userEmail = escapeHtml(req.session.user.username);
    
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
                <h2>Welcome, ${userName}</h2>
                <p><strong>Email:</strong> ${userEmail}</p>
            </div>
            
            <h2>Find Vulnerabilities</h2>
            <p>Click the button below to search for vulnerabilities associated with your account:</p>
            <form action="/search" method="post">
                <input type="hidden" name="csrf_token" value="${csrfToken}">
                <button type="submit" class="search-button">Search My Vulnerabilities</button>
            </form>
            ${getVersionFooter()}
        </body>
        </html>
    `);
});

// Login route
app.get('/auth/login', authLimiter, (req, res) => {
    const authCodeUrlParameters = {
        scopes: ['openid', 'profile', 'email'],
        redirectUri: `${process.env.BASE_URL || 'https://vuln.candi-home.com'}/auth/callback`,
    };

    cca.getAuthCodeUrl(authCodeUrlParameters).then((response) => {
        res.redirect(response);
    }).catch((error) => {
        console.error('Auth URL generation failed');
        res.status(500).send('Authentication service temporarily unavailable');
    });
});

// Callback route
app.get('/auth/callback', authLimiter, (req, res) => {
    const tokenRequest = {
        code: req.query.code,
        scopes: ['openid', 'profile', 'email'],
        redirectUri: `${process.env.BASE_URL || 'https://vuln.candi-home.com'}/auth/callback`,
    };

    cca.acquireTokenByCode(tokenRequest).then((response) => {
        // Validate email
        if (!validateEmail(response.account.username)) {
            return res.status(400).send('Invalid email format');
        }

        // Regenerate session ID to prevent session fixation
        req.session.regenerate((err) => {
            if (err) {
                console.error('Session regeneration failed');
                return res.status(500).send('Authentication failed');
            }

            // Store user info in session
            req.session.user = {
                username: response.account.username,
                name: response.account.name,
                homeAccountId: response.account.homeAccountId
            };
            res.redirect('/');
        });
    }).catch((error) => {
        console.error('Token acquisition failed');
        res.status(500).send('Authentication failed');
    });
});

// Logout route
app.get('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction failed');
        }
        res.redirect('/');
    });
});

// Search route
app.post('/search', ensureAuthenticated, csrfProtection, async (req, res) => {
    const email = req.session.user.username;
    
    if (!validateEmail(email)) {
        return res.status(400).send('<h2>Invalid email format</h2><a href="/">Go back</a>');
    }

    const username = email.split('@')[0];
    
    // Additional validation for username
    if (username.length > 64 || !/^[a-zA-Z0-9._-]+$/.test(username)) {
        return res.status(400).send('<h2>Invalid username format</h2><a href="/">Go back</a>');
    }

    let conn;
    try {
        conn = await pool.getConnection();
        
        // Find all hostnames from the 'users' table
        const userRows = await conn.query("SELECT host FROM users WHERE user = ?", [username]);
        
        if (userRows.length === 0) {
            const safeEmail = escapeHtml(email);
            res.send(`<h2>No hostname found for the email: ${safeEmail}</h2><a href="/">Go back</a>`);
            return;
        }
        
        // Extract and validate all hostnames
        const hostnames = userRows.map(row => row.host).filter(hostname => {
            return hostname && hostname.length <= 255;
        });
        
        if (hostnames.length === 0) {
            res.send('<h2>No valid hostname data found</h2><a href="/">Go back</a>');
            return;
        }
        
        // Find vulnerabilities for all hostnames using partial matching with limit
        let allVulnerabilities = [];
        const hostnameConditions = hostnames.map(() => "hostname LIKE ?");
        const hostnameParams = hostnames.map(hostname => `%${hostname}%`);
        
        const vulnerabilities = await conn.query(
            `SELECT * FROM vulnerabilities WHERE ${hostnameConditions.join(' OR ')} LIMIT 1000`, 
            hostnameParams
        );
        
        const safeHostnames = hostnames.map(h => escapeHtml(h)).join(', ');
        const safeEmail = escapeHtml(email);
        
        let html = `<h2>Vulnerabilities for hostnames containing: ${safeHostnames}</h2>`;
        html += `<p><strong>Searched for user:</strong> ${safeEmail}</p>`;
        html += `<p><strong>Total hostnames found:</strong> ${hostnames.length}</p>`;
        html += '<a href="/" style="margin-bottom: 20px; display: inline-block;">← Back to Search</a>';
        
        if (vulnerabilities.length > 0) {
            // Store results in session for CSV download
            req.session.lastResults = vulnerabilities;
            req.session.lastHostnames = hostnames;
            
            html += '<div style="margin-bottom: 20px;">';
            html += '<a href="/download-csv" style="background-color: #28a745; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; margin-right: 10px;">📥 Download CSV</a>';
            html += '</div>';
            
            html += '<table border="1" style="width:100%; border-collapse: collapse;"><tr>';
            
            // Create table headers with escaping
            for (const column in vulnerabilities[0]) {
                html += `<th style="padding: 8px; border: 1px solid #ddd; background-color: #f2f2f2;">${escapeHtml(column)}</th>`;
            }
            html += '</tr>';
            
            // Add table rows with proper escaping
            vulnerabilities.forEach(row => {
                html += '<tr>';
                for (const column in row) {
                    html += `<td style="padding: 8px; border: 1px solid #ddd;">${escapeHtml(row[column])}</td>`;
                }
                html += '</tr>';
            });
            html += '</table>';
        } else {
            html += `<p>No vulnerabilities found for hostnames: <strong>${safeHostnames}</strong></p>`;
        }
        
        html += getVersionFooter();
        
        res.send(html);
    } catch (err) {
        console.error('Database query failed');
        res.status(500).send("Database service temporarily unavailable.");
    } finally {
        if (conn) conn.release();
    }
});

// CSV download route
app.get('/download-csv', ensureAuthenticated, (req, res) => {
    const results = req.session.lastResults;
    const hostnames = req.session.lastHostnames;
    
    if (!results || results.length === 0) {
        res.send('<h2>No results to download</h2><a href="/">Go back</a>');
        return;
    }
    
    // Generate CSV content with proper escaping
    const headers = Object.keys(results[0]);
    let csvContent = headers.map(h => `"${h.replace(/"/g, '""')}"`).join(',') + '\n';
    
    results.forEach(row => {
        const values = headers.map(header => {
            const value = row[header];
            if (value === null || value === undefined) {
                return '';
            }
            const stringValue = String(value);
            return '"' + stringValue.replace(/"/g, '""') + '"';
        });
        csvContent += values.join(',') + '\n';
    });
    
    // Set headers for file download
    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
    const safeHostnames = hostnames.map(h => h.replace(/[^a-zA-Z0-9._-]/g, '_')).join('_');
    const filename = `vulnerabilities_${safeHostnames}_${timestamp}.csv`;
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error.message);
    res.status(500).send('Internal server error');
});

// Handle 404
app.use((req, res) => {
    res.status(404).send('Page not found');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

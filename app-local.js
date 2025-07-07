const express = require('express');
const mariadb = require('mariadb');
const app = express();
const port = 3001;
// Database connection pool
const pool = mariadb.createPool({
    host: 'vip.lan.candi-home.com',
    user: 'vuln',
    password: 'vuln',
    database: 'vulntest'
});
app.use(express.urlencoded({ extended: true })); // To parse form data
// Serve the HTML form
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});
// Handle the form submission with the updated two-step lookup logic
app.post('/search', async (req, res) => {
    const email = req.body.email;
    const username = email.split('@')[0];
    let conn;
    try {
        conn = await pool.getConnection();
        // 1. Find the hostname from the 'users' table using the email
        const userRows = await conn.query("SELECT host FROM users WHERE user = ?", [username]);
        // Handle case where the email is not found
        if (userRows.length === 0) {
            res.send(`<h2>No hostname found for the email: ${email}</h2>`);
            return;
        }
        const hostname = userRows[0].host;
        // 2. Find all vulnerabilities for the retrieved hostname using partial matching
        const vulnerabilities = await conn.query("SELECT * FROM vulnerabilities WHERE hostname LIKE ?", [`%${hostname}%`]);
        let html = `<h2>Vulnerabilities for hostnames containing "${hostname}"</h2>`;
        if (vulnerabilities.length > 0) {
            html += '<table border="1" style="width:100%; border-collapse: collapse;"><tr>';
            // Create table headers from column names
            for (const column in vulnerabilities[0]) {
                html += `<th style="padding: 8px; border: 1px solid #ddd; background-color: #f2f2f2;">${column}</th>`;
            }
            html += '</tr>';
            // Add table rows with data
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
        console.error(err); // Log the full error to the server console for debugging
        res.status(500).send("An error occurred while communicating with the database.");
    } finally {
        if (conn) conn.release(); // Important: Release the connection back to the pool
    }
});
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

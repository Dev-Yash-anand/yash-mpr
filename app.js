const express = require('express');
const multer = require('multer');
const xlsx = require('xlsx');
const nodemailer = require('nodemailer');
const path = require('path');
const app = express();
const dotenv = require('dotenv');
const User = require('./model/user.model.js');
const session = require('express-session');
const db = require('./config/db');
dotenv.config();
const rateLimit = require('express-rate-limit');

// Rate limiter for email sending
const emailRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each user to 10 requests per windowMs
    message: 'Too many requests from this IP, please try again after 15 minutes.',
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false,  // Disable the `X-RateLimit-*` headers
});

app.use(
    session({
        secret: process.env.SESSION_SECRET, 
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 24 * 60 * 60 * 1000 }, // Session duration (1 day)
    })
);

app.use(express.static(path.join(__dirname, 'public')));

var notsentemails = [];

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});


const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024,  // 5MB limit for each file
    },
    fileFilter: (req, file, cb) => {
        const fileType = file.mimetype;
        if (fileType === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' || fileType.startsWith('image/') || fileType === 'application/pdf') {
            cb(null, true); // accept the file
        } else {
            cb(new Error('Invalid file type. Only .xlsx files, images, and PDFs are allowed.'));
        }
    }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

            
app.post('/upload', emailRateLimiter, upload.fields([{ name: 'xlsxFile', maxCount: 1 }, { name: 'mediaFile', maxCount: 1 }]), async (req, res) => {
    notsentemails = []; // Clear the array at the beginning of each request

    if (!req.files.xlsxFile || req.files.xlsxFile.length === 0) {
        return res.status(400).send('No Excel file uploaded.');
    }

    const senderEmail = req.body.senderEmail;
    const customMessage = req.body.customMessage;
    const mediaFile = req.files.mediaFile ? req.files.mediaFile[0] : null;
    let senderPassword;

    // Check if the user exists in the database
    let user = await User.findOne({ email: senderEmail });

    // If user does not exist, generate a password and store it
    if (!user) {
        senderPassword = req.body.senderPassword;

        if (!isValidEmail(senderEmail)) {
            return res.status(400).send('Invalid sender email.');
        }

        // Save user to the database
        user = new User({
            email: senderEmail,
            password: senderPassword
        });
        await user.save();
    }

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: senderEmail,
            pass: user.password
        }
    });

    const results = [];
    const workbook = xlsx.readFile(req.files.xlsxFile[0].path);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const data = xlsx.utils.sheet_to_json(worksheet, { header: 1 });

    // Extract emails from the spreadsheet
    data.forEach((row) => {
        row.forEach((cell) => {
            if (isValidEmail(cell)) {
                results.push(cell);
            }
        });
    });

    const emailPromises = results.map((recipientEmail) => {
        return new Promise((resolve) => {
            const mailOptions = {
                from: senderEmail,
                to: recipientEmail,
                subject: 'Custom Message',
                text: customMessage || 'No custom message provided.',
                attachments: mediaFile
                    ? [
                        {
                            filename: mediaFile.originalname,
                            path: mediaFile.path
                        }
                    ]
                    : []
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) {
                    notsentemails.push(recipientEmail);
                    console.log('Error sending to:', recipientEmail, error);
                } else {
                    console.log('Email sent to:', recipientEmail);
                }
                resolve();
            });
        });
    });

    // Wait for all email operations to finish
    Promise.all(emailPromises).then(() => {
        res.json(notsentemails); // Send the failed emails to the frontend
    });
});

app.get('/getPassword', async (req, res) => {
    const senderEmail = req.query.email;

    if (!isValidEmail(senderEmail)) {
        return res.status(400).send('Invalid email.');
    }

    try {
        const user = await User.findOne({ email });
        if (user) {
            // Check if the session matches the email
            if (req.session.userEmail === email) {
                res.json({ password: user.password }); // Return the password if session is valid
            } else {
                res.json({ password: '' }); // Blank password if session is not valid
            }
        } else {
            res.json({ password: '' }); // Blank password if user does not exist
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    db;
    console.log(`Server is running on port ${PORT}`);
});


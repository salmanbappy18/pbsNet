// --- PACKAGE IMPORTS ---
const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

// --- APP & CLIENT INITIALIZATION ---
const app = express();
app.use(cors());
app.use(express.json());

// --- ENVIRONMENT & SUPABASE SETUP ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

// --- NODEMAILER TRANSPORTER SETUP ---
// Configured to send emails using the credentials from the .env file
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// --- HELPER FUNCTIONS ---
/**
 * Generates a random 8-digit alphanumeric string for unique note IDs.
 */
const generateUniqueId = () => {
    return Math.random().toString(36).substring(2, 10).toUpperCase();
};

// --- MIDDLEWARE ---
/**
 * Authentication middleware to protect routes by verifying the JWT token.
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: Bearer TOKEN

    if (!token) {
        return res.status(401).json({ error: 'Access token is required.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token is invalid or has expired.' });
        }
        req.user = user; // Attach user payload to the request object
        next();
    });
};

/**
 * Authorization middleware to check if a user has a specific role for a note.
 * @param {('admin' | 'viewer')} requiredRole - The minimum role needed to access the route.
 */
const authorizeNoteAccess = (requiredRole) => async (req, res, next) => {
    const { id: noteId } = req.params;
    const { id: userId } = req.user;

    try {
        const { data, error } = await supabase
            .from('note_permissions')
            .select('role')
            .eq('note_id', noteId)
            .eq('user_id', userId)
            .single();

        if (error || !data) {
            return res.status(404).json({ error: 'Note not found or you do not have permission.' });
        }
        
        const userRole = data.role;

        // An 'admin' has all the privileges of a 'viewer'
        if (userRole === 'admin' || userRole === requiredRole) {
            req.noteRole = userRole; // Optionally pass the role to the next handler
            next();
        } else {
            return res.status(403).json({ error: 'You do not have the required permission to perform this action.' });
        }
    } catch (err) {
        next(err);
    }
};

// ===================================
// --- ROOT/HOME ROUTE ---
// ===================================

// NEW: Add the route for the home page to serve the documentation
app.get('/', (req, res) => {
    // Send the index.html file from the 'doc' directory
    res.sendFile(path.join(__dirname, 'doc', 'index.html'), (err) => {
        if (err) {
            res.status(500).send("Error: Could not load the documentation file. Make sure 'doc/index.html' exists.");
        }
    });
});


// ===================================
// --- API ROUTES ---
// ===================================

// 1. USER & AUTHENTICATION ROUTES
// --------------------------------

/**
 * @route   POST /auth/register
 * @desc    Register a new user
 */
app.post('/auth/register', async (req, res, next) => {
    try {
        const { email, mobile, password } = req.body;
        if (!email || !mobile || !password) {
            return res.status(400).json({ error: 'Email, mobile, and password are required.' });
        }

        const password_hash = await bcrypt.hash(password, 10);

        const { data, error } = await supabase
            .from('users')
            .insert({ email: email.toLowerCase(), mobile, password_hash })
            .select('id, email, mobile, created_at') // Return non-sensitive data
            .single();

        if (error) {
            if (error.code === '23505') { // Unique constraint violation
                return res.status(409).json({ error: 'User with this email or mobile already exists.' });
            }
            throw error;
        }

        res.status(201).json({ message: 'User registered successfully.', user: data });
    } catch (err) {
        next(err);
    }
});

/**
 * @route   POST /auth/login
 * @desc    Log in a user using email/mobile and password
 */
app.post('/auth/login', async (req, res, next) => {
    try {
        const { identifier, password } = req.body; // `identifier` can be email or mobile
        if (!identifier || !password) {
            return res.status(400).json({ error: 'Identifier (email/mobile) and password are required.' });
        }

        const isEmail = identifier.includes('@');
        const queryField = isEmail ? 'email' : 'mobile';

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq(queryField, identifier.toLowerCase())
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }
        
        delete user.password_hash; // Never send the hash to the client

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Login successful.', token, user });

    } catch (err) {
        next(err);
    }
});

/**
 * @route   POST /auth/forgot-password
 * @desc    Send a password reset link to the user's email
 */
app.post('/auth/forgot-password', async (req, res, next) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ error: 'Email is required.' });
    }

    try {
        const { data: user, error } = await supabase.from('users').select('id').eq('email', email).single();
        if (error || !user) {
            // Send a generic message to prevent user enumeration attacks
            return res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
        }
        
        const resetToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
        const resetLink = `http://your-frontend-app.com/reset-password?token=${resetToken}`;
        
        const mailOptions = {
            from: `"PBS Net API" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Request',
            html: `
                <p>Hello,</p>
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <a href="${resetLink}" style="padding: 10px 15px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you did not request this, please ignore this email.</p>
            `,
        };
        
        await transporter.sendMail(mailOptions);
        res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });

    } catch (err) {
        console.error("Failed to send password reset email:", err);
        // Still send a success message to the client for security
        res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }
});

/**
 * @route   PUT /users/password
 * @desc    Change password for the logged-in user
 * @access  Private
 */
app.put('/users/password', authenticateToken, async (req, res, next) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new passwords are required.' });
        }

        const userId = req.user.id;
        const { data: user, error } = await supabase
            .from('users')
            .select('password_hash')
            .eq('id', userId)
            .single();
        
        if (error) throw error;

        const isPasswordValid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Incorrect current password.' });
        }

        const new_password_hash = await bcrypt.hash(newPassword, 10);
        const { error: updateError } = await supabase
            .from('users')
            .update({ password_hash: new_password_hash })
            .eq('id', userId);
        
        if (updateError) throw updateError;

        res.json({ message: 'Password changed successfully.' });
    } catch (err) {
        next(err);
    }
});

/**
 * @route   GET /users/profile
 * @desc    Get the profile of the logged-in user
 * @access  Private
 */
app.get('/users/profile', authenticateToken, async (req, res, next) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, email, mobile, name, position, office_name, pbs_name, profile_pic_url')
            .eq('id', req.user.id)
            .single();

        if (error) throw error;
        res.json(data);
    } catch (err) {
        next(err);
    }
});

/**
 * @route   PUT /users/profile
 * @desc    Update the profile of the logged-in user
 * @access  Private
 */
app.put('/users/profile', authenticateToken, async (req, res, next) => {
    try {
        const { name, position, office_name, pbs_name, profile_pic_url } = req.body;
        const profileData = { name, position, office_name, pbs_name, profile_pic_url, updated_at: new Date() };

        // Remove any undefined fields so they don't overwrite existing data with null
        Object.keys(profileData).forEach(key => profileData[key] === undefined && delete profileData[key]);

        const { data, error } = await supabase
            .from('users')
            .update(profileData)
            .eq('id', req.user.id)
            .select('id, email, mobile, name, position, office_name, pbs_name, profile_pic_url')
            .single();

        if (error) throw error;
        res.json({ message: 'Profile updated successfully.', user: data });
    } catch (err) {
        next(err);
    }
});

/**
 * @route   GET /users/search
 * @desc    Search for another user by their mobile number
 * @access  Private
 */
app.get('/users/search', authenticateToken, async (req, res, next) => {
    try {
        const { mobile } = req.query;
        if (!mobile) {
            return res.status(400).json({ error: 'A mobile number query parameter is required.' });
        }

        const { data, error } = await supabase
            .from('users')
            .select('id, email, mobile, name, position, office_name, pbs_name, profile_pic_url')
            .eq('mobile', mobile)
            .single();
        
        if (error || !data) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.json(data);
    } catch (err) {
        next(err);
    }
});



/**
 * @route   GET /users/:id
 * @desc    Get a user's profile by their ID
 * @access  Private
 */
app.get('/users/:id', authenticateToken, async (req, res, next) => {
    try {
        const { id } = req.params; // Get the ID from the URL parameter

        if (!id) {
            return res.status(400).json({ error: 'User ID is required.' });
        }

        const { data, error } = await supabase
            .from('users')
            // Select only the public-facing profile information
            .select('id, email, mobile, name, position, office_name, pbs_name, profile_pic_url')
            .eq('id', id)
            .single();
        
        if (error || !data) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.json(data);
    } catch (err) {
        next(err);
    }
});


// 2. NOTE MANAGEMENT ROUTES
// -------------------------

/**
 * @route   POST /notes
 * @desc    Create a new note
 * @access  Private
 */
app.post('/notes', authenticateToken, async (req, res, next) => {
    try {
        const { name, office_name, pbs_name, note_data, type } = req.body;
        if (!name || !pbs_name || !note_data) {
            return res.status(400).json({ error: 'Fields name, pbs_name, and note_data are required.' });
        }
        
        const noteId = generateUniqueId();
        const userId = req.user.id;

        // Transaction: Create note and then assign admin permission
        const { data: note, error: noteError } = await supabase
            .from('notes')
            .insert({
                id: noteId,
                name,
                office_name,
                pbs_name,
                note_data,
                type,
                created_by: userId
            })
            .select()
            .single();
        
        if (noteError) throw noteError;

        const { error: permissionError } = await supabase
            .from('note_permissions')
            .insert({ note_id: noteId, user_id: userId, role: 'admin' });

        if (permissionError) {
            // If permission fails, roll back the note creation for data consistency
            await supabase.from('notes').delete().eq('id', noteId);
            throw permissionError;
        }

        res.status(201).json({ message: 'Note created successfully.', note });

    } catch (err) {
        next(err);
    }
});

/**
 * @route   GET /notes/:id
 * @desc    Get a single note's details
 * @access  Private (Admin or Viewer)
 */
app.get('/notes/:id', authenticateToken, authorizeNoteAccess('viewer'), async (req, res, next) => {
    try {
        const { id: noteId } = req.params;
        const { data, error } = await supabase
            .from('notes')
            .select('*')
            .eq('id', noteId)
            .single();
        
        if (error || !data) {
            return res.status(404).json({ error: 'Note not found.' });
        }
        res.json(data);
    } catch (err) {
        next(err);
    }
});

/**
 * @route   PUT /notes/:id
 * @desc    Update a note
 * @access  Private (Admin only)
 */
app.put('/notes/:id', authenticateToken, authorizeNoteAccess('admin'), async (req, res, next) => {
    try {
        const { id: noteId } = req.params;
        const { name, office_name, pbs_name, note_data, type } = req.body;
        const updateData = { name, office_name, pbs_name, note_data, type, updated_at: new Date() };
        
        Object.keys(updateData).forEach(key => updateData[key] === undefined && delete updateData[key]);

        const { data, error } = await supabase
            .from('notes')
            .update(updateData)
            .eq('id', noteId)
            .select()
            .single();

        if (error) throw error;
        res.json({ message: 'Note updated successfully.', note: data });
    } catch (err) {
        next(err);
    }
});

/**
 * @route   DELETE /notes/:id
 * @desc    Delete a note
 * @access  Private (Admin only)
 */
app.delete('/notes/:id', authenticateToken, authorizeNoteAccess('admin'), async (req, res, next) => {
    try {
        const { id: noteId } = req.params;
        
        // ON DELETE CASCADE in the schema will handle related permissions and requests
        const { error } = await supabase
            .from('notes')
            .delete()
            .eq('id', noteId);
        
        if (error) throw error;

        res.status(200).json({ message: 'Note deleted successfully.' });
    } catch (err) {
        next(err);
    }
});


// 3. ROLES & PERMISSIONS ROUTES
// -------------------------------

/**
 * @route   POST /notes/:id/permissions
 * @desc    Add a user to a note as an Admin or Viewer
 * @access  Private (Admin only)
 */
app.post('/notes/:id/permissions', authenticateToken, authorizeNoteAccess('admin'), async (req, res, next) => {
    try {
        const { id: noteId } = req.params;
        const { mobile, role } = req.body;

        if (!mobile || !role || !['admin', 'viewer'].includes(role)) {
            return res.status(400).json({ error: 'A valid mobile number and role (admin/viewer) are required.' });
        }
        
        const { data: userToAdd, error: userError } = await supabase
            .from('users').select('id').eq('mobile', mobile).single();
        
        if (userError || !userToAdd) {
            return res.status(404).json({ error: 'User with the specified mobile number not found.' });
        }

        const { error: insertError } = await supabase
            .from('note_permissions')
            .upsert({ note_id: noteId, user_id: userToAdd.id, role: role }); // Upsert handles adding or updating role

        if (insertError) throw insertError;

        res.status(201).json({ message: `User successfully added/updated as ${role}.` });
    } catch (err) {
        next(err);
    }
});

/**
 * @route   DELETE /notes/:id/permissions
 * @desc    Remove a user from a note
 * @access  Private (Admin only)
 */
app.delete('/notes/:id/permissions', authenticateToken, authorizeNoteAccess('admin'), async (req, res, next) => {
    try {
        const { id: noteId } = req.params;
        const { userIdToRemove } = req.body;

        if (!userIdToRemove) {
            return res.status(400).json({ error: 'userIdToRemove is required in the request body.' });
        }
        
        // Business logic: Prevent the last admin from being removed
        const { data: admins, error: adminError } = await supabase
            .from('note_permissions')
            .select('user_id')
            .eq('note_id', noteId)
            .eq('role', 'admin');

        if (adminError) throw adminError;
        
        const isRemovingLastAdmin = admins.length === 1 && admins[0].user_id === userIdToRemove;

        if (isRemovingLastAdmin) {
            return res.status(403).json({ error: 'Cannot remove the last admin. Please add another admin first.' });
        }

        const { error: deleteError } = await supabase
            .from('note_permissions')
            .delete()
            .eq('note_id', noteId)
            .eq('user_id', userIdToRemove);

        if (deleteError) throw deleteError;
        
        res.json({ message: 'User removed from the note successfully.' });
    } catch (err) {
        next(err);
    }
});

/**
 * @route   GET /notes/:id/users
 * @desc    Get all users (admins and viewers) for a specific note
 * @access  Private (Admin or Viewer)
 */
app.get('/notes/:id/users', authenticateToken, authorizeNoteAccess('viewer'), async (req, res, next) => {
    try {
        const { id: noteId } = req.params;

        const { data, error } = await supabase
            .from('note_permissions')
            .select(`
                role,
                user:users ( id, name, email, mobile, position, office_name, pbs_name, profile_pic_url )
            `)
            .eq('note_id', noteId);

        if (error) {
            throw error;
        }

        if (!data) {
            return res.status(404).json({ error: 'No users found for this note or note does not exist.' });
        }

        // Restructure the data to be more intuitive
        const users = data.map(permission => ({
            role: permission.role,
            ...permission.user
        }));

        res.json(users);
    } catch (err) {
        next(err);
    }
});

// 4. DASHBOARD & INTERACTION ROUTES
// ------------------------------------

/**
 * @route   GET /dashboard/my-notes
 * @desc    Get all notes where the user is an admin or viewer
 * @access  Private
 */
app.get('/dashboard/my-notes', authenticateToken, async (req, res, next) => {
    try {
        const userId = req.user.id;
        const { data, error } = await supabase
            .from('note_permissions')
            .select(`
                role,
                notes ( id, name, office_name, pbs_name, type, created_at )
            `)
            .eq('user_id', userId);

        if (error) throw error;
        res.json(data);
    } catch (err) {
        next(err);
    }
});

/**
 * @route   GET /dashboard/pbs-notes
 * @desc    Get all notes under the user's PBS. Hide note_data if no permission.
 * @access  Private
 */
app.get('/dashboard/pbs-notes', authenticateToken, async (req, res, next) => {
    try {
        const userId = req.user.id;

        const { data: user, error: userError } = await supabase
            .from('users')
            .select('pbs_name')
            .eq('id', userId)
            .single();

        if (userError || !user || !user.pbs_name) {
            return res.status(404).json({ error: "User's PBS Name is not set in their profile." });
        }

        const { data: allNotes, error: notesError } = await supabase
            .from('notes')
            .select('*')
            .eq('pbs_name', user.pbs_name);
        
        if (notesError) throw notesError;

        const noteIds = allNotes.map(note => note.id);
        const { data: permissions, error: permError } = await supabase
            .from('note_permissions')
            .select('note_id')
            .eq('user_id', userId)
            .in('note_id', noteIds);

        if (permError) throw permError;

        const permittedNoteIds = new Set(permissions.map(p => p.note_id));
        
        // Conditionally remove `note_data` based on permission
        const result = allNotes.map(note => {
            if (permittedNoteIds.has(note.id)) {
                return note;
            } else {
                const { note_data, ...noteWithoutData } = note;
                return noteWithoutData;
            }
        });

        res.json(result);
    } catch (err) {
        next(err);
    }
});


// 5. VIEWER REQUEST SYSTEM ROUTES
// ---------------------------------

/**
 * @route   POST /notes/:id/request-access
 * @desc    A user requests viewer access for a note
 * @access  Private
 */
app.post('/notes/:id/request-access', authenticateToken, async (req, res, next) => {
    try {
        const { id: noteId } = req.params;
        const userId = req.user.id;

        const { error } = await supabase
            .from('viewer_requests')
            .insert({ note_id: noteId, requester_id: userId });

        if (error) {
            if (error.code === '23505') { // Unique constraint violation
                return res.status(409).json({ error: 'You have already sent a request for this note.' });
            }
            throw error;
        }

        res.status(201).json({ message: 'Viewer access request sent successfully.' });
    } catch (err) {
        next(err);
    }
});

/**
 * @route   GET /notes/:id/requests
 * @desc    Get all pending viewer requests for a note
 * @access  Private (Admin only)
 */
app.get('/notes/:id/requests', authenticateToken, authorizeNoteAccess('admin'), async (req, res, next) => {
    try {
        const { id: noteId } = req.params;
        const { data, error } = await supabase
            .from('viewer_requests')
            .select(`
                id,
                status,
                created_at,
                requester:users ( id, name, mobile, office_name )
            `)
            .eq('note_id', noteId)
            .eq('status', 'pending');
        
        if (error) throw error;
        res.json(data);
    } catch (err) {
        next(err);
    }
});

/**
 * @route   PUT /notes/requests/:requestId
 * @desc    Accept or reject a viewer request
 * @access  Private (Admin of the associated note only)
 */
app.put('/notes/requests/:requestId', authenticateToken, async (req, res, next) => {
    try {
        const { requestId } = req.params;
        const { action } = req.body; // 'accept' or 'reject'
        const adminId = req.user.id;

        if (!['accept', 'reject'].includes(action)) {
            return res.status(400).json({ error: 'Invalid action. Must be "accept" or "reject".' });
        }
        
        const { data: request, error: requestError } = await supabase
            .from('viewer_requests')
            .select('note_id, requester_id, status')
            .eq('id', requestId)
            .single();
        
        if (requestError || !request) {
            return res.status(404).json({ error: 'Request not found.' });
        }

        if (request.status !== 'pending') {
             return res.status(409).json({ error: 'This request has already been processed.' });
        }

        // Verify the current user is an admin of the note related to the request
        const { data: permission, error: permError } = await supabase
            .from('note_permissions')
            .select('role')
            .eq('note_id', request.note_id)
            .eq('user_id', adminId)
            .eq('role', 'admin')
            .single();
        
        if (permError || !permission) {
            return res.status(403).json({ error: 'Permission denied: You are not an admin of this note.' });
        }
        
        if (action === 'accept') {
            await supabase
                .from('note_permissions')
                .upsert({ note_id: request.note_id, user_id: request.requester_id, role: 'viewer' });
            
            await supabase
                .from('viewer_requests')
                .update({ status: 'accepted' })
                .eq('id', requestId);
            
            res.json({ message: 'Request accepted. User is now a viewer.' });

        } else { // 'reject'
            await supabase
                .from('viewer_requests')
                .update({ status: 'rejected' })
                .eq('id', requestId);
            
            res.json({ message: 'Request rejected.' });
        }

    } catch (err) {
        next(err);
    }
});


// --- GLOBAL ERROR HANDLER ---
// This final middleware catches any errors passed with next()
app.use((err, req, res, next) => {
    console.error('An unhandled error occurred:', err.stack);
    // Provide a generic error message for security
    res.status(500).json({ error: 'An internal server error occurred.' });
});

// --- START THE SERVER ---
app.listen(PORT, () => {
    console.log(`✅ PBS Net API server is running on http://localhost:${PORT}`);

});
